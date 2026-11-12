"""The client of one node (docs/04 §7, docs/06 §7, docs/10): join, log in, cards, send, receive, acknowledge, tasks,
agents, connected networks. Zero Trust from the client side: the node's card and its signed ``info`` are checked, every
received envelope is verified with the sender's (self-certifying) card and opened here, duplicates are dropped,
answers are size-limited and parsed strictly."""

import collections
import os
import time
import urllib.error
import urllib.request

from .agent import Agent
from .content import Content
from .encoding import b64, b64_fixed, b64_var
from .envelope import Envelope
from .errors import BridgeError, NodeError, Untrusted
from .jsonc import canonical, parse_strict
from .keys import Identity, KeyCard, check_id
from .link import JoinLink
from .pow import Puzzle
from .request import SignedRequest
from .statement import Statement

MAX_ANSWER_BYTES = 4 * 1024 * 1024
REQUEST_TIMEOUT = 40
SEEN_MEMORY = 100_000
HOME_LIFETIME_MS = 30 * 24 * 3600 * 1000 - 60_000
JOIN_CHECK_MAX_ENTRIES = 4096
MAX_PENDING_ACKS = 1000


def now_ms() -> int:
    return int(time.time() * 1000)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a node must not send us elsewhere
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class Received:
    """One verified, opened message: ``id``, ``sender``, ``net`` (the sender's network), ``content``, ``agent_of``
    (``(owner id, note)`` if the sender is an agent whose statement checked out, else ``None``)."""

    def __init__(self, envelope_id, sender, net, content, agent_of=None):
        self.id, self.sender, self.net, self.content, self.agent_of = envelope_id, sender, net, content, agent_of

    def __repr__(self):
        return f"Received(from={self.sender}, {self.content!r})"


class Inbox:
    def __init__(self):
        self.messages = []
        self.rejected = 0
        self.duplicates = 0
        self.warning = None


class Client:
    """A client of one node. ``Client.join(identity, link)`` joins a network once; later ``Client(identity, url,
    node_id).connect()``."""

    def __init__(self, identity: Identity, node_url: str, expected_node: str = None):
        self.identity = identity
        self.url = node_url.rstrip("/")
        if not (self.url.startswith("http://") or self.url.startswith("https://")):
            raise BridgeError("BAD_FORMAT", "node URL must start with http:// or https://")
        self.expected_node = expected_node
        self.card = identity.key_card("client", None, now_ms())
        self.node = None
        self.net = None
        self.session = None
        self.agent = None
        self.max_pow_tries = 1 << 30
        self.ttl_s = 7 * 24 * 3600
        self._seen = collections.OrderedDict()
        self._seen_file = None
        self._pending_acks = []
        self._stash = collections.deque()

    # --- HTTP -------------------------------------------------------------------------------------------------

    def _call(self, method: str, path: str, body: bytes = None, session: bool = False) -> dict:
        request = urllib.request.Request(self.url + path, data=body, method=method)
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", "bridge4-python/0.1")
        if session and self.session:
            request.add_header("Authorization", "Bearer " + self.session)
        try:
            with _OPENER.open(request, timeout=REQUEST_TIMEOUT) as response:
                status, data = response.status, response.read(MAX_ANSWER_BYTES + 1)
        except urllib.error.HTTPError as error:
            status, data = error.code, error.read(MAX_ANSWER_BYTES + 1)
        except (urllib.error.URLError, OSError) as error:
            raise BridgeError("UNAVAILABLE", f"node not reachable: {error}") from None
        if len(data) > MAX_ANSWER_BYTES:
            raise Untrusted("answer too large")
        try:
            answer = parse_strict(data, MAX_ANSWER_BYTES)
        except BridgeError as error:
            raise Untrusted(f"bad answer ({status}): {error}") from None
        if not isinstance(answer, dict):
            raise Untrusted("answer is not an object")
        if status != 200:
            retry = answer.get("retry_after")
            raise NodeError(str(answer.get("error", "")), str(answer.get("message", "")),
                            retry if isinstance(retry, int) else None, status)
        return answer

    def _post(self, path: str, value, session: bool = False) -> dict:
        data = value if isinstance(value, bytes) else canonical(value)
        return self._call("POST", path, data, session)

    # --- node, login, join ------------------------------------------------------------------------------------

    def _fetch_info(self) -> KeyCard:
        info = self._call("GET", "/v4/info")
        card = KeyCard.from_value(info.get("card"))
        if self.expected_node is not None and card.id != self.expected_node:
            raise Untrusted("node ID does not match")
        statement = Statement.from_value(info.get("info"))
        statement.verify([card], 1)
        statement.check_time(now_ms())
        if statement.kind != "info":
            raise Untrusted("info statement expected")
        self.node, self.net = card, statement.net
        return card

    def _solve(self, challenge: dict, node: KeyCard, body: dict) -> None:
        puzzle = challenge.get("pow")
        if puzzle is not None:
            puzzle = Puzzle(puzzle)
            puzzle.verify(node)
            solution = puzzle.solve(self.max_pow_tries)
            if solution is None:
                raise Untrusted("proof of work too hard")
            body["pow"] = b64(solution)

    def connect(self) -> "Client":
        """Checks the node, then logs in (solving a proof of work if asked). In a network the login carries a
        ``home`` statement - or, for an agent, its statement."""
        node = self._fetch_info()
        challenge = self._post("/v4/auth/challenge", {})
        body = {"challenge": challenge.get("challenge"), "card": self.card.to_value()}
        self._solve(challenge, node, body)
        if self.agent is not None:
            body["agent"] = self.agent.to_value()
        elif self.net != node.id:
            now = now_ms()
            home = Statement.sign("home", self.net, now, now + HOME_LIFETIME_MS, {"node": node.id}, self.identity)
            body["home"] = home.to_value()
        login = SignedRequest.sign(self.identity, node.id, "login", body, now_ms())
        answer = self._post("/v4/auth/login", login.to_bytes())
        token = answer.get("session")
        if not isinstance(token, str) or len(token) != 43:
            raise Untrusted("bad session token")
        self.session = token
        return self

    @classmethod
    def join(cls, identity: Identity, link: str) -> "Client":
        """Joins a network with a join link: checks the gateway belongs to the network (info, genesis, log), solves the
        proof of work, presents the invite code, checks the membership and logs in."""
        parsed = JoinLink.parse(link)
        client = cls(identity, parsed.gateway, parsed.node)
        node = client._fetch_info()
        if client.net != parsed.net:
            raise Untrusted("the gateway belongs to another network")
        client._check_gateway_in_log(parsed.net, node.id)
        challenge = client._post("/v4/auth/challenge", {"for": "join"})
        body = {"challenge": challenge.get("challenge"), "card": client.card.to_value()}
        if parsed.code is not None:
            body["code"] = parsed.code
        client._solve(challenge, node, body)
        request = SignedRequest.sign(identity, node.id, "join", body, now_ms())
        answer = client._post("/v4/net/join", request.to_bytes())
        member = answer.get("member")
        if member is not None:
            statement = Statement.from_value(member)
            statement.verify([node], 1)
            if (statement.kind != "member" or statement.net != parsed.net
                    or statement.body.get("member") != identity.id):
                raise Untrusted("the gateway answered with another membership")
        client.expected_node = node.id
        return client.connect()

    def _check_gateway_in_log(self, net: str, node: str) -> None:
        entries = []
        position = 0
        while position < JOIN_CHECK_MAX_ENTRIES:
            page = self._post(f"/v4/net/{net}/log", {"from": position, "max": 256})
            listed = page.get("entries") or []
            if not isinstance(listed, list) or not listed or len(listed) > 256:
                break
            for item in listed:
                position += 1
                try:
                    entries.append(Statement.parse(b64_var(item, "entry", 64 * 1024)))
                except BridgeError:
                    if position == 1:
                        raise Untrusted("network log: entry 0 is not a statement") from None
            size = page.get("size")
            if isinstance(size, int) and position >= size:
                break
        gateway_in_log(net, node, entries)

    # --- agents -------------------------------------------------------------------------------------------------

    def with_agent(self, statement) -> "Client":
        """Logs in as an agent from now on (docs/10 §3); uses the agent card of the statement as its own card."""
        statement = statement if isinstance(statement, Statement) else Statement.from_value(statement)
        agent = Agent.from_body(statement.body)
        if (agent.card.id != self.identity.id or agent.card.sign != self.identity.sign_public
                or agent.card.box != self.identity.box_public):
            raise Untrusted("the agent statement is for another key")
        self.card = agent.card
        self.agent = statement
        return self

    def issue_agent(self, agent_card: KeyCard, send=True, receive=True, to=None, rate=60, note=None, days=7):
        """Issues an agent card as this client (the owner, a member), homed at this client's node."""
        if self.net is None or self.node is None:
            raise Untrusted("not connected")
        scopes = [scope for scope, wanted in (("receive", receive), ("send", send)) if wanted]
        body = Agent(agent_card.id, agent_card, self.card, self.node.id, scopes, to, rate, note)
        return body.issue(self.net, self.identity, now_ms(), days)

    def revoke_agent(self, agent_id: str) -> bool:
        request = SignedRequest.sign(self.identity, self._node_id(), "agent-revoke", {"agent": agent_id}, now_ms())
        return bool(self._post("/v4/agent/revoke", request.to_bytes(), session=True).get("ended"))

    # --- cards, send ----------------------------------------------------------------------------------------------

    def _node_id(self) -> str:
        if self.node is None:
            raise Untrusted("not connected")
        return self.node.id

    def card_of(self, identity_id: str, net: str = None) -> KeyCard:
        """The card of ``identity_id`` - in the connected network ``net``, if given (docs/10 §6)."""
        body = {"id": check_id(identity_id)}
        if net is not None and net != self.net:
            body["net"] = check_id(net)
        card = KeyCard.from_value(self._post("/v4/card", body, session=True).get("card"))
        if card.id != identity_id:
            raise Untrusted("node returned a card for another ID")
        return card

    def send(self, to: KeyCard, content, net: str = None) -> bytes:
        """Encrypts ``content`` (a :class:`Content`, text or bytes) for ``to`` and hands it to the node; ``net``: the
        recipient's network if it is a connected one. Returns the envelope ID."""
        if self.net is None:
            raise Untrusted("not connected")
        if isinstance(content, str):
            content = Content.of_text(content)
        elif isinstance(content, (bytes, bytearray)):
            content = Content.of_data(bytes(content))
        dnet = net if net is not None and net != self.net else None
        envelope = Envelope.seal(self.identity, self.net, to, content.to_bytes(), now_ms(), self.ttl_s, "msg", dnet)
        self._post("/v4/send", envelope.to_bytes(), session=True)
        return envelope.id

    def request(self, to: KeyCard, value, wait: float = 30, net: str = None):
        """Sends a task (``application/json``) and waits up to ``wait`` seconds for its response (from ``to``, naming
        the task). Other messages are kept for the next :meth:`receive`. ``None``: no answer in time."""
        task = self.send(to, Content.of_json(value, "task"), net)
        deadline = time.time() + wait
        while time.time() < deadline:
            stash, self._stash = self._stash, collections.deque()
            inbox = self.receive(max(1, min(25, int(deadline - time.time()))))
            self._stash = stash + self._stash
            found = None
            for message in inbox.messages:
                if (found is None and message.sender == to.id and message.content.kind == "response"
                        and message.content.reply == task):
                    found = message
                elif len(self._stash) < 1000:
                    self._stash.append(message)
            if found is not None:
                return found
        return None

    # --- receive ------------------------------------------------------------------------------------------------

    def with_seen_file(self, path: str) -> "Client":
        """Keeps the replay protection across restarts in ``path`` (one line per envelope until it expires)."""
        now = now_ms()
        if os.path.exists(path):
            with open(path, "r", encoding="ascii", errors="replace") as file:
                for line in file.read().splitlines()[-SEEN_MEMORY:]:
                    parts = line.split(" ")
                    if len(parts) == 3 and parts[2].isdigit() and int(parts[2]) > now:
                        self._seen[(parts[0], parts[1])] = int(parts[2])
        with open(path, "w", encoding="ascii") as file:
            file.writelines(f"{a} {b} {c}\n" for (a, b), c in self._seen.items())
        self._seen_file = path
        return self

    def receive(self, wait: int = 0) -> Inbox:
        """Fetches waiting envelopes (up to ``wait`` seconds), verifies and opens them, drops duplicates and
        acknowledges everything fetched (repeated with the next call if that fails)."""
        if self._stash:
            inbox = Inbox()
            inbox.messages = list(self._stash)
            self._stash.clear()
            return inbox
        answer = self._post("/v4/poll", {"wait": max(0, min(25, int(wait))), "max": 100}, session=True)
        envelopes = answer.get("envelopes") or []
        cards = answer.get("cards") or {}
        agents = answer.get("agents") or {}
        connected = self._connected_nets(answer)
        inbox = Inbox()
        to_ack, self._pending_acks = self._pending_acks, []
        for value in envelopes[:100]:
            try:
                envelope = Envelope.from_value(value)
            except BridgeError:
                inbox.rejected += 1
                continue
            key = (envelope.sender, b64(envelope.id))
            if key not in to_ack:
                to_ack.append(key)
            if key in self._seen:
                inbox.duplicates += 1
                continue
            message = self._open(envelope, cards, agents, connected)
            if message is None:
                inbox.rejected += 1
                continue
            self._remember(key, envelope.expires_at())
            inbox.messages.append(message)
        if to_ack:
            try:
                self.ack(to_ack)
            except BridgeError as error:
                self._pending_acks = to_ack[:MAX_PENDING_ACKS]
                inbox.warning = f"acknowledging failed, will retry: {error}"
        return inbox

    def _connected_nets(self, answer: dict):
        feds, master = answer.get("feds"), answer.get("master")
        if not isinstance(feds, dict) or master is None or self.net is None:
            return []
        try:
            master = KeyCard.from_value(master)
        except BridgeError:
            return []
        if master.id != self.net or master.role != "net":
            return []
        out = []
        for peer, value in list(feds.items())[:32]:
            if check_federation(value, self.net, master, peer, now_ms()):
                out.append(peer)
        return out

    def _open(self, envelope: Envelope, cards: dict, agents: dict, connected):
        own = self.net
        from_here = envelope.net == own and envelope.dnet is None
        from_connected = envelope.dnet == own and envelope.net in connected
        if envelope.to != self.identity.id or not (from_here or from_connected):
            return None
        try:
            card = KeyCard.from_value(cards.get(envelope.sender))
            if card.id != envelope.sender:
                return None
            envelope.check_time(now_ms())
            content = Content.parse(envelope.open(self.identity, card))
        except BridgeError:
            return None
        agent_of = None
        if envelope.sender in agents:
            agent_of = agent_of_statement(agents[envelope.sender], card, envelope.net)
        return Received(envelope.id, envelope.sender, envelope.net, content, agent_of)

    def _remember(self, key, expires: int) -> None:
        self._seen[key] = expires
        while len(self._seen) > SEEN_MEMORY:
            self._seen.popitem(last=False)
        if self._seen_file:
            with open(self._seen_file, "a", encoding="ascii") as file:
                file.write(f"{key[0]} {key[1]} {expires}\n")

    def ack(self, envelopes) -> int:
        """Acknowledges ``[(sender, envelope id as Base64url)]`` - the node deletes them."""
        removed = 0
        for start in range(0, len(envelopes), 100):
            chunk = [{"from": sender, "id": envelope_id} for sender, envelope_id in envelopes[start:start + 100]]
            request = SignedRequest.sign(self.identity, self._node_id(), "ack", {"acks": chunk}, now_ms())
            removed += int(self._post("/v4/ack", request.to_bytes(), session=True).get("removed", 0))
        return removed


def agent_of_statement(value, sender: KeyCard, net: str):
    """``(owner, note)`` of an agent statement for exactly this sender and card - or ``None`` (docs/10 §3.4)."""
    try:
        statement = Statement.from_value(value)
        agent = Agent.check(statement, net, now_ms())
    except BridgeError:
        return None
    if agent.agent != sender.id or agent.card != sender:
        return None
    return (agent.owner.id, agent.note)


def check_federation(value, net: str, master: KeyCard, peer: str, now: int) -> bool:
    """Whether ``value`` is a ``federation`` statement of ``net`` with ``peer``, signed by the net key alone, in effect,
    for messages (docs/10 §6.3)."""
    try:
        statement = Statement.from_value(value)
        scope = statement.body.get("scope")
        ok = (statement.kind == "federation" and statement.net == net and statement.claimed_signers() == [net]
              and statement.body.get("peer") == peer and scope == ["messages"] and master.id == net
              and master.role == "net")
        if not ok:
            return False
        statement.check_time(now)
        statement.verify([master], 1)
        return True
    except BridgeError:
        return False


def gateway_in_log(net: str, node: str, entries) -> None:
    """What a client checks before joining at gateway ``node`` (docs/06 §7): entry 0 is the genesis manifest of
    ``net`` signed by the network key; ``node`` is a start gateway or has a ``gateway`` seal (level ≥ 2) of this
    network signed by the network key or only by admins with the right ``seals``."""
    if not entries:
        raise Untrusted("network log: empty")
    genesis = entries[0]
    master = KeyCard.from_value(genesis.body.get("card"))
    if (genesis.kind != "manifest" or genesis.net != net or master.id != net or master.role != "net"
            or genesis.body.get("version") != 1 or genesis.claimed_signers() != [net]):
        raise Untrusted("network log: entry 0 is not the genesis manifest of this network")
    genesis.verify([master], 1)
    gateways = genesis.body.get("gateways") or []
    if any(isinstance(entry, dict) and entry.get("id") == node for entry in gateways):
        return
    cards = [master]
    for statement in entries:
        if statement.kind != "delegation" or statement.net != net or statement.claimed_signers() != [net]:
            continue
        rights = statement.body.get("rights") or []
        if "seals" not in rights:
            continue
        try:
            statement.verify([master], 1)
            card = KeyCard.from_value(statement.body.get("card"))
        except BridgeError:
            continue
        if card.role == "admin" and statement.body.get("admin") == card.id and len(cards) < 10_000:
            cards.append(card)
    for seal in entries:
        body = seal.body
        level = body.get("level")
        services = body.get("services") or []
        if (seal.kind == "seal" and seal.net == net and body.get("subject") == node and isinstance(level, int)
                and level >= 2 and "gateway" in services):
            try:
                seal.verify(cards, len(seal.signers))
                return
            except BridgeError:
                continue
    raise Untrusted("network log: the gateway is not a gateway of this network")
