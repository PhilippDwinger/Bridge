"""Agent cards (docs/10 §3, ADR 0022): a member (owner) gives a program its own key with few rights."""

from .errors import BridgeError, bad_format, bad_signature
from .keys import KeyCard, check_id
from .statement import Statement

MAX_LIFETIME_MS = 30 * 24 * 3600 * 1000
MAX_TO = 32
DEFAULT_RATE = 60
SCOPES = ("receive", "send")
_FIELDS = ("agent", "card", "owner", "node", "scopes", "to", "rate", "note")


class Agent:
    """The checked body of an ``agent`` statement."""

    def __init__(self, agent, card, owner, node, scopes, to=None, rate=DEFAULT_RATE, note=None):
        self.agent, self.card, self.owner, self.node = agent, card, owner, node
        self.scopes, self.to, self.rate, self.note = sorted(set(scopes)), to, rate, note

    @classmethod
    def from_body(cls, body) -> "Agent":
        if not isinstance(body, dict):
            raise bad_format("agent: not an object")
        unknown = [key for key in body if key not in _FIELDS]
        if unknown:
            raise bad_format(f"agent: unknown field {unknown[0]!r}")
        agent = check_id(body.get("agent"))
        card = KeyCard.from_value(body.get("card"))
        owner = KeyCard.from_value(body.get("owner"))
        if card.id != agent or card.role != "client":
            raise bad_format("agent: card must be the agent's client card")
        if owner.role not in ("client", "admin") or owner.id == agent:
            raise bad_format("agent: owner card must be another client or admin card")
        node = check_id(body.get("node"))
        scopes = body.get("scopes")
        if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 2 or len(set(map(str, scopes))) != len(scopes)
                or any(scope not in SCOPES for scope in scopes)):
            raise bad_format("agent scopes: only send and receive, no duplicates")
        to = body.get("to")
        if to is not None:
            if not isinstance(to, list) or not 1 <= len(to) <= MAX_TO or len(set(map(str, to))) != len(to):
                raise bad_format("agent to: 1..=32 distinct ids")
            to = [check_id(item) for item in to]
        rate = body.get("rate", DEFAULT_RATE)
        if not isinstance(rate, int) or isinstance(rate, bool) or not 1 <= rate <= 3600:
            raise bad_format("agent rate: integer 1..=3600")
        note = body.get("note")
        if note is not None and (not isinstance(note, str) or not 1 <= len(note) <= 64
                                 or any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in note)):
            raise bad_format("agent note: 1..=64 characters, no control characters")
        return cls(agent, card, owner, node, scopes, to, rate, note)

    def to_body(self) -> dict:
        body = {"agent": self.agent, "card": self.card.to_value(), "owner": self.owner.to_value(), "node": self.node,
                "scopes": sorted(self.scopes)}
        if self.to is not None:
            body["to"] = list(self.to)
        if self.rate != DEFAULT_RATE:
            body["rate"] = self.rate
        if self.note is not None:
            body["note"] = self.note
        Agent.from_body(body)
        return body

    def may_write_to(self, recipient: str) -> bool:
        return "send" in self.scopes and (self.to is None or recipient in self.to)

    @classmethod
    def check(cls, statement: Statement, net: str, now_ms: int) -> "Agent":
        """Checks an agent statement fully: kind, network, owner alone signed it, ≤ 30 days, time, signature."""
        if statement.kind != "agent":
            raise bad_format("expected an agent statement")
        agent = cls.from_body(statement.body)
        if statement.net != net:
            raise bad_format("agent: other network")
        if statement.claimed_signers() != [agent.owner.id]:
            raise bad_signature()
        if statement.exp - statement.iat > MAX_LIFETIME_MS:
            raise bad_format("agent: lifetime over 30 days")
        statement.check_time(now_ms)
        statement.verify([agent.owner], 1)
        return agent

    def issue(self, net: str, owner, now_ms: int, days: int = 7) -> Statement:
        if not 1 <= days <= 30:
            raise BridgeError("BAD_FORMAT", "agent: 1..=30 days")
        if owner.id != self.owner.id:
            raise bad_format("agent: the owner signs")
        return Statement.sign("agent", net, now_ms, now_ms + days * 24 * 3600 * 1000, self.to_body(), owner)
