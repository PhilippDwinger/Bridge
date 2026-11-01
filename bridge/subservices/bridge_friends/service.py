"""BridgeFriends - friendships between clients, also across servers that do not trust each other.

At home:   /friends/invite {name: "paddy-home", password: "sonnenblume"}  -> paddy-home@<server>
At school: /friends/add {address: "paddy-home@<server>", password: "sonnenblume"}  -> friends

How the password is checked: see doors.py. How servers that do not trust each other talk: see link.py.
Friends talk with messages of the type "friend" (/friends/send): verified - both servers check the friendship and
that the sender really belongs to the server that delivered the message.
The status of a friend (online / presence / speed) is pulled from the friend's server when the client asks for it.
"""
import asyncio
import datetime
import hashlib
import math
import re
import secrets
import time

from bridge import errors
from bridge.banker import client_key_store, friend_store, mailbox_store
from bridge.core import address, clients, protocol
from bridge.core.jsoncheck import json_problem
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.messenger.mailbox import PoolName
from bridge.messenger.message import ContentType, MessageMode, create_message
from bridge.security.generator import generate_key
from bridge.server import url_env
from bridge.subservices.bridge_friends import doors, link

PRESENCE_MODES = ("available", "busy", "away", "invisible")
MAX_STATUS_TEXT = 100
MAX_NICKNAME = 64
# Without a request for longer than protocol.host_inactive_seconds a client is "idle", after this "offline"
IDLE_SECONDS = 15 * 60
NOTIFY_HOURS = 24
SERVER_SENDER_ID = "server"

_requests = {}
# (server_url, asking_ip) -> (monotonic, {friend_ip: status}, line_seconds)
_status_cache = {}


def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def _fail(error, problem):
    errors.handle_error(error, problem)
    errors.set_client_details(problems=[problem])
    return error

def _iso(value):
    return value.isoformat() if isinstance(value, datetime.datetime) else value

def _client_name(client_ip):
    client_key = clients.get_client_key_from_ip(client_ip)
    entry = client_key_store.get_client_entry(client_key) if client_key else None
    return entry.get("name") if entry else None

CLIENT_ID = re.compile(r"^[0-9a-f]{8,64}$")
FRIENDSHIP_ID = re.compile(r"^[0-9a-f]{8,128}$")
ONLINE_STATES = ("active", "idle", "offline", "unknown")
FRIENDSHIP_STATES = ("active", "pending_in", "pending_out", "unknown")


def valid_client_ip(value, server_url=None):
    """A client IP from another server: right format (hex id) and - if given - of that server."""
    server, local_id = address.split_address(value) if isinstance(value, str) else (None, None)
    return server is not None and CLIENT_ID.match(local_id) is not None and (server_url is None or server == server_url)

def clean_text(value, max_length):
    """A text from another server or a client, or None if it is no clean text."""
    if not isinstance(value, str) or len(value) > max_length or json_problem(value):
        return None
    return value

def _clean_number(value, low=0.0, high=1e9):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return min(max(value, low), high)

def clean_status(raw):
    """The status answer of the friend's server - rebuilt with checked types (it goes to our client)."""
    if not isinstance(raw, dict):
        return {"friendship": "unknown"}
    friendship = raw.get("friendship") if raw.get("friendship") in FRIENDSHIP_STATES else "unknown"
    status = {"friendship": friendship}
    if friendship != "active":
        return status
    status["online"] = raw.get("online") if raw.get("online") in ONLINE_STATES else "unknown"
    status["presence"] = raw.get("presence") if raw.get("presence") in PRESENCE_MODES else None
    status["status_text"] = clean_text(raw.get("status_text"), MAX_STATUS_TEXT)
    status["last_seen_s"] = _clean_number(raw.get("last_seen_s"))
    waiting = raw.get("waiting_from_you")
    status["waiting_from_you"] = waiting if isinstance(waiting, int) and not isinstance(waiting, bool) and 0 <= waiting <= 10 ** 6 else None
    pickup = raw.get("pickup")
    if isinstance(pickup, dict) and _clean_number(pickup.get("typical_s")) is not None:
        status["pickup"] = {"typical_s": _clean_number(pickup["typical_s"]),
                            "worst_s": _clean_number(pickup.get("worst_s")) or _clean_number(pickup["typical_s"]),
                            "based_on": pickup.get("based_on") if pickup.get("based_on") in ("own", "general", "baseline") else None}
    return status


def _label(value, field="label"):
    if value is None:
        return None
    if clean_text(value, doors.MAX_LABEL) is None:
        return _fail(Exceptions.ARGUMENT_ERROR, f"'{field}' must be a text with up to {doors.MAX_LABEL} characters")
    return value


# region notifications
def notify(client_ip, instruction, **fields):
    """An instruction from the server to one of our clients (friend_added, friend_request, friend_declined,
    friend_removed). Instructions only ever come from the server itself."""
    if not address.is_local(client_ip) or clients.get_client_key_from_ip(client_ip) is None:
        return
    from bridge.messenger import router
    message = create_message(address.make_address(url_env.base_root, SERVER_SENDER_ID), client_ip,
                             {"instruction": instruction, **fields}, ContentType.INSTRUCTION, MessageMode.FAST,
                             expires_at=_now() + datetime.timedelta(hours=NOTIFY_HOURS))
    if is_exception(message):
        return
    # Not part of a conversation
    message.conversation_id = None
    router.deliver_local(message)

def _friend_fields(entry):
    server_url = address.server_of(entry["friend_ip"])
    return {"friend_ip": entry["friend_ip"], "label": entry["friend_label"], "server": server_url,
            "via": link.kind_of(server_url), "friendship_id": entry["friendship_id"]}
# endregion notifications


# region summary and status
def safety_code(entry):
    """12 digits both friends see the same - they can compare them (like the safety number of a messenger)."""
    first, second = sorted([entry["local_ip"], entry["friend_ip"]])
    digest = hashlib.sha256(f"bridge-friends-safety|{entry['friendship_id']}|{first}|{second}|{entry['secret']}"
                            .encode("utf-8")).digest()
    text = f"{int.from_bytes(digest[:8], 'big') % 10 ** 12:012d}"
    return f"{text[:4]} {text[4:8]} {text[8:]}"

def summary(entry, status=None):
    server_url = address.server_of(entry["friend_ip"])
    result = {
        "friend_ip": entry["friend_ip"],
        "label": entry["friend_label"],
        "nickname": entry.get("nickname"),
        "state": entry["state"],
        "server": server_url,
        "via": link.kind_of(server_url),
        "since": _iso(entry["created_at"]),
        "accepted_at": _iso(entry.get("accepted_at")),
        "safety_code": safety_code(entry),
    }
    if status is not None:
        result["status"] = status
    return result

def local_status(local_ip, asking_ip, friendship_id):
    """What the friend asking_ip may see about our client local_ip."""
    entry = friend_store.get(local_ip, asking_ip)
    client_key = clients.get_client_key_from_ip(local_ip)
    if entry is None or entry["friendship_id"] != friendship_id or client_key is None:
        return {"friendship": "unknown"}
    if entry["state"] != "active":
        return {"friendship": entry["state"]}
    own = friend_store.presence.get(local_ip) or {}
    presence = own.get("presence", "available")
    if presence == "invisible":
        # Invisible = looks offline for friends, and nothing tells when it is there
        return {"friendship": "active", "online": "offline", "presence": None, "status_text": None}
    client_entry = client_key_store.get_client_entry(client_key)
    mailbox = mailbox_store.get_mailbox(client_key)
    last_seen = (_now() - client_entry["last_signal"]).total_seconds()
    online = "active" if last_seen <= protocol.host_inactive_seconds else "idle" if last_seen <= IDLE_SECONDS else "offline"
    waiting = mailbox.waiting_count(PoolName.FRIEND) if mailbox else 0
    from bridge.subservices.bridge_agent import agent
    return {
        "friendship": "active",
        "online": online,
        "presence": presence,
        "status_text": own.get("text") or None,
        "last_seen_s": round(last_seen, 1),
        "waiting_from_you": sum(1 for message in mailbox.friend_pool if message.sender_ip == asking_ip) if mailbox else 0,
        "waiting": waiting,
        "pickup": agent.pickup_estimate(local_ip, waiting) if agent.enabled() else None,
    }

def _speed(status, line_s):
    """fast | normal | slow (+ reasons): the line between the servers, how fast the friend takes messages (BridgeAgent,
    only from real measurements) and how many of my messages are still waiting there."""
    level, reasons = 0, []
    if line_s is not None:
        milliseconds = round(line_s * 1000)
        if line_s > 0.5:
            level = 2
            reasons.append(f"slow line between the servers ({milliseconds} ms)")
        elif line_s > 0.15:
            level = max(level, 1)
            reasons.append(f"line between the servers {milliseconds} ms")
    pickup = status.get("pickup")
    if isinstance(pickup, dict) and pickup.get("based_on") == "own" and isinstance(pickup.get("typical_s"), (int, float)):
        typical = pickup["typical_s"]
        if typical > 60:
            level = 2
            reasons.append(f"takes messages slowly (typically after {typical:.0f} s)")
        elif typical > 10:
            level = max(level, 1)
            reasons.append(f"takes messages after {typical:.0f} s")
    waiting = status.get("waiting_from_you")
    if isinstance(waiting, int):
        if waiting > 20:
            level = 2
            reasons.append(f"{waiting} of your messages are waiting")
        elif waiting > 5:
            level = max(level, 1)
            reasons.append(f"{waiting} of your messages are waiting")
    if status.get("online") == "offline" and not reasons:
        return "unknown", reasons
    return ("fast", "normal", "slow")[level], reasons

def _public_status(status, line_s):
    if status.get("friendship") == "unreachable":
        return {"online": "unreachable", "presence": None, "status_text": None, "speed": "unknown",
                "reasons": ["the friend's server cannot be reached"], "line_ms": None}
    speed, reasons = _speed(status, line_s)
    pickup = status.get("pickup") if isinstance(status.get("pickup"), dict) else None
    return {
        "online": status.get("online", "unknown"),
        "presence": status.get("presence"),
        "status_text": status.get("status_text"),
        "last_seen_s": status.get("last_seen_s"),
        "waiting_from_you": status.get("waiting_from_you"),
        "speed": speed,
        "reasons": reasons,
        "line_ms": round(line_s * 1000) if line_s is not None else None,
        "pickup_typical_s": pickup.get("typical_s") if pickup else None,
    }

async def _statuses_from(server_url, asking_ip, entries, fresh=False):
    """{friend_ip: raw status} of these friends on one server, and how long the line needed (None = local)."""
    cache_key = (server_url, asking_ip)
    cached = _status_cache.get(cache_key)
    wanted = {entry["friend_ip"] for entry in entries}
    if (not fresh and cached is not None and time.monotonic() - cached[0] < protocol.friend_status_cache_seconds
            and wanted <= set(cached[1])):
        return cached[1], cached[2]
    if server_url == url_env.base_root:
        result = {entry["friend_ip"]: local_status(entry["friend_ip"], asking_ip, entry["friendship_id"]) for entry in entries}
        line_s = None
    else:
        started = time.monotonic()
        answer = await link.post(server_url, "/s2s/friends/status", {
            "asking_ip": asking_ip,
            "friends": [{"friend_ip": entry["friend_ip"], "friendship_id": entry["friendship_id"]} for entry in entries],
        })
        line_s = time.monotonic() - started
        if is_exception(answer) or not isinstance(answer, dict):
            # Not reachable now (or starting): no "unknown" here - that would end the friendship
            errors.pop_client_details()
            return {ip: {"friendship": "unreachable"} for ip in wanted}, None
        result = {ip: clean_status(answer.get(ip)) for ip in wanted}
    if len(_status_cache) > 10000:
        _status_cache.clear()
    _status_cache[cache_key] = (time.monotonic(), result, line_s)
    return result, line_s

def _reconcile(entry, status):
    """The friend's server knows the true state of its side: follow it."""
    if friend_store.get(entry["local_ip"], entry["friend_ip"]) is not entry:
        # Changed while we asked (removed and added again) - the answer is about the old friendship
        return friend_store.get(entry["local_ip"], entry["friend_ip"])
    other = status.get("friendship")
    if other == "unknown" and entry["state"] in ("active", "pending_out"):
        # The other side does not know this friendship (anymore) - removed there, or the client is gone
        friend_store.remove(entry["local_ip"], entry["friend_ip"])
        notify(entry["local_ip"], "friend_removed", reason="the other side does not know this friendship anymore",
               **_friend_fields(entry))
        return None
    if other == "active" and entry["state"] == "pending_out":
        entry["state"], entry["accepted_at"] = "active", _now()
        notify(entry["local_ip"], "friend_added", **_friend_fields(entry))
    return entry

async def _with_statuses(local_ip, entries, fresh=False):
    by_server = {}
    for entry in entries:
        server_url = address.server_of(entry["friend_ip"])
        if entry["state"] in ("active", "pending_out") and link.check_allowed(server_url) is None:
            by_server.setdefault(server_url, []).append(entry)
    errors.pop_client_details()
    answers = await asyncio.gather(*(_statuses_from(server_url, local_ip, group, fresh) for server_url, group in by_server.items()))
    raw = {}
    for (server_url, group), (statuses, line_s) in zip(by_server.items(), answers):
        for entry in group:
            raw[entry["friend_ip"]] = (statuses.get(entry["friend_ip"], {"friendship": "unknown"}), line_s)
    results = []
    for entry in entries:
        found = raw.get(entry["friend_ip"])
        if found is not None:
            entry = _reconcile(entry, found[0])
            if entry is None:
                continue
        status = None
        if entry["state"] == "active":
            status = _public_status(found[0], found[1]) if found else {"online": "unknown", "speed": "unknown",
                                                                        "reasons": ["friendships with this server are not possible right now"]}
        results.append(summary(entry, status))
    return results
# endregion summary and status


# region client actions
def _own_presence(local_ip):
    own = friend_store.presence.get(local_ip) or {}
    return {"presence": own.get("presence", "available"), "status_text": own.get("text") or None}

def _check_on():
    if protocol.friends_mode == "off":
        return _fail(Exceptions.FRIENDS_OFF, "BridgeFriends is switched off on this server")
    return None

async def create_invite(client_key, name=None, password=None, expires_at=None, max_uses=None, accept="auto", label=None):
    problem = _check_on()
    if problem is not None:
        return problem
    owner_ip = clients.get_client_ip(client_key)
    if not _rate_ok("invite:" + owner_ip):
        return _fail(Exceptions.TOO_MANY_ATTEMPTS, f"at most {protocol.friend_requests_per_minute} invitations per minute")
    prepared = doors.prepare(owner_ip, name, password, expires_at, max_uses, accept, label)
    if is_exception(prepared):
        return prepared
    door, password = prepared
    door["verifier"] = (await doors.derive_key_async(password, door["salt"])).hex()
    added = doors.add(door)
    if is_exception(added):
        return added
    return doors.describe(door)

def list_invites(client_key):
    owner_ip = clients.get_client_ip(client_key)
    return {"invites": [doors.describe(door) for door in friend_store.doors_of(owner_ip) if doors.find(door["key"]) is door]}

def delete_invite(client_key, invite_id):
    owner_ip = clients.get_client_ip(client_key)
    for door in friend_store.doors_of(owner_ip):
        if door["invite_id"] == invite_id:
            friend_store.remove_door(door["key"])
            return {"deleted": True, "invite_id": invite_id}
    return _fail(Exceptions.KEY_ERROR, "no invitation with this id")

def parse_address(text):
    """'name@server' / 'CODE@server' / 'name' (this server) -> (door text, server URL)."""
    if not isinstance(text, str) or not text.strip() or len(text) > 600:
        return _fail(Exceptions.ARGUMENT_ERROR, "'address' must be like paddy-home@bridge.example.com")
    text = text.strip()
    if "@" in text:
        door_text, server = text.split("@", 1)
        server = server.strip()
        if "://" not in server:
            server = "https://" + server
        server_url = address.normalize_url(server)
        if server_url is None:
            return _fail(Exceptions.ARGUMENT_ERROR, f"invalid server in the friend address: {server!r}")
    else:
        door_text, server_url = text, url_env.base_root
    door_text = door_text.strip()
    if not door_text:
        return _fail(Exceptions.ARGUMENT_ERROR, "the friend address has no name or code before the @")
    return door_text, server_url

def _rate_ok(client_ip):
    now = time.monotonic()
    times = [stamp for stamp in _requests.get(client_ip, []) if now - stamp < 60]
    if len(times) >= protocol.friend_requests_per_minute:
        _requests[client_ip] = times
        return False
    times.append(now)
    if len(_requests) > 20000:
        _requests.clear()
    _requests[client_ip] = times
    return True

def _valid_challenge(challenge):
    if not isinstance(challenge, dict):
        return False
    for field in ("challenge_id", "door", "nonce", "salt"):
        if clean_text(challenge.get(field), 128) is None or not challenge[field]:
            return False
    try:
        salt = bytes.fromhex(challenge["salt"])
    except ValueError:
        return False
    return 8 <= len(salt) <= 64 and challenge.get("kdf") == doors.KDF

def _valid_answer(answer, server_url):
    if not isinstance(answer, dict):
        return False
    secret = answer.get("secret")
    return (isinstance(answer.get("friendship_id"), str) and FRIENDSHIP_ID.match(answer["friendship_id"]) is not None
            and isinstance(secret, str) and len(secret) == 64 and all(char in "0123456789abcdef" for char in secret)
            and answer.get("state") in ("active", "pending")
            and valid_client_ip(answer.get("inviter_ip"), server_url)
            and (answer.get("inviter_label") is None or clean_text(answer["inviter_label"], doors.MAX_LABEL) is not None))

async def add_friend(client_key, address_text, password, label=None):
    """Comes in through the door of another client (name or code + password)."""
    problem = _check_on()
    if problem is not None:
        return problem
    caller_ip = clients.get_client_ip(client_key)
    parsed = parse_address(address_text)
    if is_exception(parsed):
        return parsed
    door_text, server_url = parsed
    if not _rate_ok(caller_ip):
        return _fail(Exceptions.TOO_MANY_ATTEMPTS, f"at most {protocol.friend_requests_per_minute} friend requests per minute")
    problem = link.check_allowed(server_url) or await link.check_target(server_url)
    if problem is not None:
        return problem
    password = doors.check_password(password, required=False)
    if not isinstance(password, str):
        return password
    label = _label(label if label is not None else _client_name(caller_ip))
    if is_exception(label):
        return label
    if friend_store.count(caller_ip) >= protocol.max_friends_per_client:
        return _fail(Exceptions.NOT_ALLOWED, f"a client can have at most {protocol.max_friends_per_client} friends")

    if server_url == url_env.base_root:
        challenge = doors.start(door_text, url_env.base_root, caller_ip)
    else:
        challenge = await link.post(server_url, "/s2s/friends/hello", {"door": door_text, "requester_ip": caller_ip})
    if is_exception(challenge):
        return challenge
    if not _valid_challenge(challenge):
        return _fail(Exceptions.REMOTE_SERVER_ERROR, "the friend's server sent an invalid challenge")
    # The password stays here - only the proof for this one challenge goes to the other server.
    # Two steps: the second one with our own random value, so a wrong server cannot precompute a dictionary.
    client_nonce = generate_key(16)
    first_key = await doors.derive_key_async(password, challenge["salt"])
    second = await doors.second_key_async(first_key, server_url, challenge["door"], caller_ip, client_nonce)
    proof = doors.proof_for(second, server_url, challenge["door"], caller_ip, challenge["nonce"], client_nonce)
    if server_url == url_env.base_root:
        answer = await accept_request(challenge["challenge_id"], proof, client_nonce, caller_ip, label, url_env.base_root)
    else:
        answer = await link.post(server_url, "/s2s/friends/request", {
            "challenge_id": challenge["challenge_id"], "proof": proof, "client_nonce": client_nonce,
            "requester_ip": caller_ip, "requester_label": label,
        })
    if is_exception(answer):
        return answer
    if not _valid_answer(answer, server_url):
        return _fail(Exceptions.REMOTE_SERVER_ERROR, "the friend's server sent an invalid answer")
    inviter_ip = answer["inviter_ip"]
    entry = friend_store.get(caller_ip, inviter_ip)
    state = "active" if answer["state"] == "active" else "pending_out"
    if entry is not None and entry["friendship_id"] == answer["friendship_id"]:
        if entry["state"] != "active" and state == "active":
            entry["state"], entry["accepted_at"] = "active", _now()
    else:
        entry = friend_store.put({
            "friendship_id": answer["friendship_id"], "local_ip": caller_ip, "friend_ip": inviter_ip, "state": state,
            "secret": answer["secret"], "created_at": _now(), "accepted_at": _now() if state == "active" else None,
            "friend_label": answer.get("inviter_label"), "nickname": None, "door": None,
        })
    _status_cache.pop((server_url, caller_ip), None)
    return dict(summary(entry), already=bool(answer.get("already")))

async def accept_request(challenge_id, proof, client_nonce, requester_ip, requester_label, requester_server):
    """Door side: the proof fits -> the friendship (active, or pending until the owner answers)."""
    if protocol.friends_mode == "off":
        return _fail(Exceptions.FRIENDS_OFF, "BridgeFriends is switched off on this server")
    if not valid_client_ip(requester_ip, requester_server):
        return _fail(Exceptions.ARGUMENT_ERROR, "invalid client IP")
    door = await doors.finish(challenge_id, proof, client_nonce, requester_ip, requester_server)
    if is_exception(door):
        return door
    owner_ip = door["owner_ip"]
    if clients.get_client_key_from_ip(owner_ip) is None:
        friend_store.remove_door(door["key"])
        return _fail(Exceptions.FRIEND_INVITE_INVALID, "unknown friend address or wrong password")
    if requester_ip == owner_ip:
        return _fail(Exceptions.ARGUMENT_ERROR, "you cannot become your own friend")
    requester_label = clean_text(requester_label, doors.MAX_LABEL)
    inviter_label = door["label"] or _client_name(owner_ip)
    existing = friend_store.get(owner_ip, requester_ip)
    if existing is not None:
        if existing["state"] == "pending_out":
            return _fail(Exceptions.ALREADY_EXISTS, "there is already an open friend request between you")
        if existing["state"] == "pending_in" and door["accept"] == "auto":
            existing["state"], existing["accepted_at"] = "active", _now()
            notify(owner_ip, "friend_added", **_friend_fields(existing))
        return {"friendship_id": existing["friendship_id"], "secret": existing["secret"],
                "state": "active" if existing["state"] == "active" else "pending",
                "inviter_ip": owner_ip, "inviter_label": inviter_label, "already": True}
    if friend_store.count(owner_ip) >= protocol.max_friends_per_client:
        return _fail(Exceptions.NOT_ALLOWED, "the friend list of the other client is full")
    state = "active" if door["accept"] == "auto" else "pending_in"
    entry = friend_store.put({
        "friendship_id": generate_key(16), "local_ip": owner_ip, "friend_ip": requester_ip, "state": state,
        "secret": secrets.token_hex(32), "created_at": _now(), "accepted_at": _now() if state == "active" else None,
        "friend_label": requester_label, "nickname": None, "door": door["key"],
    })
    doors.used(door)
    notify(owner_ip, "friend_added" if state == "active" else "friend_request", **_friend_fields(entry))
    return {"friendship_id": entry["friendship_id"], "secret": entry["secret"],
            "state": "active" if state == "active" else "pending", "inviter_ip": owner_ip, "inviter_label": inviter_label}

def requests(client_key):
    local_ip = clients.get_client_ip(client_key)
    entries = friend_store.of_client(local_ip)
    return {"incoming": [summary(entry) for entry in entries if entry["state"] == "pending_in"],
            "outgoing": [summary(entry) for entry in entries if entry["state"] == "pending_out"]}

async def answer_request(client_key, friend_ip, accept):
    local_ip = clients.get_client_ip(client_key)
    entry = friend_store.get(local_ip, friend_ip)
    if entry is None or entry["state"] != "pending_in":
        return _fail(Exceptions.FRIEND_NOT_FOUND, "no open friend request from this client")
    if accept:
        entry["state"], entry["accepted_at"] = "active", _now()
    else:
        friend_store.remove(local_ip, friend_ip)
    server_url = address.server_of(friend_ip)
    if server_url == url_env.base_root:
        apply_answer(friend_ip, local_ip, entry["friendship_id"], accept)
    else:
        # Best effort - if the other server is not reachable now, it learns it with its next status request
        await link.post(server_url, "/s2s/friends/answer", {"friendship_id": entry["friendship_id"], "inviter_ip": local_ip,
                                                            "requester_ip": friend_ip, "accepted": bool(accept)})
        errors.pop_client_details()
    return summary(entry) if accept else {"declined": True, "friend_ip": friend_ip}

def apply_answer(requester_ip, inviter_ip, friendship_id, accepted):
    entry = friend_store.get(requester_ip, inviter_ip)
    if entry is None or entry["friendship_id"] != friendship_id or entry["state"] != "pending_out":
        return _fail(Exceptions.FRIEND_NOT_FOUND, "no open friend request")
    if accepted:
        entry["state"], entry["accepted_at"] = "active", _now()
        notify(requester_ip, "friend_added", **_friend_fields(entry))
    else:
        friend_store.remove(requester_ip, inviter_ip)
        notify(requester_ip, "friend_declined", **_friend_fields(entry))
    return True

async def remove_friend(client_key, friend_ip):
    local_ip = clients.get_client_ip(client_key)
    entry = friend_store.remove(local_ip, friend_ip)
    if entry is None:
        return _fail(Exceptions.FRIEND_NOT_FOUND, "this client is not your friend")
    server_url = address.server_of(friend_ip)
    if server_url == url_env.base_root:
        apply_remove(friend_ip, local_ip, entry["friendship_id"])
    else:
        await link.post(server_url, "/s2s/friends/remove", {"friendship_id": entry["friendship_id"], "from_ip": local_ip,
                                                            "to_ip": friend_ip})
        errors.pop_client_details()
    _status_cache.pop((server_url, local_ip), None)
    return {"removed": True, "friend_ip": friend_ip}

def apply_remove(local_ip, from_ip, friendship_id):
    entry = friend_store.get(local_ip, from_ip)
    if entry is None or entry["friendship_id"] != friendship_id:
        return _fail(Exceptions.FRIEND_NOT_FOUND, "unknown friendship")
    friend_store.remove(local_ip, from_ip)
    notify(local_ip, "friend_removed", **_friend_fields(entry))
    return True

async def list_friends(client_key):
    local_ip = clients.get_client_ip(client_key)
    entries = sorted(friend_store.of_client(local_ip), key=lambda entry: (entry["friend_label"] or "").lower())
    return {"friends": await _with_statuses(local_ip, entries), "me": _own_presence(local_ip)}

async def info(client_key, friend_ip):
    local_ip = clients.get_client_ip(client_key)
    entry = friend_store.get(local_ip, friend_ip)
    if entry is None:
        return _fail(Exceptions.FRIEND_NOT_FOUND, "this client is not your friend")
    found = await _with_statuses(local_ip, [entry], fresh=True)
    if not found:
        return _fail(Exceptions.FRIEND_NOT_FOUND, "the friendship ended")
    return found[0]

def set_presence(client_key, presence=None, text=None):
    local_ip = clients.get_client_ip(client_key)
    if presence is not None and presence not in PRESENCE_MODES:
        return _fail(Exceptions.ARGUMENT_ERROR, f"'presence' must be one of {', '.join(PRESENCE_MODES)}")
    if text is not None and (not isinstance(text, str) or len(text) > MAX_STATUS_TEXT):
        return _fail(Exceptions.ARGUMENT_ERROR, f"'status_text' must be a text with up to {MAX_STATUS_TEXT} characters")
    own = friend_store.presence.setdefault(local_ip, {"presence": "available", "text": "", "updated_at": _now()})
    if presence is not None:
        own["presence"] = presence
    if text is not None:
        own["text"] = text
    own["updated_at"] = _now()
    return _own_presence(local_ip)

def set_nickname(client_key, friend_ip, nickname):
    local_ip = clients.get_client_ip(client_key)
    entry = friend_store.get(local_ip, friend_ip)
    if entry is None:
        return _fail(Exceptions.FRIEND_NOT_FOUND, "this client is not your friend")
    if nickname is not None and (not isinstance(nickname, str) or len(nickname) > MAX_NICKNAME):
        return _fail(Exceptions.ARGUMENT_ERROR, f"'nickname' must be a text with up to {MAX_NICKNAME} characters")
    entry["nickname"] = nickname or None
    return summary(entry)
# endregion client actions


# region messages
def check_can_send(sender_ip, recipient_ip):
    entry = friend_store.get(sender_ip, recipient_ip)
    if entry is None or entry["state"] != "active":
        return _fail(Exceptions.FRIEND_NOT_FOUND, "this client is not your friend (or the friendship is not active yet)")
    return link.check_allowed(address.server_of(recipient_ip))

def accepts(recipient_ip, sender_ip):
    """Our client recipient_ip takes friend messages from sender_ip?"""
    entry = friend_store.get(recipient_ip, sender_ip)
    if entry is None or entry["state"] != "active":
        return False
    return link.check_allowed(address.server_of(sender_ip)) is None

async def send(client_key, friend_ips, content, mode, conversation_id=None, causation_id=None, times=None, broadcast=False):
    from bridge.messenger import outbox
    problem = _check_on()
    if problem is not None:
        return problem
    sender_ip = clients.get_client_ip(client_key)
    if broadcast and friend_ips is None:
        friend_ips = [entry["friend_ip"] for entry in friend_store.of_client(sender_ip) if entry["state"] == "active"
                      and link.check_allowed(address.server_of(entry["friend_ip"])) is None]
        errors.pop_client_details()
        if not friend_ips:
            return _fail(Exceptions.FRIEND_NOT_FOUND, "no active friends")
    if not isinstance(friend_ips, list) or not all(isinstance(ip, str) for ip in friend_ips):
        return _fail(Exceptions.ARGUMENT_ERROR, "'friend_ips' must be a list of client IPs")
    for friend_ip in friend_ips:
        problem = check_can_send(sender_ip, friend_ip)
        if problem is not None:
            return problem
    return await outbox.send(client_key, friend_ips, content, mode, conversation_id, causation_id, times,
                             broadcast=broadcast, content_type=ContentType.FRIEND)

async def deliver_remote(message, server_url):
    """router: a friend message to a client of another server - over the trusted or the friend connection."""
    problem = check_can_send(message.sender_ip, message.recipient_ip)
    if problem is not None:
        return problem
    result = await link.post(server_url, "/s2s/friends/message", {"message": message.to_dict()})
    return True if result is True else result

MESSAGE_STATES = ("waiting", "taken", "delivered", "expired")


async def remote_message_status(server_url, message_id, sender_ip):
    answer = await link.post(server_url, "/s2s/friends/message_status", {"message_id": message_id, "sender_ip": sender_ip})
    if is_exception(answer):
        return answer
    # From a server we do not trust: only the known fields, checked
    if not isinstance(answer, dict) or answer.get("state") not in MESSAGE_STATES:
        return {"message_id": message_id, "recipient_ip": None, "state": "unknown", "updated_at": None}
    updated_at = clean_text(answer.get("updated_at"), 64)
    try:
        if updated_at is None or datetime.datetime.fromisoformat(updated_at).tzinfo is None:
            updated_at = None
    except ValueError:
        updated_at = None
    recipient_ip = answer.get("recipient_ip") if valid_client_ip(answer.get("recipient_ip"), server_url) else None
    return {"message_id": message_id, "recipient_ip": recipient_ip, "state": answer["state"], "updated_at": updated_at}
# endregion messages


def forget_gone():
    """Called by the cleaner: friendships, invitations and presence of clients that do not exist anymore."""
    for local_ip in [ip for ip in friend_store.friendships if clients.get_client_key_from_ip(ip) is None]:
        friend_store.friendships.pop(local_ip, None)
    for key in [key for key, door in friend_store.doors.items()
                if clients.get_client_key_from_ip(door["owner_ip"]) is None
                or (door["expires_at"] is not None and _now() >= door["expires_at"])]:
        friend_store.remove_door(key)
    for client_ip in [ip for ip in friend_store.presence if clients.get_client_key_from_ip(ip) is None]:
        friend_store.presence.pop(client_ip, None)


def status():
    """For /admin/status and /admin/analysis."""
    return {
        "mode": protocol.friends_mode,
        "friendships": friend_store.total(),
        "invitations": len(friend_store.doors),
        "friend_connections": len(link.links()),
        "blocked_servers": sorted(friend_store.blocked),
    }
