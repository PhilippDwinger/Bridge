"""Conversations - like "Follow stream" in Wireshark.

Every message has a conversation_id. Each server records the stream of the messages its own clients send or receive
(direct, task, progress, response, event): in order (seq), with direction, type, mode, size, way (local / to another
server / relayed), state (sent -> waiting -> taken -> delivered, or expired / failed / dropped) and how long it took
until the recipient took it.

- conversation_mode (server setting): all (default - every conversation, only metadata) | started (only conversations
  started with /conversation/start) | off
- record (per started conversation): metadata (default) | full (contents too, max 2 MiB per conversation)
- Who sees what: a conversation started with participants is a group - all participants see everything.
  Otherwise every client sees only the messages it sent or received itself.
- Following live: /conversation/stream with after_seq + wait_seconds (long polling, pull only).
"""
import asyncio
import collections
import datetime
import json

from bridge import errors
from bridge.banker import conversation_store, status_store
from bridge.core import address, clients, protocol, timing
from bridge.errors.exceptions import Exceptions
from bridge.security.generator import generate_key

RECORD_MODES = ("metadata", "full")
MAX_TITLE = 100
MAX_PARTICIPANTS = 100
FINAL_STATES = ("delivered", "expired", "failed", "dropped")


def _fail(error, problem):
    errors.handle_error(error, problem)
    errors.set_client_details(problems=[problem])
    return error


def _new(conversation_id, title=None, record="metadata", started_by=None, participants=None, created_by=None):
    now = timing.now()
    created_by = created_by or started_by
    _limit_client(created_by)
    conversation = {
        "conversation_id": conversation_id,
        "title": title,
        "record": record,
        "started_by": started_by,
        # Whose message (or start) made this conversation - one client can only have a limited number
        "created_by": created_by,
        # Explicit participants (a group) - None: everybody only sees its own messages
        "participants": list(participants) if participants else None,
        "seen_by": set(),
        "created_at": now,
        "last_at": now,
        "closed": False,
        "entries": [],
        "next_seq": 1,
        "content_bytes": 0,
        "content_truncated": False,
        "by_message": {},
    }
    conversation_store.add(conversation)
    if created_by is not None:
        _by_creator.setdefault(created_by, collections.OrderedDict())[conversation_id] = True
    _limit()
    return conversation


def _limit():
    while len(conversation_store.conversations) > protocol.max_conversations:
        _forget(conversation_store.oldest())


_content_total = {"bytes": 0}
# client_ip -> conversation ids it made (oldest first)
_by_creator = {}


def _forget(conversation_id):
    conversation = conversation_store.get(conversation_id)
    if conversation is not None:
        _content_total["bytes"] -= conversation["content_bytes"]
        own = _by_creator.get(conversation.get("created_by"))
        if own is not None:
            own.pop(conversation_id, None)
    conversation_store.remove(conversation_id)


def _limit_client(client_ip):
    """A client that made too many conversations loses its own oldest one - not the ones of other clients.
    Automatic ones (opened by a message, e.g. from a client of another server) go first, started ones last."""
    if client_ip is None:
        return
    own = _by_creator.setdefault(client_ip, collections.OrderedDict())
    while len(own) >= protocol.max_conversations_per_client:
        automatic = next((cid for cid in own if (conversation_store.get(cid) or {}).get("started_by") is None), None)
        _forget(automatic if automatic is not None else next(iter(own)))


def reset():
    conversation_store.reset()
    _content_total["bytes"] = 0
    _by_creator.clear()


def _signal(conversation_id):
    event = conversation_store.signals.get(conversation_id)
    if event is not None:
        event.set()


def _is_local(ip):
    return address.is_local(ip) if isinstance(ip, str) else False


def _route_of(message):
    """local | relay:<server in the middle> | remote:<the other server>"""
    if _is_local(message.sender_ip) and _is_local(message.recipient_ip):
        return "local"
    if message.relayed_via:
        return "relay:" + ",".join(message.relayed_via)
    other = message.recipient_ip if _is_local(message.sender_ip) else message.sender_ip
    return f"remote:{address.server_of(other)}"


# region recording (hooks)
def record(message, state, route=None):
    """A message of one of our clients was sent or arrived. Same message_id = update instead of a new entry."""
    mode = protocol.conversation_mode
    if mode == "off" or not message.conversation_id:
        return
    conversation = conversation_store.get(message.conversation_id)
    if conversation is None:
        if mode != "all":
            return
        creator = message.sender_ip if _is_local(message.sender_ip) else message.recipient_ip
        conversation = _new(message.conversation_id, created_by=creator)
    if conversation["closed"]:
        return
    now = timing.now()
    entry = conversation["by_message"].get(message.message_id)
    if entry is not None:
        _set_state(conversation, entry, state, now)
        return
    if len(conversation["entries"]) >= protocol.max_conversation_entries:
        old = conversation["entries"].pop(0)
        conversation["by_message"].pop(old["message_id"], None)
        # Its content is gone - so it no longer counts against the limits
        freed = old.get("_content_bytes", 0)
        conversation["content_bytes"] -= freed
        _content_total["bytes"] -= freed
    entry = {
        "seq": conversation["next_seq"],
        "time": now.isoformat(),
        "message_id": message.message_id,
        "type": str(message.content_type),
        "mode": str(message.mode),
        "from": message.sender_ip,
        "to": message.recipient_ip,
        "size_bytes": message.size_bytes,
        "causation_id": message.causation_id,
        "broadcast_id": getattr(message, "broadcast_id", None),
        "relayed_via": list(message.relayed_via),
        "route": route or _route_of(message),
        "state": state,
        "taken_after_s": None,
        "_arrived": now,
    }
    if conversation["record"] == "full":
        fits = conversation["content_bytes"] + message.size_bytes <= protocol.max_conversation_content_kib * 1024
        fits_total = _content_total["bytes"] + message.size_bytes <= protocol.max_conversation_content_total_mb * 1024 * 1024
        if fits and fits_total:
            # Kept as the JSON text (what was counted) - parsed objects would need many times more memory
            entry["_content_text"] = message.payload
            entry["_content_bytes"] = message.size_bytes
            conversation["content_bytes"] += message.size_bytes
            _content_total["bytes"] += message.size_bytes
        else:
            conversation["content_truncated"] = True
    conversation["next_seq"] += 1
    conversation["entries"].append(entry)
    conversation["by_message"][message.message_id] = entry
    for ip in (message.sender_ip, message.recipient_ip):
        if _is_local(ip):
            conversation["seen_by"].add(ip)
    conversation["last_at"] = now
    conversation_store.touch(message.conversation_id)
    _signal(message.conversation_id)


def _set_state(conversation, entry, state, now):
    if entry["state"] in FINAL_STATES and state not in FINAL_STATES:
        return
    entry["state"] = state
    if state in ("taken", "delivered") and entry["taken_after_s"] is None:
        entry["taken_after_s"] = round((now - entry["_arrived"]).total_seconds(), 3)
    conversation["last_at"] = now
    _signal(conversation["conversation_id"])


def update_state(message_id, conversation_id, state):
    conversation = conversation_store.get(conversation_id)
    entry = conversation["by_message"].get(message_id) if conversation else None
    if entry is not None:
        _set_state(conversation, entry, state, timing.now())


def set_route(message_id, conversation_id, route):
    """The agent took another way than the direct one (routing = agent)."""
    conversation = conversation_store.get(conversation_id)
    entry = conversation["by_message"].get(message_id) if conversation else None
    if entry is not None:
        entry["route"] = route if route != "direct" else entry["route"]


def _status_changed(message, state):
    update_state(message.message_id, message.conversation_id, state)

status_store.on_status.append(_status_changed)
# endregion recording


# region client actions
def start(client_key, title=None, record="metadata", participants=None):
    caller_ip = clients.get_client_ip(client_key)
    if record not in RECORD_MODES:
        return _fail(Exceptions.ARGUMENT_ERROR, f"'record' must be one of {', '.join(RECORD_MODES)}")
    if title is not None and (not isinstance(title, str) or len(title) > MAX_TITLE):
        return _fail(Exceptions.ARGUMENT_ERROR, f"'title' must be a text with up to {MAX_TITLE} characters")
    if participants is not None:
        if (not isinstance(participants, list) or len(participants) > MAX_PARTICIPANTS
                or not all(address.is_valid_address(ip) for ip in participants)):
            return _fail(Exceptions.ARGUMENT_ERROR, f"'participants' must be a list of up to {MAX_PARTICIPANTS} client IPs")
        participants = list(dict.fromkeys([caller_ip] + participants))
    conversation = _new(generate_key(16), title, record, caller_ip, participants)
    conversation["seen_by"].add(caller_ip)
    return _summary(conversation, caller_ip)


def _may_see(conversation, client_ip):
    if conversation["participants"]:
        return client_ip in conversation["participants"]
    return client_ip in conversation["seen_by"] or client_ip == conversation["started_by"]


def _visible_entries(conversation, client_ip):
    if conversation["participants"]:
        return conversation["entries"]
    return [entry for entry in conversation["entries"] if client_ip in (entry["from"], entry["to"])]


def _stats(entries):
    by_type, by_state, by_route = {}, {}, {}
    taken = [entry["taken_after_s"] for entry in entries if entry["taken_after_s"] is not None]
    for entry in entries:
        by_type[entry["type"]] = by_type.get(entry["type"], 0) + 1
        by_state[entry["state"]] = by_state.get(entry["state"], 0) + 1
        by_route[entry["route"]] = by_route.get(entry["route"], 0) + 1
    first = entries[0]["time"] if entries else None
    last = entries[-1]["time"] if entries else None
    duration = (datetime.datetime.fromisoformat(last) - datetime.datetime.fromisoformat(first)).total_seconds() if entries else 0
    return {
        "messages": len(entries),
        "bytes": sum(entry["size_bytes"] for entry in entries),
        "by_type": by_type,
        "by_state": by_state,
        "by_route": by_route,
        "first_at": first,
        "last_at": last,
        "duration_s": round(duration, 3),
        "avg_taken_after_s": round(sum(taken) / len(taken), 3) if taken else None,
        "participants": sorted({entry["from"] for entry in entries} | {entry["to"] for entry in entries}),
    }


def _summary(conversation, client_ip):
    entries = _visible_entries(conversation, client_ip)
    return {
        "conversation_id": conversation["conversation_id"],
        "title": conversation["title"],
        "record": conversation["record"],
        "group": conversation["participants"] is not None,
        "participants": list(conversation["participants"] or []),
        "started_by_me": conversation["started_by"] == client_ip,
        # Counts for the limit per client (max_conversations_per_client) - also conversations its messages opened
        "created_by_me": conversation.get("created_by") == client_ip,
        "closed": conversation["closed"],
        "created_at": conversation["created_at"].isoformat(),
        "last_at": conversation["last_at"].isoformat(),
        "messages": len(entries),
    }


def list_for(client_key, limit=50):
    caller_ip = clients.get_client_ip(client_key)
    found = [conversation for conversation in reversed(conversation_store.conversations.values())
             if _may_see(conversation, caller_ip)]
    return {"conversations": [_summary(conversation, caller_ip) for conversation in found[:max(1, min(limit, 200))]]}


async def _refresh_remote_states(conversation, client_ip):
    """Messages our clients sent to other servers: only that server knows when they were taken - ask it
    (at most 20 at a time, in parallel). Like the ACKs in a Wireshark stream."""
    from bridge.banker import trust_store
    from bridge.messenger import service as messenger_service
    open_entries = [entry for entry in _visible_entries(conversation, client_ip)
                    if entry["state"] in ("sent", "waiting", "taken") and _is_local(entry["from"])
                    and not _is_local(entry["to"])
                    and (trust_store.is_trusted(address.server_of(entry["to"])) or entry["type"] == "friend")
                    and (timing.now() - entry["_arrived"]).total_seconds() < protocol.message_status_minutes * 60][-20:]
    if not open_entries:
        return

    async def refresh(entry):
        answer = await messenger_service.remote_status(address.server_of(entry["to"]), entry["message_id"], entry["from"],
                                                       entry["to"], entry["type"])
        if isinstance(answer, dict) and answer.get("state") in ("waiting", "taken", "delivered", "expired"):
            state = answer["state"]
            if state != entry["state"] and not (entry["state"] in FINAL_STATES and state not in FINAL_STATES):
                entry["state"] = state
                if state in ("taken", "delivered") and entry["taken_after_s"] is None and isinstance(answer.get("updated_at"), str):
                    try:
                        taken_at = datetime.datetime.fromisoformat(answer["updated_at"])
                        if taken_at.tzinfo is not None:
                            entry["taken_after_s"] = round(max(0.0, (taken_at - entry["_arrived"]).total_seconds()), 3)
                    except (ValueError, OverflowError):
                        pass  # another server's broken time - just no "taken after"

    await asyncio.gather(*(refresh(entry) for entry in open_entries))


def _public(entry):
    public = {key: value for key, value in entry.items() if not key.startswith("_")}
    if "_content_text" in entry:
        public["content"] = json.loads(entry["_content_text"])
    return public


async def stream(client_key, conversation_id, after_seq=0, wait_seconds=0, content_types=None):
    """The stream of a conversation from after_seq on. wait_seconds > 0: waits for new entries (follow live)."""
    caller_ip = clients.get_client_ip(client_key)
    conversation = conversation_store.get(conversation_id)
    if conversation is None or not _may_see(conversation, caller_ip):
        return _fail(Exceptions.KEY_ERROR, "Unknown conversation (or not yours, or forgotten after protocol.conversation_idle_hours)")
    if isinstance(after_seq, bool) or not isinstance(after_seq, int) or after_seq < 0:
        return _fail(Exceptions.ARGUMENT_ERROR, "'after_seq' must be a whole number >= 0")
    if content_types is not None and not (isinstance(content_types, list) and all(isinstance(x, str) for x in content_types)):
        return _fail(Exceptions.ARGUMENT_ERROR, "'content_types' must be a list like [\"direct\", \"task\"]")
    wait_seconds = min(max(float(wait_seconds or 0), 0.0), protocol.max_wait_seconds)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait_seconds

    def changed_since():
        return [entry for entry in _visible_entries(conversation, caller_ip)
                if entry["seq"] > after_seq and (content_types is None or entry["type"] in content_types)]

    await _refresh_remote_states(conversation, caller_ip)
    entries = changed_since()
    while not entries and wait_seconds > 0 and not conversation["closed"]:
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        event = conversation_store.signals.setdefault(conversation_id, asyncio.Event())
        event.clear()
        try:
            await asyncio.wait_for(event.wait(), remaining)
        except asyncio.TimeoutError:
            break
        entries = changed_since()
    visible = _visible_entries(conversation, caller_ip)
    return {
        **_summary(conversation, caller_ip),
        "entries": [_public(entry) for entry in entries],
        "last_seq": max((entry["seq"] for entry in visible), default=0),
        "stats": _stats(visible),
        "content_truncated": conversation["content_truncated"],
    }


def close(client_key, conversation_id):
    caller_ip = clients.get_client_ip(client_key)
    conversation = conversation_store.get(conversation_id)
    if conversation is None or conversation["started_by"] != caller_ip:
        return _fail(Exceptions.KEY_ERROR, "Only the client that started a conversation can close it")
    conversation["closed"] = True
    _signal(conversation_id)
    return {"closed": True, "conversation_id": conversation_id}
# endregion client actions


def forget_idle():
    """Conversations without activity for protocol.conversation_idle_hours are forgotten."""
    limit = timing.now() - datetime.timedelta(hours=protocol.conversation_idle_hours)
    for conversation_id in [cid for cid, conversation in conversation_store.conversations.items() if conversation["last_at"] < limit]:
        _forget(conversation_id)


def status():
    return {"mode": protocol.conversation_mode, "conversations": len(conversation_store.conversations),
            "entries": sum(len(conversation["entries"]) for conversation in conversation_store.conversations.values())}
