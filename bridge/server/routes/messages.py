from fastapi import APIRouter

from bridge.core import protocol
from bridge.messenger import outbox, service as messenger_service
from bridge.messenger.message import ContentType, MessageMode
from bridge.errors.exceptions import Exceptions, get_exception_id, is_exception
from bridge.realm import topics
from bridge.server.routes._helpers import authenticate, check, fail, get_field

Router = APIRouter(prefix="/message")


def _times(payload):
    # When to send (send_in_seconds / send_at), how long it lives (expires_in_seconds / expires_at),
    # "timezone" for times without offset, if_past: send (default) | reject
    return check(outbox.plan_times(
        send_in_seconds=get_field(payload, "send_in_seconds", (int, float), required=False),
        send_at=get_field(payload, "send_at", str, required=False),
        expires_in_seconds=get_field(payload, "expires_in_seconds", (int, float), required=False),
        expires_at=get_field(payload, "expires_at", str, required=False),
        timezone_name=get_field(payload, "timezone", str, required=False),
        if_past=get_field(payload, "if_past", str, required=False, default="send"),
    ))


def _direct_only(payload):
    if "content" not in payload:
        get_field(payload, "content", object)  # reports the missing field
    content_type = get_field(payload, "content_type", str, required=False, default=str(ContentType.DIRECT))
    if content_type != ContentType.DIRECT:
        fail(Exceptions.NOT_ALLOWED, "Clients can only send direct messages. Use /command/call and /command/respond.")


@Router.post("/send")
async def send(payload: dict):
    # Direct message to any client on any trusted server. Tasks and responses go through /command/...
    # mode: safe (default) | fast | compressed | temporary - optional lifetime and planned send time (see _times)
    client_key = authenticate(payload)
    _direct_only(payload)
    return check(await outbox.send(
        client_key,
        [get_field(payload, "recipient_ip", str)],
        payload.get("content"),
        mode=get_field(payload, "mode", str, required=False, default=str(MessageMode.SAFE)),
        conversation_id=get_field(payload, "conversation_id", str, required=False),
        causation_id=get_field(payload, "causation_id", str, required=False),
        times=_times(payload),
    ))


@Router.post("/broadcast")
async def broadcast(payload: dict):
    # The same direct message to many clients at once (each gets its own copy with the same broadcast_id)
    client_key = authenticate(payload)
    _direct_only(payload)
    return check(await outbox.send(
        client_key,
        get_field(payload, "recipients", list),
        payload.get("content"),
        mode=get_field(payload, "mode", str, required=False, default=str(MessageMode.SAFE)),
        conversation_id=get_field(payload, "conversation_id", str, required=False),
        causation_id=get_field(payload, "causation_id", str, required=False),
        times=_times(payload),
        broadcast=True,
    ))


@Router.post("/scheduled")
async def scheduled(payload: dict):
    # Planned messages of this client + results of the ones already sent
    client_key = authenticate(payload)
    return outbox.scheduled_of(client_key)


@Router.post("/scheduled/cancel")
async def cancel_scheduled(payload: dict):
    client_key = authenticate(payload)
    return check(outbox.cancel(client_key, get_field(payload, "message_id", str)))


def _poll_publishes(payload):
    """The optional "publish" list of a poll: [{realm_address, topic, content, mode?, include_self?}, ...]."""
    publishes = get_field(payload, "publish", list, required=False)
    if publishes is None:
        return None
    if len(publishes) > protocol.max_poll_publishes:
        fail(Exceptions.ARGUMENT_ERROR, f"'publish' takes at most {protocol.max_poll_publishes} entries")
    checked = []
    for entry in publishes:
        if not isinstance(entry, dict) or "content" not in entry:
            fail(Exceptions.CLIENT_PAYLOAD_ERROR, "Every 'publish' entry needs realm_address, topic and content")
        checked.append((
            get_field(entry, "realm_address", str),
            get_field(entry, "topic", str),
            entry.get("content"),
            get_field(entry, "mode", str, required=False, default="fast"),
            get_field(entry, "include_self", bool, required=False, default=True),
        ))
    return checked


@Router.post("/poll")
async def poll(payload: dict):
    # Optional "content_types": ["direct"] or ["task", "response"] ... to poll only some pools.
    # Optional "wait_seconds" (max 25): keep the request open until a message arrives (long polling).
    # Optional "max_messages" (1-100): take up to that many messages at once -> {"messages": [...], "count"}.
    # Optional "publish" (max 10 topic publishes, like /realm/topic/publish): done first, the answer gets
    # "published" with one result per entry ({"error": id} if one failed - the poll itself still runs).
    client_key = authenticate(payload)
    publishes = _poll_publishes(payload)
    content_types = get_field(payload, "content_types", list, required=False)
    wait_seconds = get_field(payload, "wait_seconds", (int, float), required=False, default=0)
    max_messages = get_field(payload, "max_messages", int, required=False)
    published = None
    if publishes is not None:
        # Check the poll fields first - a bad poll must not publish anything
        check(messenger_service.check_wait_seconds(wait_seconds))
        check(messenger_service.check_max_messages(max_messages))
        check(messenger_service.parse_content_types(content_types))
        published = []
        for realm_address, topic, content, mode, include_self in publishes:
            result = await topics.publish(client_key, realm_address, topic, content, mode, include_self=include_self)
            published.append({"topic": topic, "error": get_exception_id(result)} if is_exception(result) else result)
    result = check(await messenger_service.poll_wait(client_key, content_types, wait_seconds, max_messages))
    if published is not None:
        result = dict(result, published=published)
    return result


@Router.post("/status")
async def status(payload: dict):
    # Status of a message this client sent: waiting, taken, delivered, expired
    client_key = authenticate(payload)
    return check(await messenger_service.message_status(client_key, get_field(payload, "message_id", str)))


@Router.post("/chunk")
async def chunk(payload: dict):
    client_key = authenticate(payload)
    return check(messenger_service.get_chunk(
        client_key,
        get_field(payload, "pending_id", str),
        get_field(payload, "chunk_index", int),
    ))


@Router.post("/complete")
async def complete(payload: dict):
    client_key = authenticate(payload)
    return check(messenger_service.complete(
        client_key,
        get_field(payload, "pending_id", str),
        get_field(payload, "sha256", str),
    ))


@Router.post("/cancel")
async def cancel(payload: dict):
    client_key = authenticate(payload)
    check(messenger_service.cancel(client_key, get_field(payload, "pending_id", str)))
    return {"cancelled": True}
