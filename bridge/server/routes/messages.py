from fastapi import APIRouter

from bridge.messenger import service as messenger_service
from bridge.messenger.message import ContentType, MessageMode
from bridge.errors.exceptions import Exceptions
from bridge.server.routes._helpers import authenticate, check, fail, get_field

Router = APIRouter(prefix="/message")


@Router.post("/send")
async def send(payload: dict):
    # Direct message to any client on any trusted server. Tasks and responses go through /command/...
    client_key = authenticate(payload)
    if "content" not in payload:
        get_field(payload, "content", object)  # reports the missing field
    content_type = get_field(payload, "content_type", str, required=False, default=str(ContentType.DIRECT))
    if content_type != ContentType.DIRECT:
        fail(Exceptions.NOT_ALLOWED, "Clients can only send direct messages. Use /command/call and /command/respond.")
    message = check(await messenger_service.send_direct(
        client_key,
        recipient_ip=get_field(payload, "recipient_ip", str),
        content=payload.get("content"),
        mode=get_field(payload, "mode", str, required=False, default=str(MessageMode.SAFE)),
        conversation_id=get_field(payload, "conversation_id", str, required=False),
        causation_id=get_field(payload, "causation_id", str, required=False),
    ))
    return {
        "message_id": message.message_id,
        "conversation_id": message.conversation_id,
        "mode": str(message.mode),
        "size_bytes": message.size_bytes,
        "sha256": message.sha256,
    }


@Router.post("/poll")
async def poll(payload: dict):
    # Optional "content_types": ["direct"] or ["task", "response"] ... to poll only some pools.
    # Optional "wait_seconds" (max 25): keep the request open until a message arrives (long polling).
    client_key = authenticate(payload)
    return check(await messenger_service.poll_wait(
        client_key,
        get_field(payload, "content_types", list, required=False),
        get_field(payload, "wait_seconds", (int, float), required=False, default=0),
    ))


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
