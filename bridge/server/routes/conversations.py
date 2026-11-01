from fastapi import APIRouter

from bridge.messenger import conversations
from bridge.server.routes._helpers import authenticate, check, get_field

# Conversations - the stream of a conversation_id like "Follow stream" in Wireshark (see messenger/conversations.py)

Router = APIRouter(prefix="/conversation")


@Router.post("/start")
async def start(payload: dict):
    # title, record: metadata (default) | full, participants: [client IPs] -> a group, everybody sees everything
    client_key = authenticate(payload)
    return check(conversations.start(
        client_key,
        title=get_field(payload, "title", str, required=False),
        record=get_field(payload, "record", str, required=False, default="metadata"),
        participants=get_field(payload, "participants", list, required=False),
    ))


@Router.post("/list")
async def list_conversations(payload: dict):
    client_key = authenticate(payload)
    return conversations.list_for(client_key, get_field(payload, "limit", int, required=False, default=50))


@Router.post("/stream")
async def stream(payload: dict):
    # after_seq: only newer entries; wait_seconds: wait for new ones (follow live); content_types: filter
    client_key = authenticate(payload)
    return check(await conversations.stream(
        client_key,
        get_field(payload, "conversation_id", str),
        after_seq=get_field(payload, "after_seq", int, required=False, default=0),
        wait_seconds=get_field(payload, "wait_seconds", (int, float), required=False, default=0),
        content_types=get_field(payload, "content_types", list, required=False),
    ))


@Router.post("/close")
async def close(payload: dict):
    client_key = authenticate(payload)
    return check(conversations.close(client_key, get_field(payload, "conversation_id", str)))
