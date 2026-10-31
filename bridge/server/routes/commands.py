from fastapi import APIRouter

from bridge.messenger.message import MessageMode
from bridge.realm import commands
from bridge.server.routes._helpers import authenticate, check, get_field

Router = APIRouter(prefix="/command")


@Router.post("/call")
async def call(payload: dict):
    client_key = authenticate(payload)
    return check(await commands.call_command(
        client_key,
        get_field(payload, "command_name", str),
        payload.get("command_args"),
        realm_address=get_field(payload, "realm_address", str, required=False),
        mode=get_field(payload, "mode", str, required=False, default=str(MessageMode.SAFE)),
    ))


@Router.post("/respond")
async def respond(payload: dict):
    # Only the host that received the task can answer it - once
    client_key = authenticate(payload)
    if "content" not in payload:
        get_field(payload, "content", object)
    return check(await commands.respond(
        client_key,
        get_field(payload, "task_id", str),
        payload.get("content"),
        mode=get_field(payload, "mode", str, required=False, default=str(MessageMode.SAFE)),
    ))
