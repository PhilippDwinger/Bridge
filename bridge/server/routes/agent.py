from fastapi import APIRouter

from bridge.server.routes._helpers import authenticate, check, get_field
from bridge.subservices.bridge_agent import service as agent_service

# BridgeAgent: estimates from Bridge's own experience (only timings and sizes, never contents).
# Like everything else these are answers to requests of the client - Bridge never pushes.

Router = APIRouter(prefix="/agent")


@Router.post("/estimate")
async def estimate(payload: dict):
    # Before a call: typical / worst time, best host, a good wait_seconds
    client_key = authenticate(payload)
    return check(await agent_service.estimate(
        client_key,
        get_field(payload, "command_name", str),
        realm_address=get_field(payload, "realm_address", str, required=False),
        command_args=payload.get("command_args"),
    ))


@Router.post("/task")
async def task(payload: dict):
    # A running call: waiting (position) / being processed (since, progress), rest time, risk of expiry
    client_key = authenticate(payload)
    return check(await agent_service.task_status(client_key, get_field(payload, "task_id", str)))


@Router.post("/message")
async def message(payload: dict):
    # How fast a recipient usually takes its messages
    client_key = authenticate(payload)
    return check(await agent_service.message_info(client_key, get_field(payload, "recipient_ip", str)))
