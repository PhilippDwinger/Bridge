from fastapi import APIRouter

from bridge.core import address, clients
from bridge.errors.exceptions import Exceptions
from bridge.realm import service as realm_service
from bridge.server.routes._helpers import authenticate, check, fail, get_field

# All realm actions work the same for realms on this server and on trusted servers:
# the client sends them here, this server forwards them if the realm lives somewhere else.

Router = APIRouter(prefix="/realm")


async def _run(payload, action, params=None):
    client_key = authenticate(payload)
    realm_address = get_field(payload, "realm_address", str)
    caller_ip = clients.get_client_ip(client_key)
    result = check(await realm_service.execute(caller_ip, realm_address, action, params or {}))
    return client_key, realm_address, result


@Router.get("/public")
async def public_realm():
    return {"realm_address": realm_service.get_public_realm_address()}


@Router.post("/create")
async def create(payload: dict):
    client_key = authenticate(payload)
    realm_address = check(realm_service.create_realm(
        clients.get_client_ip(client_key),
        get_field(payload, "realm_type", str),
        get_field(payload, "realm_name", str, required=False, default="Unnamed Realm"),
        access_key=get_field(payload, "access_key", str, required=False),
        restricted_to_owner=get_field(payload, "restricted_to_owner", bool, required=False, default=False),
    ))
    clients.add_realm_membership(client_key, realm_address)
    return {"realm_address": realm_address}


@Router.post("/join")
async def join(payload: dict):
    # Either realm_address + access_key, or just the invitation code (+ server_url if the realm is on another server)
    code = get_field(payload, "code", str, required=False)
    if code is not None and payload.get("realm_address") is None:
        client_key = authenticate(payload)
        server_url = get_field(payload, "server_url", str, required=False)
        if server_url is not None:
            server_url = address.normalize_url(server_url)
            if server_url is None:
                fail(Exceptions.ARGUMENT_ERROR, "Invalid server_url")
        realm_address = check(await realm_service.join_by_code(clients.get_client_ip(client_key), code, server_url))
    else:
        client_key, realm_address, _ = await _run(payload, "join", {
            "access_key": get_field(payload, "access_key", str, required=False),
            "code": code,
        })
    clients.add_realm_membership(client_key, realm_address)
    return {"joined": True, "realm_address": realm_address}


@Router.post("/leave")
async def leave(payload: dict):
    client_key, realm_address, _ = await _run(payload, "leave")
    clients.remove_realm_membership(client_key, realm_address)
    return {"left": True}


@Router.post("/info")
async def info(payload: dict):
    _, _, result = await _run(payload, "info")
    return result


@Router.post("/kick")
async def kick(payload: dict):
    await _run(payload, "kick", {"member_ip": get_field(payload, "member_ip", str)})
    return {"kicked": True}


@Router.post("/transfer")
async def transfer(payload: dict):
    await _run(payload, "transfer_ownership", {"new_owner_ip": get_field(payload, "new_owner_ip", str)})
    return {"transferred": True}


@Router.post("/code/create")
async def create_code(payload: dict):
    _, _, code = await _run(payload, "create_code", {
        "expires_in_minutes": get_field(payload, "expires_in_minutes", (int, float), required=False),
        "roles": get_field(payload, "roles", list, required=False),
        "preferred_code": get_field(payload, "preferred_code", str, required=False),
        "max_uses": get_field(payload, "max_uses", int, required=False),
    })
    return {"code": code}


@Router.post("/command/create")
async def create_command(payload: dict):
    await _run(payload, "create_command", {
        "command_name": get_field(payload, "command_name", str),
        "allowed_roles": get_field(payload, "allowed_roles", list, required=False),
    })
    return {"created": True}


@Router.post("/command/remove")
async def remove_command(payload: dict):
    await _run(payload, "remove_command", {"command_name": get_field(payload, "command_name", str)})
    return {"removed": True}


# region private realms
@Router.post("/role/create")
async def create_role(payload: dict):
    await _run(payload, "create_role", {
        "role_name": get_field(payload, "role_name", str),
        "can_host_commands": get_field(payload, "can_host_commands", bool, required=False, default=False),
    })
    return {"created": True}


@Router.post("/role/set")
async def set_member_roles(payload: dict):
    await _run(payload, "set_member_roles", {
        "member_ip": get_field(payload, "member_ip", str),
        "roles": get_field(payload, "roles", list),
    })
    return {"updated": True}


@Router.post("/key/create")
async def create_access_key(payload: dict):
    _, _, key = await _run(payload, "create_access_key", {
        "roles": get_field(payload, "roles", list, required=False),
        "preferred_key": get_field(payload, "preferred_key", str, required=False),
    })
    return {"access_key": key}
# endregion private realms
