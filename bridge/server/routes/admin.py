from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from bridge import errors
from bridge.core import backup
from bridge.errors.exceptions import Exceptions
from bridge.security import authorizer
from bridge.server.routes._helpers import check, fail, get_bridge, get_field, remote_host

# Control the Bridge server from outside. Every request needs the Bridge password in the body:
# {"password": "...", ...}. After protocol.max_failed_attempts wrong passwords the caller is locked.

Router = APIRouter(prefix="/admin")


async def _verify_admin(payload, request):
    password = get_field(payload, "password", str)
    limiter_key = f"admin:{remote_host(request)}"
    if authorizer.is_locked(limiter_key):
        fail(Exceptions.TOO_MANY_ATTEMPTS, f"Admin locked for {remote_host(request)}")
    bridge = get_bridge(request)
    if not await run_in_threadpool(bridge.verify_password, password):
        # verify_password already reported it
        authorizer.register_failure(limiter_key)
        raise errors.http_exception(Exceptions.NOT_ALLOWED)
    authorizer.register_success(limiter_key)
    return bridge


@Router.post("/status")
async def status(payload: dict, request: Request):
    bridge = await _verify_admin(payload, request)
    return bridge._get_status()


@Router.post("/trusted/list")
async def trusted_list(payload: dict, request: Request):
    bridge = await _verify_admin(payload, request)
    return {"trusted_servers": bridge._get_trusted_servers()}


@Router.post("/trusted/add")
async def trusted_add(payload: dict, request: Request):
    bridge = await _verify_admin(payload, request)
    url = check(bridge._add_trusted_server(get_field(payload, "url", str)))
    return {"added": url, "trusted_servers": bridge._get_trusted_servers()}


@Router.post("/trusted/remove")
async def trusted_remove(payload: dict, request: Request):
    bridge = await _verify_admin(payload, request)
    check(bridge._remove_trusted_server(get_field(payload, "url", str)))
    return {"removed": True}


@Router.post("/trusted/connect")
async def trusted_connect(payload: dict, request: Request):
    # Start the handshake again now (e.g. after the other admin added us)
    bridge = await _verify_admin(payload, request)
    result = check(await bridge._connect_trusted_server(get_field(payload, "url", str)))
    return {"connected": result is True, "trusted_servers": bridge._get_trusted_servers()}


@Router.post("/reset")
async def reset(payload: dict, request: Request):
    bridge = await _verify_admin(payload, request)
    bridge._reset()
    return {"reset": True}


@Router.post("/password/change")
async def change_password(payload: dict, request: Request):
    bridge = await _verify_admin(payload, request)
    new_password = get_field(payload, "new_password", str)
    check(await run_in_threadpool(bridge._set_password, new_password))
    return {"changed": True}


@Router.post("/clients")
async def client_list(payload: dict, request: Request):
    bridge = await _verify_admin(payload, request)
    return {"clients": bridge._get_clients()}


@Router.post("/mailbox")
async def mailbox_view(payload: dict, request: Request):
    # Shows what waits in a client's mailbox without taking anything out (debugging / tester)
    bridge = await _verify_admin(payload, request)
    return check(bridge._get_mailbox_view(get_field(payload, "client_ip", str)))


@Router.post("/settings")
async def settings(payload: dict, request: Request):
    # relay_mode: off | trusted, accept_relayed: true | false, backup_mode: peers | off
    bridge = await _verify_admin(payload, request)
    return check(bridge._set_settings(
        relay_mode=get_field(payload, "relay_mode", str, required=False),
        accept_relayed=get_field(payload, "accept_relayed", bool, required=False),
        backup_mode=get_field(payload, "backup_mode", str, required=False),
    ))


@Router.post("/backup/status")
async def backup_status(payload: dict, request: Request):
    await _verify_admin(payload, request)
    return backup.status()


@Router.post("/backup/now")
async def backup_now(payload: dict, request: Request):
    await _verify_admin(payload, request)
    return check(await backup.backup_now(force=True))


@Router.post("/backup/restore")
async def backup_restore(payload: dict, request: Request):
    # Replaces everything in RAM with the newest backup from the trusted servers
    await _verify_admin(payload, request)
    return check(await backup.restore_from_peers(only_if_fresh=False))
