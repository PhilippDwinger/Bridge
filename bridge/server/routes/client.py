import datetime

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from bridge import errors
from bridge.core import clients, protocol
from bridge.errors.exceptions import Exceptions
from bridge.security import authorizer
from bridge.security.hasher import hash_password, verify_password
from bridge.server.routes._helpers import authenticate, check, fail, get_field, remote_host

Router = APIRouter(prefix="/client")


@Router.post("/register")
async def register(payload: dict, request: Request):
    name = get_field(payload, "name", str, required=False, default=clients.DEFAULT_NAME)
    password = get_field(payload, "password", str)
    # Checked before the slow hashing, so floods are cheap to reject
    if not authorizer.allow_event(f"register:{remote_host(request)}", protocol.max_registrations_per_host,
                                  protocol.registration_window_minutes):
        fail(Exceptions.TOO_MANY_ATTEMPTS, f"Too many registrations from {remote_host(request)}")
    if not clients.has_capacity():
        raise errors.http_exception(Exceptions.SERVER_FULL)
    if payload.get("identity_secret") is not None:
        check(clients.identity_local_id(get_field(payload, "identity_secret", str)))
    # Hashing is slow on purpose - run it outside the event loop
    hashed_password = await run_in_threadpool(hash_password, password)
    if hashed_password is None:
        fail(Exceptions.ARGUMENT_ERROR, "Password must not be empty")
    # Identity modes: without identity_secret the IP is random; with it (32+ characters, keep it secret!)
    # the IP is always the same - also after a server restart.
    identity_secret = get_field(payload, "identity_secret", str, required=False)
    client_ip = check(clients.create_client(name, hashed_password, identity_secret))
    return {"client_ip": client_ip, "stable_identity": identity_secret is not None}


@Router.post("/login")
async def login(payload: dict, request: Request):
    client_ip = get_field(payload, "client_ip", str)
    password = get_field(payload, "password", str)
    limiter_key = f"login:{remote_host(request)}"
    if authorizer.is_locked(limiter_key):
        fail(Exceptions.TOO_MANY_ATTEMPTS, f"Login locked for {remote_host(request)}")

    client_key, hashed_password = clients.get_login_data(client_ip)
    password_ok = hashed_password is not None and await run_in_threadpool(verify_password, password, hashed_password)
    if not password_ok:
        authorizer.register_failure(limiter_key)
        fail(Exceptions.INVALID_CREDENTIALS, "Login failed")
    authorizer.register_success(limiter_key)

    session_token, expires_at = check(clients.create_session(client_key))
    remaining = expires_at - datetime.datetime.now(datetime.timezone.utc)
    return {
        "session_token": session_token,
        "expires_at": expires_at.isoformat(),
        "remaining_minutes": round(remaining.total_seconds() / 60, 2),
    }


@Router.post("/logout")
async def logout(payload: dict):
    authenticate(payload)
    clients.logout(payload["session_token"])
    return {"logged_out": True}


@Router.post("/me")
async def me(payload: dict):
    client_key = authenticate(payload)
    return check(clients.get_client_info(client_key))


@Router.post("/direct")
async def direct_settings(payload: dict):
    # Who may send me direct messages. mode: everyone | allowlist | nobody; allow/block: client IPs or server URLs
    client_key = authenticate(payload)
    return check(clients.set_direct_policy(
        client_key,
        mode=get_field(payload, "mode", str, required=False),
        allow=get_field(payload, "allow", list, required=False),
        block=get_field(payload, "block", list, required=False),
    ))
