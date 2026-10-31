import datetime

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from bridge.core import clients
from bridge.errors.exceptions import Exceptions
from bridge.security import authorizer
from bridge.security.hasher import hash_password, verify_password
from bridge.server.routes._helpers import authenticate, check, fail, get_field, remote_host

Router = APIRouter(prefix="/client")


@Router.post("/register")
async def register(payload: dict):
    name = get_field(payload, "name", str, required=False, default=clients.DEFAULT_NAME)
    password = get_field(payload, "password", str)
    # Hashing is slow on purpose - run it outside the event loop
    hashed_password = await run_in_threadpool(hash_password, password)
    if hashed_password is None:
        fail(Exceptions.ARGUMENT_ERROR, "Password must not be empty")
    client_ip = check(clients.create_client(name, hashed_password))
    return {"client_ip": client_ip}


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
