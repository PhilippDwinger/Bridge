from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from bridge import errors
from bridge.banker import trust_store
from bridge.core import address
from bridge.errors.exceptions import Exceptions, get_exception_id, is_exception
from bridge.messenger import router
from bridge.messenger.message import ContentType, message_from_dict
from bridge.realm import commands, service as realm_service
from bridge.security.hasher import sha256_hex
from bridge.server import s2s_client, url_env

# Endpoints only for other Bridge servers. Answers are always {"ok": true, "result": ...}
# or {"ok": false, "error": "<EXCEPTION_ID>"} so the calling server can map the error back.

Router = APIRouter(prefix="/s2s")

MAX_BUSY_IPS = 200


def _ok(result=True):
    return {"ok": True, "result": result}

def _error(error, status_code=200):
    if not is_exception(error):
        error = Exceptions.UNKNOWN_ERROR
    return JSONResponse(status_code=status_code, content={
        "ok": False,
        "error": get_exception_id(error),
        "message": error.default_message,
    })

def _answer(result):
    return _error(result) if is_exception(result) else _ok(result)

def _authenticate_server(request):
    """Returns the URL of the calling trusted server or None."""
    from_url = address.normalize_url(request.headers.get(s2s_client.HEADER_FROM))
    token = request.headers.get(s2s_client.HEADER_TOKEN)
    if from_url is None or token is None or not trust_store.verify_token(from_url, token):
        errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"Rejected server request from {from_url!r}")
        return None
    return from_url

def _trusted_peer_from_body(payload):
    from_url = address.normalize_url(payload.get("from_url")) if isinstance(payload, dict) else None
    if from_url is None or not trust_store.is_trusted(from_url) or from_url == url_env.base_root:
        errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"Handshake from untrusted server {from_url!r}")
        return None
    return from_url


# region handshake (no token yet)
@Router.post("/handshake/hello")
async def handshake_hello(payload: dict):
    peer_url = _trusted_peer_from_body(payload)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    if not s2s_client.is_generator_for(peer_url):
        # The caller is the generator itself - it should deliver instead of saying hello
        return _error(Exceptions.ARGUMENT_ERROR)
    return _answer(await s2s_client.handshake(peer_url))


@Router.post("/handshake/deliver")
async def handshake_deliver(payload: dict):
    peer_url = _trusted_peer_from_body(payload)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    secret = payload.get("secret")
    if not isinstance(secret, str) or len(secret) < 32 or s2s_client.is_generator_for(peer_url):
        return _error(Exceptions.ARGUMENT_ERROR)
    # Call back the server at its registered URL - only the real server can confirm the secret
    try:
        status, data = await s2s_client._post(peer_url, "/s2s/handshake/confirm", {
            "from_url": url_env.base_root,
            "secret_sha256": sha256_hex(secret),
        })
    except Exception as error:
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"Confirm callback to {peer_url} failed: {error!r}")
        return _error(Exceptions.REMOTE_SERVER_ERROR)
    if status != 200 or not isinstance(data, dict) or not data.get("ok"):
        errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"{peer_url} did not confirm the handshake secret")
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    trust_store.set_connected(peer_url, secret)
    errors.debug_print(f"Connected with trusted server {peer_url}")
    return _ok()


@Router.post("/handshake/confirm")
async def handshake_confirm(payload: dict):
    peer_url = _trusted_peer_from_body(payload)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    if not s2s_client.confirm_secret_hash(peer_url, payload.get("secret_sha256")):
        errors.handle_error(Exceptions.NOT_ALLOWED, f"Unknown handshake secret for {peer_url}")
        return _error(Exceptions.NOT_ALLOWED, 403)
    return _ok()
# endregion handshake


# region authorized
@Router.post("/ping")
async def ping(request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    return _ok({"url": url_env.base_root})


@Router.post("/message")
async def receive_message(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    message = message_from_dict(payload.get("message"))
    if is_exception(message):
        return _error(message)
    # A server may only send messages of its own clients, and only to our clients
    if address.server_of(message.sender_ip) != peer_url:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} sent a message with a foreign sender IP")
        return _error(Exceptions.NOT_ALLOWED)
    if message.content_type == ContentType.INSTRUCTION:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} tried to send an instruction")
        return _error(Exceptions.NOT_ALLOWED)
    if message.content_type == ContentType.TASK:
        # Check the realm again instead of only trusting the other server
        verified = await commands.verify_remote_task(message, peer_url)
        if is_exception(verified):
            return _error(verified)
    # Responses are checked in router.deliver_local against the task we sent
    return _answer(await router.deliver(message, from_server=peer_url))


@Router.post("/realm")
async def realm_action(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    caller_ip = payload.get("caller_ip")
    if address.server_of(caller_ip) != peer_url:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} acted for a client of another server")
        return _error(Exceptions.NOT_ALLOWED)
    return _answer(realm_service.execute_local(
        caller_ip, payload.get("realm_address"), payload.get("action"), payload.get("params"),
    ))


@Router.post("/realm/code")
async def realm_code_join(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    caller_ip = payload.get("caller_ip")
    if address.server_of(caller_ip) != peer_url:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} acted for a client of another server")
        return _error(Exceptions.NOT_ALLOWED)
    return _answer(realm_service.join_by_code_local(caller_ip, payload.get("code")))


@Router.post("/busy")
async def busy(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    client_ips = payload.get("client_ips")
    if not isinstance(client_ips, list) or len(client_ips) > MAX_BUSY_IPS:
        return _error(Exceptions.ARGUMENT_ERROR)
    return _ok(commands.get_local_busy_points([ip for ip in client_ips if isinstance(ip, str)]))
# endregion authorized
