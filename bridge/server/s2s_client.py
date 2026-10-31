import asyncio

import httpx

from bridge import errors
from bridge.banker import trust_store
from bridge.core import protocol
from bridge.errors.exceptions import Exceptions, get_exception_from_id
from bridge.security.generator import generate_key
from bridge.security.hasher import sha256_hex, secrets_equal
from bridge.server import url_env

# region trust / handshake
# Two servers only talk if BOTH admins added the other one's URL.
# The handshake creates a shared secret token that protects every later server to server request:
#
#   The server with the smaller URL (string compare) is the "generator", the other one the "receiver".
#   1. generator -> receiver  /s2s/handshake/deliver {from_url, secret}
#   2. receiver checks that it trusts from_url and calls back the generator at exactly that URL:
#      receiver -> generator  /s2s/handshake/confirm {from_url, secret_sha256}
#      Only the real server behind the URL knows which secret it sent, so a fake "deliver" is rejected.
#   3. both store the secret as token.
#   If the receiver wants to start, it asks the generator with /s2s/handshake/hello.
#
# Use https in production - the secret travels once over the connection.

HEADER_FROM = "X-Bridge-From"
HEADER_TOKEN = "X-Bridge-Token"

# peer_url -> secret we are currently delivering (generator side)
_pending_secrets = {}
_handshake_locks = {}


def _lock_for(peer_url):
    lock = _handshake_locks.get(peer_url)
    if lock is None:
        lock = asyncio.Lock()
        _handshake_locks[peer_url] = lock
    return lock

def is_generator_for(peer_url):
    return url_env.base_root < peer_url

def get_pending_secret(peer_url):
    return _pending_secrets.get(peer_url)


async def _post(peer_url, path, body, headers=None):
    async with httpx.AsyncClient(timeout=protocol.s2s_timeout_seconds, verify=protocol.s2s_verify_tls) as client:
        response = await client.post(peer_url + path, json=body, headers=headers or {})
    try:
        data = response.json()
    except ValueError:
        data = None
    return response.status_code, data


def _error_from_answer(data, default=Exceptions.REMOTE_SERVER_ERROR):
    if isinstance(data, dict):
        error = get_exception_from_id(data.get("error"))
        if error is not None:
            return error
    return default


async def _run_generator(peer_url):
    async with _lock_for(peer_url):
        secret = generate_key(32)
        _pending_secrets[peer_url] = secret
        try:
            status, data = await _post(peer_url, "/s2s/handshake/deliver", {
                "from_url": url_env.base_root,
                "secret": secret,
            })
        except httpx.HTTPError as error:
            trust_store.set_waiting(peer_url, f"unreachable: {type(error).__name__}")
            errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"Handshake with {peer_url} failed: {error!r}")
            return Exceptions.REMOTE_SERVER_ERROR
        finally:
            _pending_secrets.pop(peer_url, None)
        if status == 200 and isinstance(data, dict) and data.get("ok"):
            trust_store.set_connected(peer_url, secret)
            errors.debug_print(f"Connected with trusted server {peer_url}")
            return True
        error = _error_from_answer(data)
        trust_store.set_waiting(peer_url, f"rejected: {data.get('error') if isinstance(data, dict) else status}")
        errors.debug_print(f"Handshake with {peer_url} not completed yet: {error.name}")
        return error


async def handshake(peer_url):
    """Connects to a trusted server. Safe to call again at any time (creates a new token)."""
    if not trust_store.is_trusted(peer_url):
        errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"{peer_url} is not in the trusted list")
        return Exceptions.SERVER_NOT_TRUSTED
    if peer_url == url_env.base_root:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "A server cannot trust itself")
        return Exceptions.ARGUMENT_ERROR
    if is_generator_for(peer_url):
        return await _run_generator(peer_url)

    # We are the receiver - ask the generator to deliver a secret to us
    try:
        status, data = await _post(peer_url, "/s2s/handshake/hello", {"from_url": url_env.base_root})
    except httpx.HTTPError as error:
        trust_store.set_waiting(peer_url, f"unreachable: {type(error).__name__}")
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"Handshake with {peer_url} failed: {error!r}")
        return Exceptions.REMOTE_SERVER_ERROR
    if status == 200 and isinstance(data, dict) and data.get("ok") and trust_store.get_token(peer_url):
        return True
    error = _error_from_answer(data)
    if trust_store.get_token(peer_url) is None:
        trust_store.set_waiting(peer_url, f"rejected: {data.get('error') if isinstance(data, dict) else status}")
    errors.debug_print(f"Handshake with {peer_url} not completed yet: {error.name}")
    return error
# endregion trust / handshake


# region authorized requests
async def _authorized_post(peer_url, path, body, retry=True):
    if not trust_store.is_trusted(peer_url):
        errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"{peer_url} is not in the trusted list")
        return Exceptions.SERVER_NOT_TRUSTED
    token = trust_store.get_token(peer_url)
    if token is None:
        result = await handshake(peer_url)
        if result is not True:
            return result
        token = trust_store.get_token(peer_url)
    headers = {HEADER_FROM: url_env.base_root, HEADER_TOKEN: token}
    try:
        status, data = await _post(peer_url, path, body, headers)
    except httpx.HTTPError as error:
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"{peer_url}{path}: {error!r}")
        return Exceptions.REMOTE_SERVER_ERROR
    if status == 403 and isinstance(data, dict) and data.get("error") == "SERVER_NOT_TRUSTED":
        # The other side lost or changed the token (e.g. restart) - one new handshake, then retry once
        trust_store.set_waiting(peer_url, "token rejected")
        if retry:
            return await _authorized_post(peer_url, path, body, retry=False)
        return Exceptions.SERVER_NOT_TRUSTED
    if not isinstance(data, dict) or "ok" not in data:
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"{peer_url}{path} answered with HTTP {status}")
        return Exceptions.REMOTE_SERVER_ERROR
    if not data["ok"]:
        error = _error_from_answer(data)
        errors.debug_print(f"{peer_url}{path} answered with error {error.name}")
        return error
    return data.get("result")

async def send_message(peer_url, message):
    result = await _authorized_post(peer_url, "/s2s/message", {"message": message.to_dict()})
    return True if result is True else result

async def realm_action(peer_url, caller_ip, realm_address, action, params):
    return await _authorized_post(peer_url, "/s2s/realm", {
        "caller_ip": caller_ip,
        "realm_address": realm_address,
        "action": action,
        "params": params,
    })

async def realm_code_join(peer_url, caller_ip, code):
    return await _authorized_post(peer_url, "/s2s/realm/code", {"caller_ip": caller_ip, "code": code})

async def busy_points(peer_url, client_ips):
    return await _authorized_post(peer_url, "/s2s/busy", {"client_ips": client_ips})

async def ping(peer_url):
    return await _authorized_post(peer_url, "/s2s/ping", {})
# endregion authorized requests


def confirm_secret_hash(peer_url, secret_sha256):
    """Generator side of step 2: did we really send this secret to this server just now?"""
    secret = _pending_secrets.get(peer_url)
    return secret is not None and secrets_equal(sha256_hex(secret), secret_sha256)
