import asyncio
import gzip
import json
import time

import httpx

from bridge import errors
from bridge.banker import trust_store
from bridge.core import protocol
from bridge.errors.exceptions import Exceptions, get_exception_from_id
from bridge.security.generator import generate_key
from bridge.security.hasher import sha256_hex, secrets_equal
from bridge.server import url_env
from bridge.server.compression import GZIP_MIN_REQUEST_BYTES

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

# Local neighbours: a peer's public URL (its identity) -> a direct connection address on this machine
# (e.g. "https://me.ts.net:8443" -> "http://127.0.0.1:8002"). When several Bridge servers run on the SAME
# machine, each is reachable from outside under its public Tailscale/Funnel URL, but reaching that URL from the
# same machine goes out to the internet and back onto itself (hairpin) and often fails. With this map the
# servers talk to each other directly over localhost, while keeping their public URL as identity everywhere else.
_local_peers = {}


def set_local_peers(mapping):
    from bridge.core import address
    _local_peers.clear()
    for public, local in (mapping or {}).items():
        normalized = address.normalize_url(public)
        if normalized and isinstance(local, str) and local.strip():
            _local_peers[normalized] = local.rstrip("/")


def _target(peer_url):
    """The address to actually open the HTTP connection to (localhost for a local neighbour, else the URL itself).
    The identity (from_url, tokens, trust) always stays peer_url - only the transport changes."""
    return _local_peers.get(peer_url, peer_url)

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


# One shared HTTP client for all server to server requests (per event loop and TLS setting).
# It keeps connections open and does not load the TLS certificates again for every request -
# a new client per request made every cross-server call much slower (especially on Windows).
_http = {"loop": None, "clients": {}}

def _get_http_client():
    loop = asyncio.get_running_loop()
    if _http["loop"] is not loop:
        _http["loop"], _http["clients"] = loop, {}
    verify = protocol.s2s_verify_tls
    client = _http["clients"].get(verify)
    if client is None or client.is_closed:
        # Idle connections are dropped after 2 s - before the other server closes them (uvicorn: 5 s),
        # so we never send on a connection that is just being closed
        client = httpx.AsyncClient(verify=verify, limits=httpx.Limits(max_connections=100, max_keepalive_connections=20,
                                                                      keepalive_expiry=2))
        _http["clients"][verify] = client
    return client

async def close_http_clients():
    """Called when the server stops."""
    clients, _http["clients"] = list(_http["clients"].values()), {}
    for client in clients:
        try:
            await client.aclose()
        except Exception:
            pass

async def _post(peer_url, path, body, headers=None, timeout=None):
    timeout = timeout or protocol.s2s_timeout_seconds
    data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = dict(headers or {}, **{"Content-Type": "application/json"})
    if len(data) >= GZIP_MIN_REQUEST_BYTES:
        # Big requests between servers travel gzip compressed (the other server unpacks them)
        data = gzip.compress(data, 6)
        headers["Content-Encoding"] = "gzip"
    response = await _get_http_client().post(_target(peer_url) + path, content=data, headers=headers, timeout=timeout)
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
        from bridge.core import version as ver
        secret = generate_key(32)
        _pending_secrets[peer_url] = secret
        try:
            status, data = await _post(peer_url, "/s2s/handshake/deliver", {
                "from_url": url_env.base_root,
                "secret": secret,
                "protocol_version": ver.protocol_version(),
                "commit": ver.commit(),
            })
        except httpx.HTTPError as error:
            trust_store.set_waiting(peer_url, f"unreachable: {type(error).__name__}")
            errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"Handshake with {peer_url} failed: {error!r}")
            return Exceptions.REMOTE_SERVER_ERROR
        finally:
            _pending_secrets.pop(peer_url, None)
        if status == 200 and isinstance(data, dict) and data.get("ok"):
            # The other server tells us its version in the answer
            info = data.get("result") if isinstance(data.get("result"), dict) else {}
            peer_version = info.get("protocol_version")
            if not protocol.compatible(peer_version):
                trust_store.set_waiting(peer_url, f"incompatible version {peer_version} (we are {ver.protocol_version()})")
                errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"{peer_url} runs incompatible version {peer_version}")
                return Exceptions.SERVER_NOT_TRUSTED
            trust_store.set_connected(peer_url, secret, peer_version, info.get("commit"))
            errors.debug_print(f"Connected with trusted server {peer_url} (version {peer_version})")
            _after_connect(peer_url)
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
async def _authorized_post(peer_url, path, body, retry=True, timeout=None):
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
    from bridge.subservices.bridge_agent import agent, routing
    started = time.monotonic()
    try:
        status, data = await _post(peer_url, path, body, headers, timeout)
    except httpx.HTTPError as error:
        # Health of the line - the agent avoids broken lines (routing = agent)
        routing.request_failed(peer_url)
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"{peer_url}{path}: {error!r}")
        return Exceptions.REMOTE_SERVER_ERROR
    if status >= 500:
        routing.request_failed(peer_url)
    else:
        routing.request_ok(peer_url)
        if not path.startswith("/s2s/backup/"):
            # Latency of the line (BridgeAgent). Backups are big and rare - they would only disturb it.
            agent.s2s_sample(peer_url, time.monotonic() - started)
    if status == 403 and isinstance(data, dict) and data.get("error") == "SERVER_NOT_TRUSTED":
        # The other side lost or changed the token (e.g. restart) - one new handshake, then retry once
        trust_store.set_waiting(peer_url, "token rejected")
        if retry:
            return await _authorized_post(peer_url, path, body, retry=False, timeout=timeout)
        return Exceptions.SERVER_NOT_TRUSTED
    if not isinstance(data, dict) or "ok" not in data:
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"{peer_url}{path} answered with HTTP {status}")
        return Exceptions.REMOTE_SERVER_ERROR
    if not data["ok"]:
        error = _error_from_answer(data)
        errors.debug_print(f"{peer_url}{path} answered with error {error.name}")
        if isinstance(data.get("details"), dict):
            # Public details of the other server (e.g. which argument is wrong) go on to our client
            errors.set_client_details(**data["details"])
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

async def relay_message(peer_url, message):
    result = await _authorized_post(peer_url, "/s2s/relay", {"message": message.to_dict()})
    return True if result is True else result

async def message_status(peer_url, message_id, sender_ip):
    return await _authorized_post(peer_url, "/s2s/status", {"message_id": message_id, "sender_ip": sender_ip})

BACKUP_TIMEOUT_SECONDS = 60

async def backup_store(peer_url, blob):
    return await _authorized_post(peer_url, "/s2s/backup/store", {"backup": blob}, timeout=BACKUP_TIMEOUT_SECONDS)

async def backup_fetch(peer_url):
    return await _authorized_post(peer_url, "/s2s/backup/fetch", {}, timeout=BACKUP_TIMEOUT_SECONDS)

async def backup_relay(peer_url, blob):
    # Hand a backup we keep for ANOTHER server on to this peer (resilience chain A -> B -> C)
    result = await _authorized_post(peer_url, "/s2s/backup/relay", {"backup": blob}, timeout=BACKUP_TIMEOUT_SECONDS)
    return True if result is True else result

async def realm_push(peer_url, view):
    """Realm server -> member server: the new view of a realm after a change."""
    return await _authorized_post(peer_url, "/s2s/realm/push", {"view": view})

async def realm_versions(peer_url, realm_addresses):
    """Member server -> realm server: current versions of these realms."""
    return await _authorized_post(peer_url, "/s2s/realm/versions", {"realm_addresses": realm_addresses})

async def realm_mirror(peer_url, realm_address):
    """Member server -> realm server: the view of one realm for us."""
    return await _authorized_post(peer_url, "/s2s/realm/mirror", {"realm_address": realm_address})

async def agent_hosts(peer_url, entries):
    """BridgeAgent: queue / waiting / working time of hosts of the other server."""
    return await _authorized_post(peer_url, "/s2s/agent/hosts", {"hosts": entries})

async def agent_task(peer_url, task_id, caller_ip):
    return await _authorized_post(peer_url, "/s2s/agent/task", {"task_id": task_id, "caller_ip": caller_ip})

async def agent_client(peer_url, client_ip, asking_ip):
    return await _authorized_post(peer_url, "/s2s/agent/client", {"client_ip": client_ip, "asking_ip": asking_ip})

async def links(peer_url):
    """The line table of the other server (BridgeAgent routing)."""
    return await _authorized_post(peer_url, "/s2s/links", {})

async def realm_code_join(peer_url, caller_ip, code):
    return await _authorized_post(peer_url, "/s2s/realm/code", {"caller_ip": caller_ip, "code": code})

async def busy_points(peer_url, client_ips):
    return await _authorized_post(peer_url, "/s2s/busy", {"client_ips": client_ips})

async def ping(peer_url):
    return await _authorized_post(peer_url, "/s2s/ping", {})
# endregion authorized requests


def _after_connect(peer_url):
    # Exchange the realm states right away (lazy import: realm.sync uses this module)
    from bridge.realm import sync
    from bridge.server import runtime
    runtime.schedule(sync.on_connected(peer_url))


def confirm_secret_hash(peer_url, secret_sha256):
    """Generator side of step 2: did we really send this secret to this server just now?"""
    secret = _pending_secrets.get(peer_url)
    return secret is not None and secrets_equal(sha256_hex(secret), secret_sha256)
