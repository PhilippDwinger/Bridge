"""Connections between servers for BridgeFriends.

Trusted servers (both admins added each other) use their normal connection. With a neutral server (not trusted, not
blocked) a limited **friend connection** is made. It uses the same handshake as trusted servers, so the other server
is proven by its URL (and TLS):

  The server with the smaller URL is the "generator". It delivers a secret (/s2s/friends/link/deliver). The other
  server calls the generator back at exactly that URL (/s2s/friends/link/confirm) - only the real server behind the
  URL knows which secret it sent. Then both use the secret as token. The other server can ask the generator to start
  (/s2s/friends/link/hello).

The token of a friend connection only opens /s2s/friends/* - nothing else. Friend connections live in RAM only and are
made again automatically when one side forgot them (e.g. after a restart).
"""
import asyncio
import collections
import ipaddress
import socket
import time
from urllib.parse import urlsplit

import httpx

from bridge import errors
from bridge.banker import friend_store, trust_store
from bridge.core import address, protocol
from bridge.core.jsoncheck import json_problem
from bridge.errors.exceptions import Exceptions, get_exception_from_id, get_exception_id, is_exception
from bridge.security.generator import generate_key
from bridge.security.hasher import secrets_equal, sha256_hex
from bridge.server import s2s_client, url_env

HEADER_FRIEND_TOKEN = "X-Bridge-Friend-Token"

# peer_url -> {"token", "since"} (oldest first - the oldest goes when there are too many)
_links = collections.OrderedDict()
# Generator side: peer_url -> secret we are delivering right now
_pending = {}
_locks = {}
_handshakes = collections.deque()
_last_try = {}
# sending address -> times of its handshake requests
_sources = {}
# peer_url -> (no new try before this monotonic time, failures in a row) - only when the server did not answer
_backoff = {}
# host -> (is_private, checked_at)
_private_cache = {}


def _fail(error, problem):
    errors.handle_error(error, problem)
    errors.set_client_details(problems=[problem])
    return error


# region policy
def trusted_connected(server_url):
    return trust_store.is_trusted(server_url) and trust_store.get_token(server_url) is not None

def kind_of(server_url):
    """local | trusted | neutral | blocked"""
    if server_url == url_env.base_root:
        return "local"
    # A server both admins added on purpose wins over a stray block entry (e.g. a different spelling of the URL),
    # so an actively trusted partner is never cut off by the block list.
    if trusted_connected(server_url):
        return "trusted"
    if friend_store.is_blocked(server_url):
        return "blocked"
    return "neutral"

def check_allowed(server_url):
    """None if friendships with clients of this server are allowed (friends_mode, block list), else the exception."""
    mode = protocol.friends_mode
    if mode == "off":
        return _fail(Exceptions.FRIENDS_OFF, "BridgeFriends is switched off on this server")
    if server_url is None:
        return _fail(Exceptions.ARGUMENT_ERROR, "invalid server URL")
    kind = kind_of(server_url)
    if kind == "local":
        return None
    if kind == "blocked":
        return _fail(Exceptions.FRIEND_SERVER_NOT_ALLOWED, f"{server_url} is blocked on this server")
    if mode == "local":
        return _fail(Exceptions.FRIENDS_OFF, "friendships only with clients of this server (friends_mode local)")
    if kind == "neutral" and mode != "open":
        return _fail(Exceptions.FRIENDS_OFF, "friendships only with trusted servers (friends_mode trusted)")
    return None


def _is_private_ip(text):
    # Everything that is not a public internet address: private, loopback, link local, carrier NAT (100.64/10), ...
    return not ipaddress.ip_address(text).is_global

async def _host_is_private(host):
    if not host:
        return True
    cached = _private_cache.get(host)
    if cached is not None and time.monotonic() - cached[1] < 300:
        return cached[0]
    try:
        result = _is_private_ip(host)
    except ValueError:
        try:
            infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
            result = not infos or any(_is_private_ip(info[4][0].split("%")[0]) for info in infos)
        except (OSError, ValueError, UnicodeError):
            # Cannot be resolved: treated as not allowed (fail closed)
            result = True
    if len(_private_cache) > 5000:
        _private_cache.clear()
    _private_cache[host] = (result, time.monotonic())
    return result

def _host(url):
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None

async def check_target(server_url):
    """Neutral servers only (the URL comes from a client): a public server does not connect to private or local
    addresses (protection against requests into its own network). A server that runs locally itself may."""
    if kind_of(server_url) != "neutral":
        return None
    allowed = protocol.friends_allow_private_addresses
    if allowed is None:
        allowed = await _host_is_private(_host(url_env.base_root))
    if not allowed and await _host_is_private(_host(server_url)):
        return _fail(Exceptions.FRIEND_SERVER_NOT_ALLOWED, f"{server_url} has a private or local address")
    return None
# endregion policy


# region friend connections
def _is_generator(peer_url):
    return url_env.base_root < peer_url

def _incoming_ok(peer_url, source):
    """A server asks us to connect (hello / deliver) - each makes us call a URL we were given. So: per sending
    address (where the request really came from) friend_link_handshakes_per_minute, per server URL one per second,
    and a high limit in total. Junk requests from one address cannot use up the limit of the real servers."""
    now = time.monotonic()
    while _handshakes and now - _handshakes[0] > 60:
        _handshakes.popleft()
    if len(_handshakes) >= protocol.friend_link_handshakes_per_minute * 20:
        return False
    from_source = [stamp for stamp in _sources.get(source, []) if now - stamp < 60]
    if len(from_source) >= protocol.friend_link_handshakes_per_minute:
        _sources[source] = from_source
        return False
    last = _last_try.get(peer_url)
    if last is not None and now - last < 1:
        return False
    if len(_last_try) > 5000:
        _last_try.clear()
    if len(_sources) > 5000:
        _sources.clear()
    from_source.append(now)
    _sources[source] = from_source
    _handshakes.append(now)
    _last_try[peer_url] = now
    return True

def _backoff_left(peer_url):
    entry = _backoff.get(peer_url)
    return max(0.0, entry[0] - time.monotonic()) if entry else 0.0

def _unreachable(peer_url):
    """The other server did not answer: wait 1, 2, 4 ... at most 30 s before the next try."""
    failures = (_backoff.get(peer_url) or (0, 0))[1] + 1
    if len(_backoff) > 5000:
        _backoff.clear()
    _backoff[peer_url] = (time.monotonic() + min(30.0, 2.0 ** (failures - 1)), failures)

def _store(peer_url, token):
    _links[peer_url] = {"token": token, "since": time.time()}
    _links.move_to_end(peer_url)
    while len(_links) > protocol.max_friend_links:
        _links.popitem(last=False)

def token_of(peer_url):
    entry = _links.get(peer_url)
    return entry["token"] if entry else None

def verify_token(peer_url, token):
    entry = _links.get(peer_url)
    if entry is None or not secrets_equal(entry["token"], token):
        return False
    # Used = stays (when there are too many connections, the one not used for the longest time goes)
    _links.move_to_end(peer_url)
    return True

def drop(peer_url):
    _links.pop(peer_url, None)

def links():
    return {url: {"since": entry["since"]} for url, entry in _links.items()}

def reset():
    _links.clear()
    _pending.clear()
    _backoff.clear()


# Errors another server may give our clients through BridgeFriends - everything else becomes REMOTE_SERVER_ERROR
# (a neutral server could otherwise answer e.g. SESSION_INVALID and our client would log in again)
REMOTE_ERRORS = {
    "FRIEND_INVITE_INVALID", "FRIEND_NOT_FOUND", "FRIENDS_OFF", "FRIEND_SERVER_NOT_ALLOWED", "TOO_MANY_ATTEMPTS",
    "ALREADY_EXISTS", "NOT_ALLOWED", "ARGUMENT_ERROR", "CLIENT_PAYLOAD_ERROR", "MAILBOX_FULL", "RECIPIENT_NOT_FOUND",
    "MESSAGE_TOO_LARGE", "MESSAGE_EXPIRED", "HASH_MISMATCH", "KEY_ERROR", "SERVER_NOT_TRUSTED",
}


def remote_error(error, details=None):
    """An error of another server as our clients may see it (allow list, only short text details)."""
    error_id = get_exception_id(error)
    problems = details.get("problems") if isinstance(details, dict) else None
    if isinstance(problems, list):
        problems = [text[:200] for text in problems[:5] if isinstance(text, str) and not json_problem(text)]
        if problems:
            errors.set_client_details(problems=problems)
    if error_id not in REMOTE_ERRORS:
        if error_id == "SERVER_STARTING":
            errors.set_client_details(problems=["the friend's server is starting - try again in a moment"])
        return Exceptions.REMOTE_SERVER_ERROR
    return error

def _error_from(data, default=Exceptions.REMOTE_SERVER_ERROR):
    if isinstance(data, dict):
        error = get_exception_from_id(data.get("error"))
        if error is not None:
            return remote_error(error, data.get("details"))
    return default

def _lock_for(peer_url):
    lock = _locks.get(peer_url)
    if lock is None:
        if len(_locks) > 5000:
            _locks.clear()
        lock = _locks[peer_url] = asyncio.Lock()
    return lock

async def connect(peer_url, renew=False):
    """Makes a friend connection with a neutral server. True or an exception.
    renew: deliver a new secret even if we have one (the other server lost its token). The old token stays valid
    until the new one is confirmed - a fake hello cannot cut the connection."""
    problem = check_allowed(peer_url) or await check_target(peer_url)
    if problem is not None:
        return problem
    async with _lock_for(peer_url):
        if token_of(peer_url) and not renew:
            return True
        waiting = _backoff_left(peer_url)
        if waiting > 0:
            return _fail(Exceptions.REMOTE_SERVER_ERROR, f"the friend's server did not answer - next try in {waiting:.0f} s")
        if _is_generator(peer_url):
            return await _deliver(peer_url)
        try:
            status, data = await s2s_client._post(peer_url, "/s2s/friends/link/hello", {"from_url": url_env.base_root})
        except (httpx.HTTPError, httpx.InvalidURL) as error:
            _unreachable(peer_url)
            errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"Friend connection to {peer_url} failed: {error!r}")
            return Exceptions.REMOTE_SERVER_ERROR
        _backoff.pop(peer_url, None)
        if status == 200 and isinstance(data, dict) and data.get("ok") and token_of(peer_url):
            return True
        return _error_from(data)

async def _deliver(peer_url):
    secret = generate_key(32)
    _pending[peer_url] = secret
    try:
        status, data = await s2s_client._post(peer_url, "/s2s/friends/link/deliver",
                                              {"from_url": url_env.base_root, "secret": secret})
    except (httpx.HTTPError, httpx.InvalidURL) as error:
        _unreachable(peer_url)
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"Friend connection to {peer_url} failed: {error!r}")
        return Exceptions.REMOTE_SERVER_ERROR
    finally:
        _pending.pop(peer_url, None)
    _backoff.pop(peer_url, None)
    if status == 200 and isinstance(data, dict) and data.get("ok"):
        _store(peer_url, secret)
        errors.debug_print(f"Friend connection with {peer_url}")
        return True
    return _error_from(data)


def _peer_from_body(payload):
    peer_url = address.normalize_url(payload.get("from_url")) if isinstance(payload, dict) else None
    if peer_url is None or peer_url == url_env.base_root:
        return None
    return peer_url

async def on_hello(payload, source):
    """We are the generator - the other server asks us to deliver a secret."""
    peer_url = _peer_from_body(payload)
    if peer_url is None or not _is_generator(peer_url):
        return _fail(Exceptions.ARGUMENT_ERROR, "invalid friend connection request")
    problem = check_allowed(peer_url) or await check_target(peer_url)
    if problem is not None:
        return problem
    if not _incoming_ok(peer_url, source):
        return _fail(Exceptions.TOO_MANY_ATTEMPTS, "too many friend connection attempts")
    # The other server has no token (anymore): deliver a new one. It asked, so it is there.
    _backoff.pop(peer_url, None)
    return await connect(peer_url, renew=True)

async def on_deliver(payload, source):
    """We are the receiver: check the secret by calling the generator back at its URL."""
    peer_url = _peer_from_body(payload)
    secret = payload.get("secret") if isinstance(payload, dict) else None
    if peer_url is None or _is_generator(peer_url) or not isinstance(secret, str) or len(secret) < 32 or len(secret) > 256:
        return _fail(Exceptions.ARGUMENT_ERROR, "invalid friend connection request")
    problem = check_allowed(peer_url) or await check_target(peer_url)
    if problem is not None:
        return problem
    if not _incoming_ok(peer_url, source):
        return _fail(Exceptions.TOO_MANY_ATTEMPTS, "too many friend connection attempts")
    try:
        status, data = await s2s_client._post(peer_url, "/s2s/friends/link/confirm",
                                              {"from_url": url_env.base_root, "secret_sha256": sha256_hex(secret)})
    except (httpx.HTTPError, httpx.InvalidURL) as error:
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"Friend confirm callback to {peer_url} failed: {error!r}")
        return Exceptions.REMOTE_SERVER_ERROR
    if status != 200 or not isinstance(data, dict) or not data.get("ok"):
        return _fail(Exceptions.SERVER_NOT_TRUSTED, f"{peer_url} did not confirm the friend connection")
    _store(peer_url, secret)
    errors.debug_print(f"Friend connection with {peer_url}")
    return True

def on_confirm(payload):
    peer_url = _peer_from_body(payload)
    secret = _pending.get(peer_url) if peer_url else None
    return secret is not None and secrets_equal(sha256_hex(secret), payload.get("secret_sha256"))
# endregion friend connections


# region requests
def authenticate(request):
    """(peer_url, None) for a server with a valid trusted or friend token that may do friendships with us,
    else (None, exception). An invalid token gives SERVER_NOT_TRUSTED - the other side then connects again."""
    peer_url = address.normalize_url(request.headers.get(s2s_client.HEADER_FROM))
    trusted_token = request.headers.get(s2s_client.HEADER_TOKEN)
    friend_token = request.headers.get(HEADER_FRIEND_TOKEN)
    if peer_url is None or peer_url == url_env.base_root:
        return None, Exceptions.SERVER_NOT_TRUSTED
    if trusted_token is not None and trust_store.verify_token(peer_url, trusted_token):
        pass
    elif friend_token is not None and verify_token(peer_url, friend_token):
        pass
    else:
        errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"Friend request from {peer_url} without a valid token")
        return None, Exceptions.SERVER_NOT_TRUSTED
    problem = check_allowed(peer_url)
    if problem is not None:
        return None, problem
    return peer_url, None

async def post(peer_url, path, body, retry=True):
    """A request to /s2s/friends/* of another server - over the trusted connection or a friend connection.
    Returns the result, or an exception (with the public details of the other server)."""
    problem = check_allowed(peer_url)
    if problem is not None:
        return problem
    if trusted_connected(peer_url):
        result = await s2s_client._authorized_post(peer_url, path, body)
        if is_exception(result):
            return remote_error(result, errors.pop_client_details())
        return result
    if token_of(peer_url) is None:
        result = await connect(peer_url)
        if result is not True:
            return result
    token = token_of(peer_url)
    if token is None:
        return Exceptions.REMOTE_SERVER_ERROR
    headers = {s2s_client.HEADER_FROM: url_env.base_root, HEADER_FRIEND_TOKEN: token}
    started = time.monotonic()
    try:
        status, data = await s2s_client._post(peer_url, path, body, headers)
    except (httpx.HTTPError, httpx.InvalidURL) as error:
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"{peer_url}{path}: {error!r}")
        return Exceptions.REMOTE_SERVER_ERROR
    if status < 500:
        from bridge.subservices.bridge_agent import agent
        agent.s2s_sample(peer_url, time.monotonic() - started)
    if status == 403 and isinstance(data, dict) and data.get("error") == "SERVER_NOT_TRUSTED":
        # The other server forgot the friend connection (e.g. restart) - connect again, then retry once
        drop(peer_url)
        if retry:
            return await post(peer_url, path, body, retry=False)
        return Exceptions.SERVER_NOT_TRUSTED
    if not isinstance(data, dict) or "ok" not in data:
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"{peer_url}{path} answered with HTTP {status}")
        return Exceptions.REMOTE_SERVER_ERROR
    if not data["ok"]:
        return _error_from(data)
    return data.get("result")
# endregion requests
