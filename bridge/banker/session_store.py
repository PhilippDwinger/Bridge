import datetime
import time

from bridge import errors
from bridge.core import protocol
from bridge.errors.exceptions import Exceptions
from bridge.security.generator import get_free_key_in_dict

# session_token -> {"client_key", "created_at", "expires_at"}
session_storage = {}
# client_key -> [session tokens, oldest first] - a client keeps at most protocol.max_sessions_per_client
_by_client = {}
_last_cleanup = [0.0]

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def _drop(token):
    entry = session_storage.pop(token, None)
    if entry is not None:
        tokens = _by_client.get(entry["client_key"])
        if tokens is not None:
            if token in tokens:
                tokens.remove(token)
            if not tokens:
                _by_client.pop(entry["client_key"], None)

def cleanup_expired():
    now = _now()
    expired_tokens = [token for token, entry in session_storage.items() if entry["expires_at"] <= now]
    for token in expired_tokens:
        _drop(token)
    return len(expired_tokens)

def rebuild_index():
    """After a restore from the backup (session_storage was filled directly)."""
    _by_client.clear()
    for token, entry in sorted(session_storage.items(), key=lambda item: item[1]["created_at"]):
        _by_client.setdefault(entry["client_key"], []).append(token)

def create_session(client_key):
    # A full cleanup at most every 10 seconds - not with every login
    if time.monotonic() - _last_cleanup[0] > 10:
        _last_cleanup[0] = time.monotonic()
        cleanup_expired()
    token = get_free_key_in_dict(session_storage)
    if token is None:
        errors.handle_error(Exceptions.FAILED, "No free session token could be generated")
        return Exceptions.FAILED
    now = _now()
    expires_at = now + datetime.timedelta(minutes=protocol.session_lifetime_minutes)
    session_storage[token] = {
        "client_key": client_key,
        "created_at": now,
        "expires_at": expires_at,
    }
    tokens = _by_client.setdefault(client_key, [])
    tokens.append(token)
    # Every login makes a new session - the oldest ones of this client go
    while len(tokens) > protocol.max_sessions_per_client:
        _drop(tokens[0])
    return token, expires_at

def get_client_key(session_token):
    entry = session_storage.get(session_token) if isinstance(session_token, str) else None
    if entry is None:
        errors.handle_error(Exceptions.SESSION_INVALID, "Unknown session token")
        return Exceptions.SESSION_INVALID
    if entry["expires_at"] <= _now():
        _drop(session_token)
        errors.handle_error(Exceptions.SESSION_INVALID, "Session token expired")
        return Exceptions.SESSION_INVALID
    return entry["client_key"]

def remove_session(session_token):
    _drop(session_token)

def remove_sessions_of_client(client_key):
    for token in list(_by_client.get(client_key, [])):
        _drop(token)
    for token in [token for token, entry in session_storage.items() if entry["client_key"] == client_key]:
        _drop(token)

def reset():
    session_storage.clear()
    _by_client.clear()
