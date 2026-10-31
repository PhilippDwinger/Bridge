import datetime

from bridge import errors
from bridge.core import protocol
from bridge.errors.exceptions import Exceptions
from bridge.security.generator import get_free_key_in_dict

# session_token -> {"client_key", "created_at", "expires_at"}
session_storage = {}

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def cleanup_expired():
    now = _now()
    expired_tokens = [token for token, entry in session_storage.items() if entry["expires_at"] <= now]
    for token in expired_tokens:
        del session_storage[token]
    return len(expired_tokens)

def create_session(client_key):
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
    return token, expires_at

def get_client_key(session_token):
    entry = session_storage.get(session_token) if isinstance(session_token, str) else None
    if entry is None:
        errors.handle_error(Exceptions.SESSION_INVALID, "Unknown session token")
        return Exceptions.SESSION_INVALID
    if entry["expires_at"] <= _now():
        del session_storage[session_token]
        errors.handle_error(Exceptions.SESSION_INVALID, "Session token expired")
        return Exceptions.SESSION_INVALID
    return entry["client_key"]

def remove_session(session_token):
    session_storage.pop(session_token, None)

def remove_sessions_of_client(client_key):
    for token in [token for token, entry in session_storage.items() if entry["client_key"] == client_key]:
        del session_storage[token]

def reset():
    session_storage.clear()
