from fastapi import Request

from bridge import errors
from bridge.core import clients
from bridge.core.jsoncheck import json_problem, number_problem  # noqa: F401 (json_problem is used by routes)
from bridge.errors.exceptions import Exceptions, is_exception

# Small helpers shared by all routes. Request bodies are plain JSON objects (works well with Roblox/Lua).


def check(result):
    """Turns an Exceptions entry into an HTTP error, otherwise returns the result unchanged."""
    if is_exception(result):
        raise errors.http_exception(result)
    return result


def fail(error, msg="N/A"):
    errors.handle_error(error, msg)
    raise errors.http_exception(error)


def get_field(payload, key, expected_type, required=True, default=None):
    if not isinstance(payload, dict):
        fail(Exceptions.CLIENT_PAYLOAD_ERROR, "The request body must be a JSON object")
    value = payload.get(key)
    if value is None:
        if required:
            fail(Exceptions.CLIENT_PAYLOAD_ERROR, f"Missing field '{key}'")
        return default
    if expected_type is int and isinstance(value, bool):
        fail(Exceptions.CLIENT_PAYLOAD_ERROR, f"Field '{key}' must be a whole number")
    if expected_type is int and isinstance(value, float) and value.is_integer():
        value = int(value)  # Lua numbers are often sent as 3.0
    if not isinstance(value, expected_type):
        type_name = expected_type.__name__ if isinstance(expected_type, type) else str(expected_type)
        fail(Exceptions.CLIENT_PAYLOAD_ERROR, f"Field '{key}' must be of type {type_name}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # Seconds, counts, percent ... - a number with 400 digits would break float() / timedelta() later
        problem = number_problem(value)
        if problem:
            fail(Exceptions.CLIENT_PAYLOAD_ERROR, f"Field '{key}': {problem}")
    problem = json_problem(value)
    if problem:
        fail(Exceptions.CLIENT_PAYLOAD_ERROR, f"Field '{key}': {problem}")
    return value


def authenticate(payload):
    """Returns the client key for the session token in the body."""
    session_token = get_field(payload, "session_token", str)
    return check(clients.authenticate(session_token))


def get_bridge(request: Request):
    return request.app.state.bridge


def remote_host(request: Request):
    return request.client.host if request.client else "unknown"
