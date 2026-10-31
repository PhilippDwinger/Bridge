import datetime

from bridge import errors
from bridge.errors.exceptions import Exceptions
from bridge.security.generator import get_free_key_in_dict

# client_key -> entry. The client key is internal only and never leaves this server.
# entry: {"hashed_password", "name", "client_ip", "realms", "created_at", "last_signal"}
client_key_storage = {}

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def generate_client_key(hashed_password):
    key = get_free_key_in_dict(client_key_storage)
    if key is None:
        errors.handle_error(Exceptions.FAILED, "No free client key could be generated")
        return Exceptions.FAILED
    client_key_storage[key] = {
        "hashed_password": hashed_password,
        "created_at": _now(),
        "last_signal": _now(),
    }
    return key

def get_client_entry(client_key):
    return client_key_storage.get(client_key)

def set_client_entry(client_key, entry_key : str, value):
    entry = client_key_storage.get(client_key)
    if entry is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND, "Client key not found while setting an entry")
        return Exceptions.CLIENT_NOT_FOUND
    if not entry_key or not isinstance(entry_key, str):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "entry_key must be a non-empty string")
        return Exceptions.ARGUMENT_ERROR
    entry[entry_key] = value
    return None

def touch(client_key):
    entry = client_key_storage.get(client_key)
    if entry is not None:
        entry["last_signal"] = _now()

def remove_client(client_key):
    client_key_storage.pop(client_key, None)

def reset():
    client_key_storage.clear()
