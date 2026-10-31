import datetime

import hashlib

from bridge import errors
from bridge.banker import client_key_store, ip_store, mailbox_store, session_store
from bridge.core import address, protocol
from bridge.server import url_env
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.messenger.mailbox import Mailbox
from bridge.security.hasher import hash_password

# A client has two identifiers:
#   client_key - internal locator on this server, everything is stored under it. Never sent to anyone.
#   client_ip  - public address, unique across all Bridge servers, contains the URL of the home server.

MAX_NAME_LENGTH = 64
DEFAULT_NAME = "Unnamed Client"
MIN_IDENTITY_SECRET_LENGTH = 32
MAX_IDENTITY_SECRET_LENGTH = 256

# Who may send direct messages to a client
DIRECT_MODES = ("everyone", "allowlist", "nobody")
MAX_DIRECT_LIST = 500

# region registration
def remove_inactive_clients():
    """Removes clients without any request for protocol.inactive_client_days. Returns how many were removed."""
    limit = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=protocol.inactive_client_days)
    inactive_keys = [key for key, entry in client_key_store.client_key_storage.items() if entry["last_signal"] < limit]
    for client_key in inactive_keys:
        delete_client(client_key)
    if inactive_keys:
        errors.debug_print(f"Removed {len(inactive_keys)} inactive clients to make room")
    return len(inactive_keys)

def has_capacity():
    if len(client_key_store.client_key_storage) < protocol.max_clients:
        return True
    remove_inactive_clients()
    if len(client_key_store.client_key_storage) < protocol.max_clients:
        return True
    errors.handle_error(Exceptions.SERVER_FULL, f"{protocol.max_clients} clients registered")
    return False

def identity_local_id(identity_secret):
    """Stable identity: the same secret always gives the same IP on this server (also after a restart).
    Only a hash of the secret is used, so the IP does not reveal it."""
    if (not isinstance(identity_secret, str)
            or not MIN_IDENTITY_SECRET_LENGTH <= len(identity_secret) <= MAX_IDENTITY_SECRET_LENGTH):
        errors.handle_error(
            Exceptions.ARGUMENT_ERROR,
            f"identity_secret must have {MIN_IDENTITY_SECRET_LENGTH}-{MAX_IDENTITY_SECRET_LENGTH} characters"
        )
        return Exceptions.ARGUMENT_ERROR
    return hashlib.sha256(f"bridge-identity|{url_env.base_root}|{identity_secret}".encode("utf-8")).hexdigest()[:32]

def create_client(name, hashed_password, identity_secret=None):
    """Creates a client from an already hashed password. Returns the client IP.
    Without identity_secret the IP is random, with it the IP is stable (same secret -> same IP)."""
    if not hashed_password or not isinstance(hashed_password, str):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "A hashed password is required")
        return Exceptions.ARGUMENT_ERROR
    if not isinstance(name, str) or not name.strip():
        name = DEFAULT_NAME
    name = name.strip()
    if len(name) > MAX_NAME_LENGTH:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Client name is longer than {MAX_NAME_LENGTH} characters")
        return Exceptions.ARGUMENT_ERROR
    local_id = None
    if identity_secret is not None:
        local_id = identity_local_id(identity_secret)
        if is_exception(local_id):
            return local_id
    if not has_capacity():
        return Exceptions.SERVER_FULL

    client_key = client_key_store.generate_client_key(hashed_password)
    if is_exception(client_key):
        return client_key
    client_ip = ip_store.get_free_ip(client_key, local_id)
    if is_exception(client_ip):
        client_key_store.remove_client(client_key)
        return client_ip

    mailbox_store.set_mailbox(client_key, Mailbox())
    client_key_store.set_client_entry(client_key, "name", name)
    client_key_store.set_client_entry(client_key, "client_ip", client_ip)
    client_key_store.set_client_entry(client_key, "realms", [])
    client_key_store.set_client_entry(client_key, "stable_identity", local_id is not None)
    client_key_store.set_client_entry(client_key, "direct_policy", {"mode": "everyone", "allow": [], "block": []})
    errors.debug_print(f"Client '{name}' registered")
    return client_ip

def register_client(name, password, identity_secret=None):
    """Python API: registers a client with a plain password. Returns the client IP."""
    hashed_password = hash_password(password)
    if hashed_password is None:
        return Exceptions.ARGUMENT_ERROR
    return create_client(name, hashed_password, identity_secret)

def delete_client(client_key):
    entry = client_key_store.get_client_entry(client_key)
    if entry is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND)
        return Exceptions.CLIENT_NOT_FOUND
    session_store.remove_sessions_of_client(client_key)
    mailbox_store.remove_mailbox(client_key)
    ip_store.remove_ip(entry.get("client_ip"))
    client_key_store.remove_client(client_key)
    return True
# endregion registration

# region login and sessions
def get_login_data(client_ip):
    """Returns (client_key, hashed_password) or (None, None) if the IP is unknown."""
    client_key = ip_store.get_client_key(client_ip)
    entry = client_key_store.get_client_entry(client_key) if client_key else None
    if entry is None:
        return None, None
    return client_key, entry["hashed_password"]

def create_session(client_key):
    """Returns (session_token, expires_at)."""
    if client_key_store.get_client_entry(client_key) is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND)
        return Exceptions.CLIENT_NOT_FOUND
    return session_store.create_session(client_key)

def authenticate(session_token):
    """Returns the client key of a valid session."""
    client_key = session_store.get_client_key(session_token)
    if is_exception(client_key):
        return client_key
    if client_key_store.get_client_entry(client_key) is None:
        session_store.remove_session(session_token)
        errors.handle_error(Exceptions.SESSION_INVALID, "Session belongs to a client that no longer exists")
        return Exceptions.SESSION_INVALID
    client_key_store.touch(client_key)
    return client_key

def logout(session_token):
    session_store.remove_session(session_token)
    return True
# endregion login and sessions

# region client data
def get_client_ip(client_key):
    entry = client_key_store.get_client_entry(client_key)
    return entry.get("client_ip") if entry else None

def get_client_key_from_ip(client_ip):
    return ip_store.get_client_key(client_ip)

def get_client_info(client_key):
    entry = client_key_store.get_client_entry(client_key)
    if entry is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND)
        return Exceptions.CLIENT_NOT_FOUND
    return {
        "client_ip": entry["client_ip"],
        "name": entry["name"],
        "realms": list(entry["realms"]),
        "stable_identity": entry.get("stable_identity", False),
        "direct_policy": get_direct_policy(client_key),
        "created_at": entry["created_at"].isoformat(),
    }

def get_realm_memberships(client_key):
    entry = client_key_store.get_client_entry(client_key)
    return list(entry["realms"]) if entry else []

def add_realm_membership(client_key, realm_address):
    entry = client_key_store.get_client_entry(client_key)
    if entry is not None and realm_address not in entry["realms"]:
        entry["realms"].append(realm_address)

def remove_realm_membership(client_key, realm_address):
    entry = client_key_store.get_client_entry(client_key)
    if entry is not None and realm_address in entry["realms"]:
        entry["realms"].remove(realm_address)
# endregion client data


# region direct message policy
def get_direct_policy(client_key):
    entry = client_key_store.get_client_entry(client_key)
    policy = (entry or {}).get("direct_policy") or {"mode": "everyone", "allow": [], "block": []}
    return {"mode": policy["mode"], "allow": list(policy["allow"]), "block": list(policy["block"])}

def _valid_entries(entries, field_name):
    # An entry is a client IP or a whole server URL
    if not isinstance(entries, list) or len(entries) > MAX_DIRECT_LIST:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'{field_name}' must be a list with up to {MAX_DIRECT_LIST} entries")
        return False
    for entry in entries:
        if not (address.is_valid_address(entry) or address.normalize_url(entry) == entry):
            errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'{field_name}' contains neither a client IP nor a server URL: {entry!r}")
            return False
    return True

def set_direct_policy(client_key, mode=None, allow=None, block=None):
    entry = client_key_store.get_client_entry(client_key)
    if entry is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND)
        return Exceptions.CLIENT_NOT_FOUND
    policy = get_direct_policy(client_key)
    if mode is not None:
        if mode not in DIRECT_MODES:
            errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'mode' must be one of {', '.join(DIRECT_MODES)}")
            return Exceptions.ARGUMENT_ERROR
        policy["mode"] = mode
    if allow is not None:
        if not _valid_entries(allow, "allow"):
            return Exceptions.ARGUMENT_ERROR
        policy["allow"] = list(dict.fromkeys(allow))
    if block is not None:
        if not _valid_entries(block, "block"):
            return Exceptions.ARGUMENT_ERROR
        policy["block"] = list(dict.fromkeys(block))
    entry["direct_policy"] = policy
    return policy

def accepts_direct(client_key, sender_ip):
    policy = get_direct_policy(client_key)
    matches = (sender_ip, address.server_of(sender_ip))
    if any(entry in matches for entry in policy["block"]):
        return False
    if policy["mode"] == "nobody":
        return False
    if policy["mode"] == "allowlist":
        return any(entry in matches for entry in policy["allow"])
    return True
# endregion direct message policy
