from bridge import errors
from bridge.banker import realm_store
from bridge.core import address, protocol
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.security import authorizer
from bridge.realm import RealmType, _valid_name
from bridge.realm.private import PrivateRealm
from bridge.realm.protected import ProtectedRealm
from bridge.realm.public import PublicRealm
from bridge.server import s2s_client, url_env

# Realms always live on the server of their address. A client only talks to its own server;
# if the realm lives somewhere else, the action is sent to that server (server to server).
# The realm server trusts the caller IP because it comes from the caller's home server, which
# authenticated the client and which must be a trusted server.

DEFAULT_PUBLIC_REALM_NAME = "Bridge"

# action -> (method name, parameters, only for private realms)
ACTIONS = {
    "join": ("join", ("access_key", "code"), False),
    "leave": ("leave", (), False),
    "info": ("info", (), False),
    "kick": ("kick", ("member_ip",), False),
    "transfer_ownership": ("transfer_ownership", ("new_owner_ip",), False),
    "create_code": ("create_code", ("expires_in_minutes", "roles", "preferred_code", "max_uses"), False),
    "create_command": ("create_command", ("command_name", "allowed_roles", "description"), False),
    "list_commands": ("list_commands", (), False),
    "subscribe": ("subscribe", ("topic",), False),
    "unsubscribe": ("unsubscribe", ("topic",), False),
    "resolve_subscribers": ("resolve_subscribers", ("topic",), False),
    "verify_event": ("verify_event", ("topic", "subscriber_ip"), False),
    "remove_command": ("remove_command", ("command_name",), False),
    "resolve_hosts": ("resolve_hosts", ("command_name",), False),
    "create_role": ("create_role", ("role_name", "can_host_commands", "can_publish"), True),
    "create_access_key": ("create_access_key", ("roles", "preferred_key"), True),
    "set_member_roles": ("set_member_roles", ("member_ip", "roles"), True),
}


# region creation
def create_realm(owner_ip, realm_type, name, access_key=None, restricted_to_owner=False):
    """Creates a realm on this server. The owner must be a client of this server. Returns the realm address."""
    if not address.is_local(owner_ip):
        errors.handle_error(Exceptions.NOT_ALLOWED, "Realms can only be created by clients of this server")
        return Exceptions.NOT_ALLOWED
    try:
        realm_type = RealmType(realm_type)
    except ValueError:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Unknown realm type: {realm_type!r}")
        return Exceptions.ARGUMENT_ERROR
    if not _valid_name(name, "realm_name"):
        return Exceptions.ARGUMENT_ERROR
    if access_key is not None and not _valid_name(access_key, "access_key", 128):
        return Exceptions.ARGUMENT_ERROR
    realm_id = realm_store.generate_realm_id()
    if realm_id is None:
        errors.handle_error(Exceptions.FAILED, "No free realm id could be generated")
        return Exceptions.FAILED

    if realm_type == RealmType.PUBLIC:
        realm = PublicRealm(realm_id, name, owner_ip)
    elif realm_type == RealmType.PROTECTED:
        realm = ProtectedRealm(realm_id, name, owner_ip, access_key, restricted_to_owner)
    else:
        realm = PrivateRealm(realm_id, name, owner_ip)
    realm_store.add_realm(realm)
    return realm.address

def create_default_public_realm():
    if realm_store.public_realm_id and realm_store.get_realm(realm_store.public_realm_id):
        return get_public_realm_address()
    realm_id = realm_store.generate_realm_id()
    realm = PublicRealm(realm_id, DEFAULT_PUBLIC_REALM_NAME)
    realm_store.add_realm(realm)
    realm_store.set_public_realm_id(realm_id)
    return realm.address

def get_public_realm_address():
    if not realm_store.public_realm_id:
        return None
    return address.make_address(url_env.base_root, realm_store.public_realm_id)
# endregion creation


# region execution
def execute_local(caller_ip, realm_address, action, params):
    server_url, realm_id = address.split_address(realm_address)
    if server_url is None:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Invalid realm address: {realm_address!r}")
        return Exceptions.ARGUMENT_ERROR
    if server_url != url_env.base_root:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "The realm does not live on this server")
        return Exceptions.ARGUMENT_ERROR
    if not address.is_valid_address(caller_ip):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "Invalid caller IP")
        return Exceptions.ARGUMENT_ERROR
    realm = realm_store.get_realm(realm_id)
    if realm is None:
        errors.handle_error(Exceptions.REALM_NOT_FOUND)
        return Exceptions.REALM_NOT_FOUND
    if action not in ACTIONS:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Unknown realm action: {action!r}")
        return Exceptions.ARGUMENT_ERROR
    if params is None:
        params = {}
    if not isinstance(params, dict):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "Realm action params must be an object")
        return Exceptions.ARGUMENT_ERROR
    method_name, param_names, private_only = ACTIONS[action]
    if private_only and not isinstance(realm, PrivateRealm):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'{action}' is only available in private realms")
        return Exceptions.ARGUMENT_ERROR
    if action == "join" and _join_locked(caller_ip):
        return Exceptions.TOO_MANY_ATTEMPTS
    method = getattr(realm, method_name)
    result = method(caller_ip, *(params.get(name) for name in param_names))
    if action == "join":
        _register_join_result(caller_ip, result)
    return result

# region join protection
# Wrong access keys and codes are counted per client and per home server of the client,
# so nobody can guess codes by trying many of them.
def _join_limiter_keys(caller_ip):
    return f"join:{caller_ip}", f"join-server:{address.server_of(caller_ip)}"

def _join_locked(caller_ip):
    client_key, server_key = _join_limiter_keys(caller_ip)
    if authorizer.is_locked(client_key) or authorizer.is_locked(server_key):
        errors.handle_error(Exceptions.TOO_MANY_ATTEMPTS, "Too many wrong access keys/codes")
        return True
    return False

def _register_join_result(caller_ip, result):
    client_key, server_key = _join_limiter_keys(caller_ip)
    if result is Exceptions.NOT_ALLOWED:
        authorizer.register_failure(client_key)
        authorizer.register_failure(server_key, protocol.max_failed_attempts_per_server)
    elif not is_exception(result):
        authorizer.register_success(client_key)
# endregion join protection


def join_by_code_local(caller_ip, code):
    """Joins the realm of an invitation code on this server. Returns the realm address."""
    if not address.is_valid_address(caller_ip):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "Invalid caller IP")
        return Exceptions.ARGUMENT_ERROR
    if _join_locked(caller_ip):
        return Exceptions.TOO_MANY_ATTEMPTS
    entry = realm_store.get_code(code)
    realm = realm_store.get_realm(entry["realm_id"]) if entry else None
    if realm is None:
        errors.handle_error(Exceptions.NOT_ALLOWED, "Unknown or expired invitation code")
        result = Exceptions.NOT_ALLOWED
    else:
        result = realm.join(caller_ip, code=code)
    _register_join_result(caller_ip, result)
    if is_exception(result):
        return result
    return realm.address

async def join_by_code(caller_ip, code, server_url=None):
    """Code of a realm on this server (server_url None) or on a trusted server."""
    if server_url is None or server_url == url_env.base_root:
        return join_by_code_local(caller_ip, code)
    return await s2s_client.realm_code_join(server_url, caller_ip, code)


async def execute(caller_ip, realm_address, action, params=None):
    """Runs a realm action where the realm lives - here or on a trusted server."""
    server_url = address.server_of(realm_address)
    if server_url is None:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Invalid realm address: {realm_address!r}")
        return Exceptions.ARGUMENT_ERROR
    if server_url == url_env.base_root:
        return execute_local(caller_ip, realm_address, action, params)
    return await s2s_client.realm_action(server_url, caller_ip, realm_address, action, params or {})
# endregion execution
