from bridge import errors
from bridge.banker import realm_store
from bridge.core import address
from bridge.errors.exceptions import Exceptions
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
    "create_code": ("create_code", ("expires_in_minutes", "roles", "preferred_code"), False),
    "create_command": ("create_command", ("command_name", "allowed_roles"), False),
    "remove_command": ("remove_command", ("command_name",), False),
    "resolve_hosts": ("resolve_hosts", ("command_name",), False),
    "create_role": ("create_role", ("role_name", "can_host_commands"), True),
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
    method = getattr(realm, method_name)
    return method(caller_ip, *(params.get(name) for name in param_names))

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
