from bridge import errors
from bridge.banker import realm_store
from bridge.core import address, protocol
from bridge.core.jsoncheck import json_problem, number_problem
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.security import authorizer
from bridge.realm import RealmType, _valid_name, sync
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
    "create_command": ("create_command", ("command_name", "allowed_roles", "description", "signature"), False),
    "list_commands": ("list_commands", (), False),
    "subscribe": ("subscribe", ("topic",), False),
    "unsubscribe": ("unsubscribe", ("topic",), False),
    "resolve_subscribers": ("resolve_subscribers", ("topic",), False),
    "verify_event": ("verify_event", ("topic", "subscriber_ip"), False),
    "remove_command": ("remove_command", ("command_name",), False),
    "resolve_hosts": ("resolve_hosts", ("command_name",), False),
    "resolve_call": ("resolve_call", ("command_name",), False),
    "create_role": ("create_role", ("role_name", "can_host_commands", "can_publish"), True),
    "create_access_key": ("create_access_key", ("roles", "preferred_key"), True),
    "set_member_roles": ("set_member_roles", ("member_ip", "roles"), True),
}


# Types of the action parameters - they also come from other servers, so they are checked here
PARAM_TYPES = {
    "access_key": str, "code": str, "member_ip": str, "new_owner_ip": str, "expires_in_minutes": (int, float),
    "roles": list, "preferred_code": str, "max_uses": int, "command_name": str, "allowed_roles": list,
    "description": str, "signature": dict, "topic": str, "subscriber_ip": str, "role_name": str,
    "can_host_commands": bool, "can_publish": bool, "preferred_key": str,
}


def _param_problem(name, value):
    expected = PARAM_TYPES.get(name)
    if value is None or expected is None:
        return None
    if isinstance(value, bool) and expected is not bool:
        return f"'{name}' has the wrong type"
    if not isinstance(value, expected):
        return f"'{name}' has the wrong type"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        problem = number_problem(value)
        if problem:
            return f"'{name}': {problem}"
    if isinstance(value, list) and not all(isinstance(item, str) for item in value):
        return f"'{name}' must be a list of texts"
    problem = json_problem(value)
    return f"'{name}': {problem}" if problem else None


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
    owned = sum(1 for realm in realm_store.realm_storage.values() if realm.owner_ip == owner_ip)
    if owned >= protocol.max_realms_per_owner:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"A client can own at most {protocol.max_realms_per_owner} realms")
        errors.set_client_details(problems=[f"a client can own at most {protocol.max_realms_per_owner} realms"])
        return Exceptions.NOT_ALLOWED
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
    for name in param_names:
        problem = _param_problem(name, params.get(name))
        if problem:
            errors.handle_error(Exceptions.ARGUMENT_ERROR, problem)
            errors.set_client_details(problems=[problem])
            return Exceptions.ARGUMENT_ERROR
    if private_only and not isinstance(realm, PrivateRealm):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'{action}' is only available in private realms")
        return Exceptions.ARGUMENT_ERROR
    if action in ("join", "create_code") and _join_locked(caller_ip):
        return Exceptions.TOO_MANY_ATTEMPTS
    method = getattr(realm, method_name)
    before = sync.before_change(realm) if action in sync.MUTATING_ACTIONS else None
    was_member = realm.is_member(caller_ip) if action == "join" else False
    result = method(caller_ip, *(params.get(name) for name in param_names))
    if action == "join":
        # The guessing counter is only reset when a real secret was checked: a public realm has none, and a
        # client that was already a member did not have one checked either. Otherwise a public join (or a rejoin)
        # with a throw-away access_key would wipe the failures and defeat the limit on protected/private realms.
        secret_checked = (realm.realm_type != RealmType.PUBLIC and not was_member
                          and bool(params.get("access_key") or params.get("code")))
        _register_join_result(caller_ip, result, secret_checked=secret_checked)
    elif action == "create_code" and result is Exceptions.ALREADY_EXISTS:
        # preferred_code that is taken tells that the code exists - it counts like a wrong code
        _register_join_result(caller_ip, Exceptions.NOT_ALLOWED)
    if before is not None and not is_exception(result):
        sync.realm_changed(realm, before)
    return result

# region join protection
# Wrong access keys and codes are counted per client and - for clients of other servers - per home server of the
# client, so nobody can guess codes by trying many of them. Our own clients are not counted together: one bad client
# would lock all of them out (each of them is limited on its own, and registrations are limited too).
def _join_limiter_keys(caller_ip):
    server_url = address.server_of(caller_ip)
    return f"join:{caller_ip}", (f"join-server:{server_url}" if server_url != url_env.base_root else None)

def _join_locked(caller_ip):
    client_key, server_key = _join_limiter_keys(caller_ip)
    if authorizer.is_locked(client_key) or (server_key and authorizer.is_locked(server_key)):
        errors.handle_error(Exceptions.TOO_MANY_ATTEMPTS, "Too many wrong access keys/codes")
        return True
    return False

def _register_join_result(caller_ip, result, secret_checked=True):
    client_key, server_key = _join_limiter_keys(caller_ip)
    if result is Exceptions.NOT_ALLOWED:
        authorizer.register_failure(client_key)
        if server_key:
            authorizer.register_failure(server_key, protocol.max_failed_attempts_per_server)
    elif not is_exception(result) and secret_checked:
        # Only a right key/code resets the counter - joining a public realm (no secret) does not
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
        before = sync.before_change(realm)
        result = realm.join(caller_ip, code=code)
        if not is_exception(result):
            sync.realm_changed(realm, before)
    _register_join_result(caller_ip, result)
    if is_exception(result):
        return result
    return realm.address

async def join_by_code(caller_ip, code, server_url=None):
    """Code of a realm on this server (server_url None) or on a trusted server."""
    if server_url is None or server_url == url_env.base_root:
        return join_by_code_local(caller_ip, code)
    result = await s2s_client.realm_code_join(server_url, caller_ip, code)
    if is_exception(result):
        return result
    # The answer becomes part of the client's memberships - only a realm address of that server is accepted
    if not isinstance(result, str) or address.server_of(result) != server_url:
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"{server_url} answered the code join with an invalid realm address")
        return Exceptions.REMOTE_SERVER_ERROR
    return result


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


def forget_client(client_ip, realm_addresses):
    """A client of this server was removed: it leaves its realms, and the local realms it owns are removed."""
    from bridge.core import clients
    from bridge.server import runtime
    for realm in list(realm_store.realm_storage.values()):
        if realm.owner_ip == client_ip and realm.realm_id != realm_store.public_realm_id:
            # Nobody could manage it anymore. Member servers see it is gone with their next version check.
            realm_store.remove_realm(realm.realm_id)
            for member_ip in realm.members:
                member_key = clients.get_client_key_from_ip(member_ip) if address.is_local(member_ip) else None
                if member_key and member_ip != client_ip:
                    clients.remove_realm_membership(member_key, realm.address)
        elif realm.is_member(client_ip):
            before = sync.before_change(realm)
            realm.remove_member(client_ip)
            sync.realm_changed(realm, before)
    for realm_address in realm_addresses:
        server_url = address.server_of(realm_address)
        if server_url and server_url != url_env.base_root:
            # Best effort - the realm server also removes it when the member is unknown later
            runtime.schedule(s2s_client.realm_action(server_url, client_ip, realm_address, "leave", {}))
