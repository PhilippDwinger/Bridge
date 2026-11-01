from bridge import errors
from bridge.core import protocol
from bridge.errors.exceptions import Exceptions
from bridge.realm import Realm, RealmType, MAX_KEY_LENGTH, _valid_name
from bridge.security.generator import get_free_key_in_dict


class PrivateRealm(Realm):
    """Roles decide everything:
    - access keys and invitation codes give roles when joining
    - a role with can_host_commands lets members host commands
    - a role with can_publish lets members publish events to topics
    - a command can be limited to allowed_roles (empty = every member)
    The owner can always host and call everything."""
    realm_type = RealmType.PRIVATE

    def __init__(self, realm_id, name, owner_ip):
        super().__init__(realm_id, name, owner_ip)
        # role_name -> {"can_host_commands": bool, "can_publish": bool}
        self.roles = {}
        # access_key -> [role names]
        self.access_keys = {}

    def _validate_roles(self, roles):
        if roles is None:
            return True
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            errors.handle_error(Exceptions.ARGUMENT_ERROR, "'roles' must be a list of role names")
            return False
        unknown_roles = [role for role in roles if role not in self.roles]
        if unknown_roles:
            errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Unknown roles: {unknown_roles}")
            return False
        return True

    def _extra_state(self):
        return {
            "roles": {name: dict(entry) for name, entry in self.roles.items()},
            "access_keys": {key: list(roles) for key, roles in self.access_keys.items()},
        }

    def _load_extra_state(self, extra):
        self.roles = {name: dict(entry) for name, entry in extra.get("roles", {}).items()}
        self.access_keys = {key: list(roles) for key, roles in extra.get("access_keys", {}).items()}

    # region join
    def join(self, client_ip, access_key=None, code=None):
        roles = None
        if isinstance(access_key, str) and access_key in self.access_keys:
            roles = self.access_keys[access_key]
        elif code is not None:
            roles = self._take_code(code)
        if roles is None:
            errors.handle_error(Exceptions.NOT_ALLOWED, "Invalid access key or invitation code")
            return Exceptions.NOT_ALLOWED
        # Roles that were deleted in the meantime are ignored
        return self.add_member(client_ip, [role for role in roles if role in self.roles])
    # endregion join

    # region owner functions
    def create_role(self, client_ip, role_name, can_host_commands=False, can_publish=False):
        if not self.is_owner(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "Only the owner can create roles")
            return Exceptions.NOT_ALLOWED
        if not _valid_name(role_name, "role_name"):
            return Exceptions.ARGUMENT_ERROR
        if role_name in self.roles:
            errors.handle_error(Exceptions.ALREADY_EXISTS, f"Role '{role_name}' already exists")
            return Exceptions.ALREADY_EXISTS
        self.roles[role_name] = {"can_host_commands": bool(can_host_commands), "can_publish": bool(can_publish)}
        return True

    def create_access_key(self, client_ip, roles=None, preferred_key=None):
        if not self.is_owner(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "Only the owner can create access keys")
            return Exceptions.NOT_ALLOWED
        if len(self.access_keys) >= protocol.max_access_keys_per_realm:
            errors.handle_error(Exceptions.NOT_ALLOWED, "Too many access keys")
            return Exceptions.NOT_ALLOWED
        if not self._validate_roles(roles):
            return Exceptions.ARGUMENT_ERROR
        if preferred_key is not None:
            if not _valid_name(preferred_key, "preferred_key", MAX_KEY_LENGTH):
                return Exceptions.ARGUMENT_ERROR
            if preferred_key in self.access_keys:
                errors.handle_error(Exceptions.ALREADY_EXISTS, "This access key already exists")
                return Exceptions.ALREADY_EXISTS
            key = preferred_key
        else:
            key = get_free_key_in_dict(self.access_keys, n_bytes=16)
        self.access_keys[key] = list(roles or [])
        return key

    def set_member_roles(self, client_ip, member_ip, roles):
        if not self.is_owner(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "Only the owner can change roles")
            return Exceptions.NOT_ALLOWED
        if not self.is_member(member_ip):
            errors.handle_error(Exceptions.ARGUMENT_ERROR, "member_ip is not a member of the realm")
            return Exceptions.ARGUMENT_ERROR
        if roles is None or not self._validate_roles(roles):
            return Exceptions.ARGUMENT_ERROR
        self.members[member_ip]["roles"] = list(dict.fromkeys(roles))
        # Without a role that may host, the member's hosted commands go
        self.prune_hosts()
        return True
    # endregion owner functions

    # region permissions
    def can_host(self, client_ip):
        if self.is_owner(client_ip):
            return True
        member = self.members.get(client_ip)
        if member is None:
            return False
        return any(self.roles.get(role, {}).get("can_host_commands") for role in member["roles"])

    def can_publish(self, client_ip):
        if self.is_owner(client_ip):
            return True
        member = self.members.get(client_ip)
        if member is None:
            return False
        return any(self.roles.get(role, {}).get("can_publish") for role in member["roles"])

    def can_call(self, client_ip, host_entry):
        if self.is_owner(client_ip):
            return True
        member = self.members.get(client_ip)
        if member is None:
            return False
        allowed_roles = host_entry.get("allowed_roles") or []
        if not allowed_roles:
            return True
        return any(role in allowed_roles for role in member["roles"])
    # endregion permissions

    def info(self, client_ip):
        data = super().info(client_ip)
        if isinstance(data, dict) and self.is_owner(client_ip):
            data["roles"] = {name: dict(entry) for name, entry in self.roles.items()}
            data["access_keys"] = {key: list(roles) for key, roles in self.access_keys.items()}
        return data
