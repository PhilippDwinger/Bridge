import datetime
from enum import StrEnum

from bridge import errors
from bridge.core import address
from bridge.errors.exceptions import Exceptions
from bridge.security.generator import get_free_key_in_dict
from bridge.server import url_env

# Members are identified by their client IP (not the client key), because members can live on other servers.

MAX_NAME_LENGTH = 64
MAX_KEY_LENGTH = 128
MAX_CODE_MINUTES = 60 * 24 * 30


class RealmType(StrEnum):
    PUBLIC = "public"
    PROTECTED = "protected"
    PRIVATE = "private"


def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def _valid_name(value, field_name, max_length=MAX_NAME_LENGTH):
    if isinstance(value, str) and value.strip() and len(value) <= max_length:
        return True
    errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'{field_name}' must be a non-empty string with up to {max_length} characters")
    return False

def _valid_minutes(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= MAX_CODE_MINUTES:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'expires_in_minutes' must be a number between 1 and {MAX_CODE_MINUTES}")
        return False
    return True


class Realm:
    realm_type = None

    def __init__(self, realm_id, name, owner_ip=None):
        self.realm_id = realm_id
        self.address = address.make_address(url_env.base_root, realm_id)
        self.name = name
        self.owner_ip = owner_ip
        self.created_at = _now()
        # client_ip -> {"roles": [role names], "joined_at": datetime}
        self.members = {}
        # command_name -> {host_ip: {"allowed_roles": [role names]}}
        self.commands = {}
        # invitation code -> {"roles": [role names], "expires_at": datetime}
        self.codes = {}
        if owner_ip:
            self.add_member(owner_ip)

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return str(self.__dict__)

    # region membership
    def is_owner(self, client_ip):
        return client_ip is not None and client_ip == self.owner_ip

    def is_member(self, client_ip):
        return client_ip in self.members

    def add_member(self, client_ip, roles=None):
        entry = self.members.get(client_ip)
        if entry is None:
            entry = {"roles": [], "joined_at": _now()}
            self.members[client_ip] = entry
        for role in roles or []:
            if role not in entry["roles"]:
                entry["roles"].append(role)
        return True

    def remove_member(self, client_ip):
        self.members.pop(client_ip, None)
        # Hosted commands of a member that left are removed as well
        for command_name in list(self.commands):
            self.commands[command_name].pop(client_ip, None)
            if not self.commands[command_name]:
                del self.commands[command_name]

    def join(self, client_ip, access_key=None, code=None):
        raise NotImplementedError

    def leave(self, client_ip):
        if not self.is_member(client_ip):
            errors.handle_error(Exceptions.KEY_ERROR, "Client is not a member of the realm")
            return Exceptions.KEY_ERROR
        if self.is_owner(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "The owner cannot leave. Transfer the ownership first.")
            return Exceptions.NOT_ALLOWED
        self.remove_member(client_ip)
        return True

    def kick(self, client_ip, member_ip):
        if not self.is_owner(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "Only the owner can kick members")
            return Exceptions.NOT_ALLOWED
        if member_ip == client_ip or not self.is_member(member_ip):
            errors.handle_error(Exceptions.ARGUMENT_ERROR, "member_ip must be another member of the realm")
            return Exceptions.ARGUMENT_ERROR
        self.remove_member(member_ip)
        return True

    def transfer_ownership(self, client_ip, new_owner_ip):
        if not self.is_owner(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "Only the owner can transfer the ownership")
            return Exceptions.NOT_ALLOWED
        if not self.is_member(new_owner_ip):
            errors.handle_error(Exceptions.ARGUMENT_ERROR, "The new owner must be a member of the realm")
            return Exceptions.ARGUMENT_ERROR
        self.owner_ip = new_owner_ip
        return True
    # endregion membership

    # region codes
    def _take_code(self, code):
        """Returns the roles of a valid code (codes can be used multiple times until they expire)."""
        now = _now()
        for expired_code in [c for c, entry in self.codes.items() if entry["expires_at"] <= now]:
            del self.codes[expired_code]
        if not isinstance(code, str):
            return None
        entry = self.codes.get(code)
        return list(entry["roles"]) if entry else None

    def _validate_roles(self, roles):
        # Overwritten by PrivateRealm. Other realms have no roles.
        if roles:
            errors.handle_error(Exceptions.ARGUMENT_ERROR, f"{self.realm_type} realms have no roles")
            return False
        return True

    def create_code(self, client_ip, expires_in_minutes, roles=None, preferred_code=None):
        if not self.is_owner(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "Only the owner can create invitation codes")
            return Exceptions.NOT_ALLOWED
        if not _valid_minutes(expires_in_minutes) or not self._validate_roles(roles):
            return Exceptions.ARGUMENT_ERROR
        if preferred_code is not None:
            if not _valid_name(preferred_code, "preferred_code", MAX_KEY_LENGTH):
                return Exceptions.ARGUMENT_ERROR
            self._take_code(None)  # cleans up expired codes
            if preferred_code in self.codes:
                errors.handle_error(Exceptions.ALREADY_EXISTS, "This code is already in use")
                return Exceptions.ALREADY_EXISTS
            code = preferred_code
        else:
            code = get_free_key_in_dict(self.codes, n_bytes=6)
        self.codes[code] = {
            "roles": list(roles or []),
            "expires_at": _now() + datetime.timedelta(minutes=expires_in_minutes),
        }
        return code
    # endregion codes

    # region commands
    def can_see_commands(self, client_ip):
        return self.is_member(client_ip)

    def can_host(self, client_ip):
        return self.is_member(client_ip)

    def can_call(self, client_ip, host_entry):
        return self.is_member(client_ip)

    def create_command(self, client_ip, command_name, allowed_roles=None):
        if not _valid_name(command_name, "command_name", 128):
            return Exceptions.ARGUMENT_ERROR
        if not self.can_host(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, f"Client may not host commands in this {self.realm_type} realm")
            return Exceptions.NOT_ALLOWED
        if allowed_roles is not None and not isinstance(allowed_roles, list):
            errors.handle_error(Exceptions.ARGUMENT_ERROR, "'allowed_roles' must be a list")
            return Exceptions.ARGUMENT_ERROR
        if not self._validate_roles(allowed_roles):
            return Exceptions.ARGUMENT_ERROR
        hosts = self.commands.setdefault(command_name, {})
        if client_ip in hosts:
            errors.handle_error(Exceptions.ALREADY_EXISTS, f"Client already hosts '{command_name}'")
            return Exceptions.ALREADY_EXISTS
        hosts[client_ip] = {"allowed_roles": list(allowed_roles or [])}
        return True

    def remove_command(self, client_ip, command_name):
        hosts = self.commands.get(command_name)
        if not hosts or client_ip not in hosts:
            errors.handle_error(Exceptions.COMMAND_NOT_FOUND, f"Client does not host '{command_name}'")
            return Exceptions.COMMAND_NOT_FOUND
        del hosts[client_ip]
        if not hosts:
            del self.commands[command_name]
        return True

    def resolve_hosts(self, client_ip, command_name):
        """All hosts of the command the caller is allowed to use (can be an empty list)."""
        if not self.can_see_commands(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "Client is not a member of the realm")
            return Exceptions.NOT_ALLOWED
        hosts = self.commands.get(command_name) or {}
        return [host_ip for host_ip, host_entry in hosts.items() if self.can_call(client_ip, host_entry)]
    # endregion commands

    # region info
    def info(self, client_ip):
        if not self.can_see_commands(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "Client is not a member of the realm")
            return Exceptions.NOT_ALLOWED
        data = {
            "realm_address": self.address,
            "realm_type": str(self.realm_type),
            "name": self.name,
            "owner_ip": self.owner_ip,
            "is_owner": self.is_owner(client_ip),
            "is_member": self.is_member(client_ip),
            "member_count": len(self.members),
            "commands": {name: len(hosts) for name, hosts in self.commands.items()},
            "created_at": self.created_at.isoformat(),
        }
        if self.is_member(client_ip):
            data["my_roles"] = list(self.members[client_ip]["roles"])
        if self.is_owner(client_ip):
            data["members"] = {ip: list(entry["roles"]) for ip, entry in self.members.items()}
            data["codes"] = {code: entry["expires_at"].isoformat() for code, entry in self.codes.items()}
        return data
    # endregion info
