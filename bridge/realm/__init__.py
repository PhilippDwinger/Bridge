import datetime
import json
from enum import StrEnum

from bridge import errors
from bridge.banker import realm_store
from bridge.core import address, protocol
from bridge.errors.exceptions import Exceptions
from bridge.server import url_env
from bridge.subservices import bridge_express as express

# Members are identified by their client IP (not the client key), because members can live on other servers.

MAX_NAME_LENGTH = 64
MAX_KEY_LENGTH = 128
MAX_CODE_MINUTES = 60 * 24 * 30
MAX_CODE_USES = 100_000
MAX_DESCRIPTION_LENGTH = 300


class RealmType(StrEnum):
    PUBLIC = "public"
    PROTECTED = "protected"
    PRIVATE = "private"


def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def _valid_name(value, field_name, max_length=MAX_NAME_LENGTH):
    if isinstance(value, str) and value.strip() and len(value) <= max_length and _encodable(value):
        return True
    errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'{field_name}' must be a non-empty string with up to {max_length} characters")
    return False

def _encodable(value):
    # Broken unicode (lone surrogates) would break every answer that contains the name
    try:
        value.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False

def _valid_minutes(value):
    # At least one minute: codes that expire in milliseconds could be used to test which codes exist
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 1 <= value <= MAX_CODE_MINUTES:
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
        # Goes up with every change - other servers compare it to keep their copy up to date (realm/sync.py)
        self.version = 1
        # client_ip -> {"roles": [role names], "joined_at": datetime}
        self.members = {}
        # command_name -> {host_ip: {"allowed_roles": [role names], "description": str}}
        self.commands = {}
        # command_name -> signature (BridgeExpress) - the same for all hosts of a command
        self.signatures = {}
        # topic -> [subscriber client IPs]
        self.topics = {}
        # Invitation codes are stored per server in realm_store.realm_codes
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
        # Hosted commands and topic subscriptions of a member that left are removed as well
        for command_name in list(self.commands):
            self.commands[command_name].pop(client_ip, None)
            if not self.commands[command_name]:
                del self.commands[command_name]
                self.signatures.pop(command_name, None)
        for topic in list(self.topics):
            if client_ip in self.topics[topic]:
                self.topics[topic].remove(client_ip)
            if not self.topics[topic]:
                del self.topics[topic]

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
        # Who may host can change with the owner (protected: restricted_to_owner)
        self.prune_hosts()
        return True

    def prune_hosts(self):
        """Removes hosted commands of clients that may not host anymore (role taken away, owner changed)."""
        for command_name in list(self.commands):
            hosts = self.commands[command_name]
            for host_ip in [ip for ip in hosts if not self.can_host(ip)]:
                del hosts[host_ip]
            if not hosts:
                del self.commands[command_name]
                self.signatures.pop(command_name, None)
    # endregion membership

    # region codes
    def _take_code(self, code):
        """Uses an invitation code of this realm and returns its roles (None if the code is not valid)."""
        return realm_store.use_code(code, self.realm_id)

    def _validate_roles(self, roles):
        # Overwritten by PrivateRealm. Other realms have no roles.
        if roles:
            errors.handle_error(Exceptions.ARGUMENT_ERROR, f"{self.realm_type} realms have no roles")
            return False
        return True

    def create_code(self, client_ip, expires_in_minutes=None, roles=None, preferred_code=None, max_uses=None):
        """Creates an 8 character invitation code (unique on this server, easy to type, e.g. 'K7M3XQ9P')."""
        if not self.is_owner(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "Only the owner can create invitation codes")
            return Exceptions.NOT_ALLOWED
        if len(realm_store.get_codes_of_realm(self.realm_id)) >= protocol.max_codes_per_realm:
            errors.handle_error(Exceptions.NOT_ALLOWED, f"The realm has {protocol.max_codes_per_realm} codes already")
            errors.set_client_details(problems=[f"a realm can have at most {protocol.max_codes_per_realm} open invitation codes"])
            return Exceptions.NOT_ALLOWED
        if expires_in_minutes is None:
            expires_in_minutes = protocol.default_code_minutes
        if not _valid_minutes(expires_in_minutes) or not self._validate_roles(roles):
            return Exceptions.ARGUMENT_ERROR
        if max_uses is not None and (isinstance(max_uses, bool) or not isinstance(max_uses, int) or not 0 < max_uses <= MAX_CODE_USES):
            errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'max_uses' must be a whole number between 1 and {MAX_CODE_USES}")
            return Exceptions.ARGUMENT_ERROR
        if preferred_code is not None:
            code = realm_store.normalize_code(preferred_code)
            if code is None:
                errors.handle_error(
                    Exceptions.ARGUMENT_ERROR,
                    f"'preferred_code' must be {protocol.code_length} letters/digits (A-Z, 0-9)"
                )
                return Exceptions.ARGUMENT_ERROR
            if realm_store.get_code(code) is not None:
                errors.handle_error(Exceptions.ALREADY_EXISTS, "This code is already in use on this server")
                return Exceptions.ALREADY_EXISTS
        else:
            code = realm_store.generate_code()
            if code is None:
                errors.handle_error(Exceptions.FAILED, "No free invitation code could be generated")
                return Exceptions.FAILED
        expires_at = _now() + datetime.timedelta(minutes=expires_in_minutes)
        realm_store.add_code(code, self.realm_id, roles, expires_at, max_uses)
        return code
    # endregion codes

    # region commands
    def can_see_commands(self, client_ip):
        return self.is_member(client_ip)

    def can_host(self, client_ip):
        return self.is_member(client_ip)

    def can_call(self, client_ip, host_entry):
        return self.is_member(client_ip)

    def create_command(self, client_ip, command_name, allowed_roles=None, description=None, signature=None):
        if not _valid_name(command_name, "command_name", 128):
            return Exceptions.ARGUMENT_ERROR
        if signature is not None:
            size = len(json.dumps(signature, ensure_ascii=False))
            if size > protocol.max_signature_kib * 1024:
                errors.handle_error(Exceptions.ARGUMENT_ERROR, "Signature too big")
                errors.set_client_details(problems=[f"a signature can have up to {protocol.max_signature_kib} KiB"])
                return Exceptions.ARGUMENT_ERROR
            signature, problems = express.normalize_signature(signature)
            if problems:
                errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Invalid signature: {problems}")
                errors.set_client_details(problems=problems)
                return Exceptions.ARGUMENT_ERROR
        if description is not None and (not isinstance(description, str) or len(description) > MAX_DESCRIPTION_LENGTH):
            errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'description' must be a text with up to {MAX_DESCRIPTION_LENGTH} characters")
            return Exceptions.ARGUMENT_ERROR
        if not self.can_host(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, f"Client may not host commands in this {self.realm_type} realm")
            return Exceptions.NOT_ALLOWED
        if allowed_roles is not None and not isinstance(allowed_roles, list):
            errors.handle_error(Exceptions.ARGUMENT_ERROR, "'allowed_roles' must be a list")
            return Exceptions.ARGUMENT_ERROR
        if not self._validate_roles(allowed_roles):
            return Exceptions.ARGUMENT_ERROR
        hosts = self.commands.get(command_name) or {}
        if client_ip in hosts:
            errors.handle_error(Exceptions.ALREADY_EXISTS, f"Client already hosts '{command_name}'")
            return Exceptions.ALREADY_EXISTS
        if not hosts and len(self.commands) >= protocol.max_commands_per_realm:
            errors.handle_error(Exceptions.NOT_ALLOWED, "Too many commands in this realm")
            errors.set_client_details(problems=[f"a realm can have at most {protocol.max_commands_per_realm} commands"])
            return Exceptions.NOT_ALLOWED
        if sum(1 for other in self.commands.values() if client_ip in other) >= protocol.max_commands_per_host_per_realm:
            errors.handle_error(Exceptions.NOT_ALLOWED, "Client hosts too many commands in this realm")
            errors.set_client_details(problems=[f"a client can host at most {protocol.max_commands_per_host_per_realm} commands per realm"])
            return Exceptions.NOT_ALLOWED
        if hosts and signature is not None and not express.same_shape(signature, self.signatures.get(command_name)):
            # All hosts of a command have the same signature. Without one, a new host takes the existing one.
            errors.handle_error(Exceptions.SIGNATURE_MISMATCH, f"'{command_name}' is hosted with another signature")
            return Exceptions.SIGNATURE_MISMATCH
        if not hosts and signature is not None:
            self.signatures[command_name] = signature
        self.commands.setdefault(command_name, {})[client_ip] = {"allowed_roles": list(allowed_roles or []),
                                                                  "description": description or ""}
        return True

    def remove_command(self, client_ip, command_name):
        hosts = self.commands.get(command_name)
        if not hosts or client_ip not in hosts:
            errors.handle_error(Exceptions.COMMAND_NOT_FOUND, f"Client does not host '{command_name}'")
            return Exceptions.COMMAND_NOT_FOUND
        del hosts[client_ip]
        if not hosts:
            del self.commands[command_name]
            self.signatures.pop(command_name, None)
        return True

    def resolve_hosts(self, client_ip, command_name):
        """All hosts of the command the caller is allowed to use (can be an empty list)."""
        if not self.can_see_commands(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "Client is not a member of the realm")
            return Exceptions.NOT_ALLOWED
        hosts = self.commands.get(command_name) or {}
        return [host_ip for host_ip, host_entry in hosts.items()
                if self.can_host(host_ip) and self.can_call(client_ip, host_entry)]

    def resolve_call(self, client_ip, command_name):
        """Hosts the caller may use + the signature of the command (to check the arguments before sending)."""
        hosts = self.resolve_hosts(client_ip, command_name)
        if not isinstance(hosts, list):
            return hosts
        return {"hosts": hosts, "signature": self.signatures.get(command_name)}

    def list_commands(self, client_ip):
        """Command catalog: every command the caller may use, with number of hosts and descriptions."""
        if not self.can_see_commands(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "Client is not a member of the realm")
            return Exceptions.NOT_ALLOWED
        catalog = {}
        for command_name, hosts in self.commands.items():
            usable = [entry for host_ip, entry in hosts.items() if self.can_host(host_ip) and self.can_call(client_ip, entry)]
            if usable:
                catalog[command_name] = {
                    "hosts": len(usable),
                    "descriptions": sorted({entry.get("description", "") for entry in usable} - {""}),
                    "signature": self.signatures.get(command_name),
                }
        return catalog
    # endregion commands

    # region topics
    # Publish/subscribe: an event published to a topic goes to every subscriber as "event" message.
    # Subscribers fetch events like every other message (poll) - Bridge does not push.
    def can_publish(self, client_ip):
        return self.can_host(client_ip)

    def subscribe(self, client_ip, topic):
        if not _valid_name(topic, "topic", 128):
            return Exceptions.ARGUMENT_ERROR
        if not self.can_see_commands(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, "Client is not a member of the realm")
            return Exceptions.NOT_ALLOWED
        if topic not in self.topics and len(self.topics) >= protocol.max_topics_per_realm:
            errors.handle_error(Exceptions.NOT_ALLOWED, f"The realm has {protocol.max_topics_per_realm} topics already")
            return Exceptions.NOT_ALLOWED
        subscribers = self.topics.setdefault(topic, [])
        if client_ip not in subscribers:
            if len(subscribers) >= protocol.max_topic_subscribers:
                errors.handle_error(Exceptions.NOT_ALLOWED, f"Topic has {protocol.max_topic_subscribers} subscribers already")
                return Exceptions.NOT_ALLOWED
            subscribers.append(client_ip)
        if self.realm_type == RealmType.PUBLIC:
            self.add_member(client_ip)
        return True

    def unsubscribe(self, client_ip, topic):
        subscribers = self.topics.get(topic) or []
        if client_ip not in subscribers:
            errors.handle_error(Exceptions.KEY_ERROR, "Client is not subscribed to this topic")
            return Exceptions.KEY_ERROR
        subscribers.remove(client_ip)
        if not subscribers:
            del self.topics[topic]
        return True

    def resolve_subscribers(self, client_ip, topic):
        """Subscribers of a topic, if the caller may publish to it."""
        if not _valid_name(topic, "topic", 128):
            return Exceptions.ARGUMENT_ERROR
        if not self.can_publish(client_ip):
            errors.handle_error(Exceptions.NOT_ALLOWED, f"Client may not publish in this {self.realm_type} realm")
            return Exceptions.NOT_ALLOWED
        return list(self.topics.get(topic) or [])

    def verify_event(self, client_ip, topic, subscriber_ip):
        """For the server of a subscriber: may client_ip publish here, and is subscriber_ip subscribed?"""
        if not self.can_publish(client_ip):
            return False
        return subscriber_ip in (self.topics.get(topic) or [])
    # endregion topics

    # region backup
    def to_state(self):
        """Everything of the realm as JSON-ready data (for the encrypted backup)."""
        return {
            "realm_type": str(self.realm_type),
            "realm_id": self.realm_id,
            "name": self.name,
            "owner_ip": self.owner_ip,
            "created_at": self.created_at.isoformat(),
            "version": self.version,
            "members": {
                ip: {"roles": list(entry["roles"]), "joined_at": entry["joined_at"].isoformat()}
                for ip, entry in self.members.items()
            },
            "commands": {name: {ip: dict(entry) for ip, entry in hosts.items()} for name, hosts in self.commands.items()},
            "signatures": dict(self.signatures),
            "topics": {topic: list(subscribers) for topic, subscribers in self.topics.items()},
            "extra": self._extra_state(),
        }

    def _extra_state(self):
        return {}

    def _load_extra_state(self, extra):
        pass

    def load_state(self, state):
        self.created_at = datetime.datetime.fromisoformat(state["created_at"])
        self.version = int(state.get("version", 1))
        self.members = {
            ip: {"roles": list(entry["roles"]), "joined_at": datetime.datetime.fromisoformat(entry["joined_at"])}
            for ip, entry in state["members"].items()
        }
        self.commands = {name: {ip: dict(entry) for ip, entry in hosts.items()} for name, hosts in state["commands"].items()}
        self.signatures = dict(state.get("signatures") or {})
        self.topics = {topic: list(subscribers) for topic, subscribers in state.get("topics", {}).items()}
        self._load_extra_state(state.get("extra") or {})
    # endregion backup

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
            "topics": {topic: len(subscribers) for topic, subscribers in self.topics.items()},
            "my_topics": [topic for topic, subscribers in self.topics.items() if client_ip in subscribers],
            "created_at": self.created_at.isoformat(),
            "version": self.version,
        }
        if self.is_member(client_ip):
            data["my_roles"] = list(self.members[client_ip]["roles"])
        if self.is_owner(client_ip):
            data["members"] = {ip: list(entry["roles"]) for ip, entry in self.members.items()}
            data["codes"] = {
                code: {
                    "expires_at": entry["expires_at"].isoformat(),
                    "roles": list(entry["roles"]),
                    "uses": entry["uses"],
                    "max_uses": entry["max_uses"],
                }
                for code, entry in realm_store.get_codes_of_realm(self.realm_id).items()
            }
        return data
    # endregion info
