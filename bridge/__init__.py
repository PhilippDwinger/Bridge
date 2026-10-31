import datetime

from bridge import errors
from bridge.errors import Exceptions
from bridge.errors.exceptions import is_exception
from bridge.core import address, protocol
from bridge.banker import client_key_store, ip_store, mailbox_store, realm_store, session_store, task_store, trust_store
from bridge.security import authorizer
from bridge.security.hasher import hash_password, verify_password
from bridge.server import runtime, s2s_client, url_env
from bridge.server.connection_modes import ConnectionMode
from bridge.server.server import start_server
from bridge.realm import service as realm_service
from bridge.core import backup, clients
from bridge.banker import backup_store, status_store


def verify_bridge_password(password, bridge_password_hash):
    if not bridge_password_hash or not isinstance(bridge_password_hash, str):
        errors.handle_error(Exceptions.BRIDGE_PASSWORD_MISSING, "The Bridge has no password")
        return False
    if not verify_password(password, bridge_password_hash):
        errors.handle_error(Exceptions.NOT_ALLOWED, "Wrong Bridge password")
        return False
    return True


def _default_public_url(host, port):
    if host in ("0.0.0.0", "::", ""):
        host = "localhost"
    return f"http://{host}:{port}"


class Bridge:
    """One Bridge server. Everything lives in RAM - when the server stops, all data is gone.

    password   - controls the server (admin functions and /admin endpoints). Always required.
    public_url - URL under which clients and other Bridge servers reach this server. It is part of every
                 client IP and realm address, so set it to the real address (e.g. "https://bridge.example.com").
    """
    _instance = None

    def __new__(cls, host: str, port: int, password: str, public_url: str | None = None):
        if cls._instance is not None:
            raise RuntimeError("Bridge can only be instantiated once")

        if not isinstance(host, str) or not host:
            raise ValueError("Host must be a non-empty string")

        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("Port must be an integer between 1 and 65535")

        if not isinstance(password, str) or not password:
            raise ValueError("A Bridge server always needs a password")

        if public_url is not None and address.normalize_url(public_url) is None:
            raise ValueError("public_url must be a http(s) URL like 'https://bridge.example.com'")

        instance = super().__new__(cls)
        cls._instance = instance
        return instance

    def __init__(self, host: str, port: int, password: str, public_url: str | None = None):
        self.host = host
        self.port = port
        if public_url is None:
            public_url = _default_public_url(host, port)
            errors.debug_print(f"No public_url given, using {public_url} - set it if other servers should reach this one")
        self.public_url = address.normalize_url(public_url)
        url_env.set_base_root(self.public_url)
        self._metadata = {
            "initialization_time": datetime.datetime.now(datetime.timezone.utc),
        }
        self.password = hash_password(password)
        backup.set_password(password, self.public_url)
        realm_service.create_default_public_realm()

    def __str__(self) -> str:
        return str({"host": self.host, "port": self.port, "public_url": self.public_url})
    def __repr__(self) -> str:
        return self.__str__()

    # region password
    def verify_password(self, password) -> bool:
        return verify_bridge_password(password, self.password)

    def _set_password(self, new_password):
        hashed_password = hash_password(new_password)
        if hashed_password is None:
            return Exceptions.ARGUMENT_ERROR
        self.password = hashed_password
        backup.set_password(new_password, self.public_url)
        return True

    def change_password(self, password, new_password):
        if not self.verify_password(password):
            return Exceptions.NOT_ALLOWED
        return self._set_password(new_password)
    # endregion password

    # region trusted servers
    # Public methods need the Bridge password. The _methods are used by the /admin routes after they
    # checked the password themselves.
    def _add_trusted_server(self, url):
        server_url = address.normalize_url(url)
        if server_url is None:
            errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Invalid server URL: {url!r}")
            return Exceptions.ARGUMENT_ERROR
        if server_url == self.public_url:
            errors.handle_error(Exceptions.ARGUMENT_ERROR, "A server cannot trust itself")
            return Exceptions.ARGUMENT_ERROR
        result = trust_store.add_server(server_url)
        if is_exception(result):
            return result
        # Connects right away if the server is running, otherwise when it starts
        runtime.schedule(s2s_client.handshake(server_url))
        return server_url

    def _remove_trusted_server(self, url):
        server_url = address.normalize_url(url)
        if server_url is None:
            errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Invalid server URL: {url!r}")
            return Exceptions.ARGUMENT_ERROR
        return trust_store.remove_server(server_url)

    async def _connect_trusted_server(self, url):
        server_url = address.normalize_url(url)
        if server_url is None or not trust_store.is_trusted(server_url):
            errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"{url!r} is not in the trusted list")
            return Exceptions.SERVER_NOT_TRUSTED
        return await s2s_client.handshake(server_url)

    def _get_trusted_servers(self):
        return trust_store.list_servers()

    def add_trusted_server(self, password, url):
        if not self.verify_password(password):
            return Exceptions.NOT_ALLOWED
        return self._add_trusted_server(url)

    def remove_trusted_server(self, password, url):
        if not self.verify_password(password):
            return Exceptions.NOT_ALLOWED
        return self._remove_trusted_server(url)

    def get_trusted_servers(self, password):
        if not self.verify_password(password):
            return Exceptions.NOT_ALLOWED
        return self._get_trusted_servers()
    # endregion trusted servers

    # region control
    def _reset(self):
        # Removes all clients, sessions, messages and realms. Trusted servers stay.
        session_store.reset()
        mailbox_store.reset()
        ip_store.reset()
        client_key_store.reset()
        realm_store.reset()
        task_store.reset()
        status_store.reset()
        authorizer.reset()
        realm_service.create_default_public_realm()
        errors.debug_print("Bridge was reset")
        return True

    def reset(self, password):
        if not self.verify_password(password):
            return Exceptions.NOT_ALLOWED
        return self._reset()

    # Old name from Bridge 3 rework part 1
    restart_bridge = reset

    def _get_status(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        return {
            "url": self.public_url,
            "protocol_version": protocol.current_protocol.version,
            "started_at": self._metadata["initialization_time"].isoformat(),
            "uptime_seconds": int((now - self._metadata["initialization_time"]).total_seconds()),
            "clients": len(client_key_store.client_key_storage),
            "sessions": len(session_store.session_storage),
            "max_clients": protocol.max_clients,
            "realms": len(realm_store.realm_storage),
            "open_tasks": len(task_store.incoming_tasks),
            "public_realm_address": realm_service.get_public_realm_address(),
            "trusted_servers": trust_store.list_servers(),
            "settings": self._get_settings(),
            "backup": {key: value for key, value in backup.status().items() if key != "stored_for_other_servers"},
            "stored_backups": len(backup_store.stored_backups),
            "errors": {error.name: entry["amount"] for error, entry in errors.tracker.get_errors().items()},
        }

    # region settings
    SETTINGS = {
        "relay_mode": ("off", "trusted"),
        "accept_relayed": (True, False),
        "backup_mode": ("peers", "off"),
    }

    def _get_settings(self):
        return {name: getattr(protocol, name) for name in self.SETTINGS}

    def _set_settings(self, **changes):
        for name, value in changes.items():
            if value is None:
                continue
            if name not in self.SETTINGS or value not in self.SETTINGS[name]:
                errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Invalid setting {name}={value!r}")
                return Exceptions.ARGUMENT_ERROR
        for name, value in changes.items():
            if value is not None:
                setattr(protocol, name, value)
        return self._get_settings()

    def set_settings(self, password, **changes):
        if not self.verify_password(password):
            return Exceptions.NOT_ALLOWED
        return self._set_settings(**changes)
    # endregion settings

    def get_status(self, password):
        if not self.verify_password(password):
            return Exceptions.NOT_ALLOWED
        return self._get_status()

    def _get_clients(self):
        result = []
        for client_key, entry in client_key_store.client_key_storage.items():
            mailbox = mailbox_store.get_mailbox(client_key)
            result.append({
                "client_ip": entry.get("client_ip"),
                "name": entry.get("name"),
                "realms": list(entry.get("realms", [])),
                "created_at": entry["created_at"].isoformat(),
                "last_signal": entry["last_signal"].isoformat(),
                "waiting_messages": sum(len(pool) for pool in mailbox.snapshot(0)["pools"].values()) if mailbox else 0,
            })
        return result

    def _get_mailbox_view(self, client_ip):
        client_key = ip_store.get_client_key(client_ip)
        mailbox = mailbox_store.get_mailbox(client_key) if client_key else None
        if mailbox is None:
            errors.handle_error(Exceptions.CLIENT_NOT_FOUND, "No client with this IP on this server")
            return Exceptions.CLIENT_NOT_FOUND
        return mailbox.snapshot()

    def get_clients(self, password):
        if not self.verify_password(password):
            return Exceptions.NOT_ALLOWED
        return self._get_clients()

    def get_mailbox_view(self, password, client_ip):
        if not self.verify_password(password):
            return Exceptions.NOT_ALLOWED
        return self._get_mailbox_view(client_ip)

    def get_all_storages(self, password):
        # Raw view of everything in RAM (debugging only - contains password hashes)
        if not self.verify_password(password):
            return None
        return {
            "ip_storage": ip_store.ip_storage,
            "client_key_storage": client_key_store.client_key_storage,
            "session_storage": session_store.session_storage,
            "mailbox_storage": mailbox_store.mailbox_storage,
            "realm_storage": realm_store.realm_storage,
            "realm_codes": realm_store.realm_codes,
            "outgoing_tasks": task_store.outgoing_tasks,
            "incoming_tasks": task_store.incoming_tasks,
            "trusted_servers": trust_store.list_servers(),
        }
    # endregion control

    # region clients (Python API)
    def register_client(self, name, password):
        """Registers a client directly in Python. Returns its client IP."""
        return clients.register_client(name, password)
    # endregion clients

    def start_server(self, connection_mode: ConnectionMode = ConnectionMode.UNSAFE,
                     ssl_keyfile="localhost+2-key.pem", ssl_certfile="localhost+2.pem") -> None:
        start_server(self, self.host, self.port, connection_mode, ssl_keyfile, ssl_certfile)
