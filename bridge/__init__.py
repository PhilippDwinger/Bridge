import datetime

from bridge import errors
from bridge.banker import ip_store
from bridge.banker import client_key_store
from bridge.errors import Exceptions
from bridge.security.hasher import hash_password, verify_password
from bridge.server.connection_modes import ConnectionMode
from bridge.server.server import start_server

def verify_bridge_password(password, bridge_password_hash):
    bridge_password = bridge_password_hash
    if bridge_password and isinstance(bridge_password, str):
        if not verify_password(password, bridge_password):
            errors.handle_error(Exceptions.FOLLOWING_ERROR, "Password is not correct!")
            return False
    else:
        errors.handle_error(Exceptions.BRIDGE_PASSWORD_MISSING, "Password is missing!")
        return False
    return True

class Bridge:
    _instance = None
    def __new__(cls, host: str, port: int, password: str | None= None):
        if cls._instance is not None:
            raise RuntimeError("Bridge can only be instantiated once")

        if not isinstance(host, str) or not host:
            raise ValueError("Host must be a non-empty string")

        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("Port must be an integer between 1 and 65535")

        instance = super().__new__(cls)
        cls._instance = instance
        return instance
    def __init__(self, host: str, port: int, password: str | None= None):
        self.host = host
        self.port = port
        self._metadata = {
            "initialization_time": datetime.datetime.now(),
        }
        # region bridge password
        self.password = False
        if password and isinstance(password, str):
            hashed_password = hash_password(password)
            if not hashed_password:
                errors.handle_error(Exceptions.FOLLOWING_ERROR, "Password not hashed")
            else:
                self.password = hashed_password
        # endregion bridge password

    def __str__(self) -> str:
        return str(self.__dict__)
    def __repr__(self) -> str:
        return str(self.__dict__)
    def first_set_password(self, password):
        if password and isinstance(password, str) and self.password is False:
            hashed_password = hash_password(password)
            self.password = hashed_password
            errors.debug_print("Bridge first password is set!")

    def restart_bridge(self, password):
        if not verify_bridge_password(password, self.password):
            return
        ip_store.reset()
        client_key_store.reset()

    def start_server(self, connection_mode: ConnectionMode) -> None:
        host = self.host
        port = self.port

        start_server(host, port, connection_mode)

    def get_all_storages(self, password):
        if not self.password:
            errors.handle_error(Exceptions.BRIDGE_PASSWORD_MISSING, "Password is missing!")
            return None
        if not verify_bridge_password(password, self.password):
            return None
        return {
            "ip_storage": ip_store.ip_storage,
            "client_key_storage": client_key_store.client_key_storage,
        }
