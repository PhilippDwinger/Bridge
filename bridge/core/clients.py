from bridge import errors
from bridge.banker import ip_store
from bridge.banker.client_key_store import generate_client_key
from bridge.errors import Exceptions
from bridge.security import generator
from bridge.security.authorizer import verify_http_call_arg
from bridge.security.hasher import hash_password

class Client:
    def __init__(self, bridge_url, preferred_password, name="Unnamed Client", http_call=False):
        # region http_call_arg check!
        http_call = verify_http_call_arg(http_call)
        if http_call is None:
            errors.handle_error(Exceptions.FOLLOWING_ERROR, f"HTTP call argument not provided")
            return
        # endregion http_call_arg check!
        # region name
        if not name or not isinstance(name, str):
            errors.handle_error(Exceptions.ARGUMENT_ERROR)
            name = "Unnamed Client"
        self.name = name
        # endregion name
        # region password
        self.password = hash_password(generator.generate_key())
        if preferred_password is not None:
            hashed_password = hash_password(preferred_password)
            if hashed_password:
                self.password = hashed_password
            else:
                errors.handle_error(Exceptions.FOLLOWING_ERROR, f"Password not provided")
                return
        # endregion password
        client_key = generate_client_key(self.password)
        client_ip = ip_store.get_free_ip(bridge_url, client_key)

    def __str__(self) -> str:
        return str(self.__dict__)
    def __repr__(self) -> str:
        return str(self.__dict__)

    def set_password(self, password):
        self.password = password