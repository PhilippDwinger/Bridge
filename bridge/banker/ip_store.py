from bridge import errors
from bridge.core import address
from bridge.errors.exceptions import Exceptions
from bridge.security.generator import generate_key
from bridge.server import url_env

# client_ip -> client_key
ip_storage = {}

def get_free_ip(client_key, local_id=None):
    """A new client IP. With local_id (stable identity) the IP is always the same for the same identity."""
    bridge_url = url_env.base_root
    if not bridge_url:
        errors.handle_error(Exceptions.BRIDGE_URL_MISSING, "Cannot create a client IP without the server URL")
        return Exceptions.BRIDGE_URL_MISSING
    if local_id is not None:
        client_ip = address.make_address(bridge_url, local_id)
        if client_ip in ip_storage:
            errors.handle_error(Exceptions.ALREADY_EXISTS, "This identity is already registered - log in instead")
            return Exceptions.ALREADY_EXISTS
        ip_storage[client_ip] = client_key
        return client_ip
    for _ in range(100):
        client_ip = address.make_address(bridge_url, generate_key(16))
        if client_ip not in ip_storage:
            ip_storage[client_ip] = client_key
            return client_ip
    errors.handle_error(Exceptions.FAILED, "No free client IP could be generated")
    return Exceptions.FAILED

def get_client_key(client_ip):
    if not isinstance(client_ip, str):
        return None
    return ip_storage.get(client_ip)

def remove_ip(client_ip):
    ip_storage.pop(client_ip, None)

def is_valid_ip(client_ip):
    return client_ip in ip_storage

def reset():
    ip_storage.clear()
