import hashlib
import secrets

from bridge.errors.exceptions import Exceptions


def generate_key():
    return secrets.token_hex(32)

def get_free_key_in_dict(dictionary : dict, max_tries=100):
    counter = 0
    while counter < max_tries:
        counter += 1
        key = generate_key()
        if key not in dictionary:
            return key
    return None

def get_free_key_in_list(given_list : list, max_tries=100):
    counter = 0
    while counter < max_tries:
        counter += 1
        key = generate_key()
        if key not in given_list:
            return key
    return None

def generate_client_ip(bridge_url, used_ip_dict):
    random_key = get_free_key_in_dict(used_ip_dict)
    if not random_key:
        return Exceptions.FAILED
    return hashlib.sha256(f"{bridge_url}:{random_key}".encode()).hexdigest()