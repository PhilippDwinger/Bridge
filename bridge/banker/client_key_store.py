import datetime

from bridge.security.generator import get_free_key_in_dict

client_key_storage = {}

def generate_client_key(hashed_password):
    key = get_free_key_in_dict(client_key_storage)
    client_key_storage[key] = {
        "hashed_password": hashed_password,
    }
    return key

def reset():
    client_key_storage.clear()