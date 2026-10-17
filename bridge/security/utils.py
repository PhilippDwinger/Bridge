import secrets
import uuid

def generate_key_uuid4():
    return str(uuid.uuid4())

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