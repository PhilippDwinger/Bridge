import secrets


def generate_key(n_bytes: int = 32):
    # Random hex string with n_bytes of randomness (32 -> 64 hex characters)
    return secrets.token_hex(n_bytes)

def get_free_key_in_dict(dictionary : dict, max_tries=100, n_bytes: int = 32):
    counter = 0
    while counter < max_tries:
        counter += 1
        key = generate_key(n_bytes)
        if key not in dictionary:
            return key
    return None

def get_free_key_in_list(given_list : list, max_tries=100, n_bytes: int = 32):
    counter = 0
    while counter < max_tries:
        counter += 1
        key = generate_key(n_bytes)
        if key not in given_list:
            return key
    return None
