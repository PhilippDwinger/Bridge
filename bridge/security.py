import uuid
import hmac
import hashlib
import secrets
from argon2 import PasswordHasher

def generate_key_uuid4():
    return str(uuid.uuid4())

def generate_key():
    return secrets.token_hex(32)

password_hasher = PasswordHasher()

def hash_password(password):
    return password_hasher.hash(password)

def verify_password(password, password_hash):
    return password_hasher.verify(password_hash, password)

def generate_key_from_name_and_password(name, password):
    return hmac.new(
        str(password).encode(),
        str(name).encode(),
        hashlib.sha256
    ).hexdigest()

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