import uuid
import hmac
import hashlib
import secrets
from fastapi import HTTPException

from argon2 import PasswordHasher

from bridge import banker
from bridge.security.utils import get_free_key_in_dict

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

def resolve_client_key(session_token: str):
    client_key = banker.get_client_key_from_session_token(session_token)
    if not client_key:
        raise HTTPException(status_code=404, detail="Session token not found")
    return client_key

def authenticate_session(session_token: str):
    resolve_client_key(session_token)
    return True

def generate_client_ip(bridge_url, used_ip_dict):
    random_key = get_free_key_in_dict(used_ip_dict)
    if not random_key:
        raise HTTPException(status_code=404, detail="Session token not found")
    return hashlib.sha256(f"{bridge_url}:{random_key}".encode()).hexdigest()