import hashlib

from argon2 import PasswordHasher

from bridge import errors

password_hasher = PasswordHasher()

def hash_password(password : str):
    if not isinstance(password, str):
        pass
    return password_hasher.hash(password)

def verify_password(password : str, hashed_password : str):
    try:
        password_hasher.verify(hashed_password, password)
    except Exception as e:
        errors.debug_print(f"Password verification failed: {e}")
        return False
    return True

def merge_hash_strings(string1, string2):
    return hashlib.sha256(f"{string1}:{string2}".encode()).hexdigest()