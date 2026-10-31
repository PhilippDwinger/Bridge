import hashlib
import hmac

from argon2 import PasswordHasher

from bridge import errors
from bridge.errors.exceptions import Exceptions

password_hasher = PasswordHasher()

def hash_password(password : str):
    if not isinstance(password, str) or not password:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "Password must be a non-empty string")
        return None
    return password_hasher.hash(password)

def verify_password(password : str, hashed_password : str):
    if not isinstance(password, str) or not isinstance(hashed_password, str):
        return False
    try:
        password_hasher.verify(hashed_password, password)
    except Exception as e:
        errors.debug_print(f"Password verification failed: {e}")
        return False
    return True

def merge_hash_strings(string1, string2):
    return hashlib.sha256(f"{string1}:{string2}".encode()).hexdigest()

def sha256_hex(text : str) -> str:
    # Hash used to check that a message arrived complete: SHA-256 over the UTF-8 bytes, as hex
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def secrets_equal(value1, value2) -> bool:
    # Constant time comparison, so attackers cannot guess secrets by measuring response times
    if not isinstance(value1, str) or not isinstance(value2, str):
        return False
    return hmac.compare_digest(value1.encode("utf-8"), value2.encode("utf-8"))
