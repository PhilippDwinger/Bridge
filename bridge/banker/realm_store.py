import datetime
import secrets

from bridge.core import protocol
from bridge.security.generator import generate_key

# realm_id -> Realm (only realms that live on this server)
realm_storage = {}
# realm_id of this server's default public realm
public_realm_id = None
# Invitation codes are unique per server, so a client only needs the code (not the long realm address).
# code -> {"realm_id", "roles", "expires_at", "max_uses", "uses"}
realm_codes = {}

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

# region realms
def generate_realm_id():
    for _ in range(100):
        realm_id = generate_key(16)
        if realm_id not in realm_storage:
            return realm_id
    return None

def add_realm(realm):
    realm_storage[realm.realm_id] = realm

def get_realm(realm_id):
    return realm_storage.get(realm_id)

def remove_realm(realm_id):
    realm_storage.pop(realm_id, None)
    for code in [code for code, entry in realm_codes.items() if entry["realm_id"] == realm_id]:
        del realm_codes[code]

def set_public_realm_id(realm_id):
    global public_realm_id
    public_realm_id = realm_id
# endregion realms

# region codes
def normalize_code(code):
    """'abcd-2345' -> 'ABCD2345'. Returns None if it cannot be a code."""
    if not isinstance(code, str):
        return None
    code = code.strip().upper().replace("-", "").replace(" ", "")
    if len(code) != protocol.code_length or not code.isascii() or not code.isalnum():
        return None
    return code

def cleanup_codes():
    now = _now()
    for code in [code for code, entry in realm_codes.items()
                 if entry["expires_at"] <= now or (entry["max_uses"] is not None and entry["uses"] >= entry["max_uses"])]:
        del realm_codes[code]

def generate_code():
    cleanup_codes()
    for _ in range(100):
        code = "".join(secrets.choice(protocol.code_alphabet) for _ in range(protocol.code_length))
        if code not in realm_codes:
            return code
    return None

def add_code(code, realm_id, roles, expires_at, max_uses=None):
    realm_codes[code] = {
        "realm_id": realm_id,
        "roles": list(roles or []),
        "expires_at": expires_at,
        "max_uses": max_uses,
        "uses": 0,
    }

def get_code(code):
    cleanup_codes()
    code = normalize_code(code)
    return realm_codes.get(code) if code else None

def use_code(code, realm_id):
    """Counts one use and returns the roles, or None if the code is not valid for this realm."""
    code = normalize_code(code)
    entry = get_code(code)
    if entry is None or entry["realm_id"] != realm_id:
        return None
    entry["uses"] += 1
    roles = list(entry["roles"])
    cleanup_codes()
    return roles

def get_codes_of_realm(realm_id):
    cleanup_codes()
    return {code: entry for code, entry in realm_codes.items() if entry["realm_id"] == realm_id}
# endregion codes

def reset():
    global public_realm_id
    realm_storage.clear()
    realm_codes.clear()
    public_realm_id = None
