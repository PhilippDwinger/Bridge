from fastapi import HTTPException
from datetime import datetime, timedelta, timezone

from bridge import security
from bridge.messenger import sender
from bridge.messenger.mailbox import MailBox
from bridge.security.utils import generate_key, get_free_key_in_dict
from bridge.utils.time_calc import is_expired

# region Stores
realms = {}
clients = {}
session_tokens = {}
realm_codes = {}
# endregion

# region realm functions

# region Utils

def generate_realm_id():
    counter = 0
    while counter < len(realms) + 1:
        counter += 1
        realm_id = generate_key()
        if realm_id_exists(realm_id) is False:
            return realm_id
    raise HTTPException(status_code=500, detail="Could not generate realm id!")

def realm_id_exists(realm_id: str):
    if realm_id in realms:
        return True
    return False

# endregion

def get_realm_from_id(realm_id: str):
    if realm_id in realms:
        return realms[realm_id]
    raise HTTPException(status_code=404, detail="Realm not found!")

def add_realm(realm):
    realm_id = generate_realm_id()
    realms[realm_id] = realm
    return realm_id

# endregion

def register_new_client(client_name: str, password: str, bridge_url: str):
    client_key = generate_key()
    if not client_key:
        raise HTTPException(status_code=500, detail="Error while generating key!")

    client_mailbox = MailBox()
    if not client_mailbox:
        raise HTTPException(status_code=500, detail="Error while creating mailbox!")

    client_ip = sender.initialize_client_traffic(client_key, client_mailbox, bridge_url)

    hashed_password = security.hash_password(password)

    entry = {
        "client_name": client_name,
        "hashed_password": hashed_password,
        "client_key": client_key,
        "client_ip": client_ip,
        "client_mailbox": client_mailbox,
        "metadata": {
            "first_code_join_attempt" : None,
            "code_join_declines": None
        }
    }

    clients[client_key] = entry
    return client_key

def get_client_by_key(client_key: str):
    if client_key in clients:
        return clients[client_key]

    raise HTTPException(status_code=404, detail="Client not found!")

def generate_session_token(client_key: str):
    session_token = generate_key()
    expires_at_time = datetime.now(timezone.utc) + timedelta(hours=1)

    session_tokens[session_token] = {
        "client_key": client_key,
        "expires_at_time": expires_at_time
    }

    remaining_time = expires_at_time - datetime.now(timezone.utc)
    remaining_minutes = remaining_time.total_seconds() / 60

    return session_token, remaining_minutes

def validate_session_token(session_token: str):
    if session_token not in session_tokens:
        raise HTTPException(status_code=401, detail="Invalid session token!")

    entry = session_tokens[session_token]

    if is_expired(entry["expires_at_time"]):
        del session_tokens[session_token]
        raise HTTPException(status_code=401, detail="Session token expired!")

    return entry

def get_client_key_from_session_token(session_token: str):
    return validate_session_token(session_token)["client_key"]

def create_protected_realm_code(realm_id, realm_type, expires_at, preferred_code=None):
    if not realm_id or not realm_type:
        raise HTTPException(status_code=400, detail="Missing Arguments!")
    code = preferred_code
    if not code:
        code = get_free_key_in_dict(realm_codes)
    if is_expired(expires_at):
        raise HTTPException(status_code=400, detail="Expired Session!")
    realm_codes[code] = {
        "realm_id": realm_id,
        "realm_type": realm_type,
        "expires_at": expires_at,
    }
    return code

def create_private_realm_code(realm_id, realm_type, giving_roles, expires_at, preferred_code=None):
    if not realm_id or not realm_type or not giving_roles:
        raise HTTPException(status_code=400, detail="Missing Arguments!")
    code = preferred_code
    if not code:
        code = get_free_key_in_dict(realm_codes)
    if is_expired(expires_at):
        raise HTTPException(status_code=400, detail="Expired Session!")
    realm_codes[code] = {
        "realm_id": realm_id,
        "realm_type": realm_type,
        "giving_roles": giving_roles,
        "expires_at": expires_at,
    }
    return code

def get_realm_entry_from_code(code: str):
    if code not in realm_codes:
        raise HTTPException(status_code=404, detail="Realm not found!")
    return realm_codes[code]

def delete_realm_code(code: str):
    if code not in realm_codes:
        return False
    del realm_codes[code]
    return True