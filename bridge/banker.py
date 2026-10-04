from fastapi import HTTPException
from datetime import datetime, timedelta, timezone

from bridge import security
from bridge.messenger import sender
from bridge.messenger.mailbox import MailBox

# region Stores
realms = {}
clients = {}
session_tokens = {}
# endregion

# region realm functions

# region Utils

def generate_realm_id():
    counter = 0
    while counter < len(realms) + 1:
        counter += 1
        realm_id = security.generate_key()
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

def register_new_client(client_name: str, password: str):
    client_key = security.generate_key()
    if not client_key:
        raise HTTPException(status_code=500, detail="Error while generating key!")

    client_mailbox = MailBox()
    if not client_mailbox:
        raise HTTPException(status_code=500, detail="Error while creating mailbox!")

    client_ip = sender.initialize_client_traffic(client_key, client_mailbox)

    hashed_password = security.hash_password(password)

    entry = {
        "client_name": client_name,
        "hashed_password": hashed_password,
        "client_key": client_key,
        "client_ip": client_ip,
        "client_mailbox": client_mailbox
    }

    clients[client_key] = entry
    return client_key

def get_client_by_key(client_key: str):
    if client_key in clients:
        return clients[client_key]

    raise HTTPException(status_code=404, detail="Client not found!")

def generate_session_token(client_key: str):
    session_token = security.generate_key()

    session_tokens[session_token] = {
        "client_key": client_key,
        "expires_at_time": datetime.now(timezone.utc) + timedelta(hours=1)
    }

    return session_token

def validate_session_token(session_token: str):
    if session_token not in session_tokens:
        raise HTTPException(status_code=401, detail="Invalid session token!")

    entry = session_tokens[session_token]
    current_time = datetime.now(timezone.utc)

    if current_time >= entry["expires_at_time"]:
        del session_tokens[session_token]
        raise HTTPException(status_code=401, detail="Session token expired!")

    return entry

def get_client_key_from_session_token(session_token: str):
    return validate_session_token(session_token)["client_key"]