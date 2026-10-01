from fastapi import HTTPException
from datetime import datetime, timedelta, timezone

from bridge import security
from bridge.messenger.mailbox import MailBox

realms = {}
clients = {}
session_tokens = {}
used_client_ips = []

def register_new_client(client_name: str, password: str):
    client_key = security.generate_key()
    if not client_key:
        raise HTTPException(status_code=500, detail="Error while generating key!")

    client_ip = security.get_free_key_in_list(used_client_ips, len(used_client_ips) + 1)
    if not client_ip:
        raise HTTPException(status_code=500, detail="Error while generating ip!")
    used_client_ips.append(client_ip)

    client_mailbox = MailBox()
    if not client_mailbox:
        raise HTTPException(status_code=500, detail="Error while creating mailbox!")

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