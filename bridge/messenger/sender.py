from fastapi import HTTPException

from bridge import security, banker
from bridge.messenger.mailbox import MailBox

ip_registry = {}
message_routes = {}

def send_to_client_ip():
    pass

def delete_message():
    pass

def handle_respond():
    pass

def acknowledge_message():
    pass

def initialize_client_traffic(client_key, client_mailbox):
    client_ip = security.get_free_key_in_dict(ip_registry)
    if not client_ip:
        raise HTTPException(status_code=500, detail="Error while generating ip!")
    ip_registry[client_ip] = {
        "client_key": client_key,
        "client_mailbox": client_mailbox,
        "client_ip": client_ip
    }

def get_client_ip(client_key):
    for _, client_ip_entry in ip_registry.items():
        if client_key == client_ip_entry["client_key"]:
            return client_ip_entry["client_ip"]
    raise HTTPException(status_code=404, detail="Didn't find client ip!")

def get_client_mailbox_from_client_key(client_key):
    client_ip = get_client_ip(client_key)
    if not ip_registry.get(client_ip):
        raise HTTPException(status_code=404, detail="Client_ip not found")
    client_mailbox : MailBox = ip_registry[client_ip]["client_mailbox"]
    return client_mailbox