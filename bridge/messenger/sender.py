from fastapi import HTTPException

from bridge import security, banker
from bridge.messenger.mailbox import MailBox

ip_registry = {}
message_routes = {}

def send_to_client_ip(origin_client_ip, target_client_ip, content, content_type, register=False):
    if not ip_registry.get(target_client_ip):
        raise HTTPException(status_code=404, detail="Client_ip not found")
    client_entry : dict = ip_registry[target_client_ip]
    client_mailbox : MailBox = client_entry["client_mailbox"]
    message_id = None
    if register:
        message_id = security.get_free_key_in_dict(message_routes)
        if not message_id:
            raise HTTPException(status_code=500, detail="Error while generating message id!")
        message_routes[message_id] = {
            "origin_client_ip": origin_client_ip,
            "target_client_ip": target_client_ip,
            "content": content,
            "content_type": content_type,
        }
    message = {
        "content": content,
        "message_id": message_id,
        "origin_client_ip": origin_client_ip,
    }
    client_mailbox.create_message(
        message_id,
        origin_client_ip,
        content,
        content_type,
        register
    )
    return message_id

def delete_message(message_id, client_ip):
    route_entry = message_routes.get(message_id)
    if not route_entry:
        raise HTTPException(status_code=404, detail="Message id not found!")
    if not ip_registry.get(client_ip):
        raise HTTPException(status_code=404, detail="Client_ip not found")
    client_entry: dict = ip_registry[client_ip]
    client_mailbox: MailBox = client_entry["client_mailbox"]
    result = client_mailbox.delete_message(message_id)
    if not result:
        raise HTTPException(status_code=404, detail="Error while deleting message!")

def handle_respond(message_id, client_ip, target_client_ip, content):
    route_entry = message_routes.get(message_id)
    if not route_entry:
        raise HTTPException(status_code=404, detail="Message id not found!")
    if route_entry["origin_client_ip"] != target_client_ip or route_entry["target_client_ip"] != client_ip:
        raise HTTPException(status_code=404, detail="Ips not matching!")
    send_to_client_ip(
        client_ip,
        target_client_ip,
        content,
        "response",
    )
    delete_message(message_id, client_ip)

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