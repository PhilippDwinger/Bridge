from fastapi import HTTPException

from bridge import security, banker
from bridge.messenger.mailbox import MailBox
from bridge.transfer.transfer import Message, is_message_expired

ip_registry = {}

def send_message(message: Message):
    expired_check_message(message)
    if message.traffic_type == "relayed":
        send_message_relayed(message)
    elif message.traffic_type == "direct":
        send_message_direct(message)
    else:
        raise HTTPException(status_code=400, detail="Unknown traffic type!")

def send_message_direct(message: Message):
    expired_check_message(message)
    if message.traffic_type != "direct":
        raise HTTPException(status_code=400, detail="Not valid traffic type!")
    recipient_mailbox : MailBox = get_client_mailbox_from_client_ip(message.recipient_ip)
    if not recipient_mailbox:
        raise HTTPException(status_code=400, detail="Client_ip not found!")
    recipient_mailbox.add_message(message)

def send_message_relayed(message: Message):
    expired_check_message(message)
    if message.traffic_type != "relayed":
        raise HTTPException(status_code=400, detail="Not valid traffic type!")
    expired_check_message(message)
    if message.traffic_type != "direct":
        raise HTTPException(status_code=400, detail="Not valid traffic type!")
    recipient_mailbox: MailBox = get_client_mailbox_from_client_ip(message.recipient_ip)
    if recipient_mailbox:
        send_message_direct(message)
    ## Search all Bridge Apps known for ip!

def expired_check_message(message: Message):
    if is_message_expired(message):
        delete_message(message)
        raise HTTPException(status_code=404, detail="Message expired!")

def delete_message(message: Message):
    pass

def initialize_client_traffic(client_key, client_mailbox, bridge_url):
    client_ip = security.generate_client_ip(bridge_url, ip_registry)
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

def get_client_mailbox_from_client_ip(client_ip):
    if not ip_registry.get(client_ip):
        raise HTTPException(status_code=404, detail="Client_ip not found")
    client_mailbox : MailBox = ip_registry[client_ip]["client_mailbox"]
    return client_mailbox