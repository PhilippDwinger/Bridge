# client_key -> Mailbox
mailbox_storage = {}

def get_mailbox(client_key):
    return mailbox_storage.get(client_key)

def set_mailbox(client_key, mailbox):
    mailbox_storage[client_key] = mailbox

def remove_mailbox(client_key):
    mailbox_storage.pop(client_key, None)

def reset():
    mailbox_storage.clear()
