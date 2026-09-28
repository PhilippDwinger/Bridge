import uuid

def generate_key():
    return str(uuid.uuid4())

def generate_client_key(client_name):
    return str(uuid.uuid3(uuid.NAMESPACE_DNS, client_name))