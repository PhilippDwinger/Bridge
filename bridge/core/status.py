from bridge.banker import trust_store


def get_server_status():
    return "online"

def get_connection_status(url):
    # Status of a trusted server: "connected", "waiting" or None if it is not trusted
    for server in trust_store.list_servers():
        if server["url"] == url:
            return server["status"]
    return None

def get_message_status(message_id):
    # Planned
    pass
