from bridge.security import hasher
from bridge.security.generator import get_free_key_in_dict

ip_storage = {}

def get_free_ip(bridge_url, client_key):
    free_raw_ip = get_free_key_in_dict(ip_storage)
    free_ip = hasher.merge_hash_strings(free_raw_ip, bridge_url)
    ip_storage[free_ip] = client_key
    return free_ip

def reset():
    ip_storage.clear()