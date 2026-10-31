# Public URL of this Bridge server (e.g. "https://bridge.example.com").
# It is part of every client IP and realm address, so other servers can see where an address belongs.
# Set once by Bridge(...). Always read it as url_env.base_root (never "from url_env import base_root").
base_root = None

def set_base_root(url):
    global base_root
    base_root = url

def get_base_root():
    return base_root
