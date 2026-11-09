# Public URL of this Bridge server (e.g. "https://bridge.example.com").
# It is part of every client IP and realm address, so other servers can see where an address belongs.
# Set once by Bridge(...). Always read it as url_env.base_root (never "from url_env import base_root").
base_root = None

def set_base_root(url):
    global base_root
    base_root = url

def get_base_root():
    return base_root

def base_path():
    """The path part of the public URL: "" for https://x, "/momentum" for https://pc.ts.net:10000/momentum (several
    servers behind one host and port). Requests may arrive with it (a proxy that keeps the path) or without it (a
    proxy that strips it, like Tailscale serve/funnel) - app.py accepts both. Pages use it for their links."""
    from urllib.parse import urlsplit
    if not base_root:
        return ""
    try:
        return urlsplit(base_root).path.rstrip("/")
    except ValueError:
        return ""
