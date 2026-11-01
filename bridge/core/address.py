from urllib.parse import urlsplit, urlunsplit

from bridge.server import url_env

# Every client IP and every realm address looks like: <server url><|BRIDGE_IP_SPLIT|><local id>
# Example: https://bridge.example.com<|BRIDGE_IP_SPLIT|>3f9a0c...
# The server URL makes the address unique across all Bridge servers and tells everyone where it belongs.
ADDRESS_SPLIT = "<|BRIDGE_IP_SPLIT|>"
MAX_ADDRESS_LENGTH = 512


DEFAULT_PORTS = {"http": 80, "https": 443}

# Top-level routes of a Bridge server. A server address never ends in one of them - if someone pastes e.g.
# "https://x.ts.net/admin" (copied from the dashboard's address bar), the server is "https://x.ts.net".
# Without this, "https://x.ts.net/admin" would count as a different server and trust could never connect.
_BRIDGE_ROUTES = {"admin", "server", "s2s", "client", "message", "command", "realm", "express", "agent",
                  "conversation", "friends"}


def normalize_url(url):
    """Returns the canonical form of a server URL or None if it is not a valid http(s) URL.
    Canonical: lower case, no default port (https://x:443 = https://x), no dot at the end of the host, no "/" at the
    end, no Bridge route at the end (https://x/admin = https://x) - otherwise the same server could appear under
    several names (trust, block list, limits per server)."""
    if not isinstance(url, str) or len(url) > 300:
        return None
    url = url.strip()
    if not url or ADDRESS_SPLIT in url:
        return None
    try:
        url.encode("ascii")
        parts = urlsplit(url)
        port = parts.port
        host = parts.hostname
    except (ValueError, UnicodeEncodeError):
        return None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS or not host:
        return None
    if parts.query or parts.fragment or parts.username or parts.password:
        return None
    host = host.lower().rstrip(".")
    if not host or any(char in host for char in " %\\"):
        return None
    if ":" in host:
        host = f"[{host}]"  # IPv6
    netloc = host if port is None or port == DEFAULT_PORTS[scheme] else f"{host}:{port}"
    path = parts.path.rstrip("/")
    segments = path.split("/")
    for index, segment in enumerate(segments):
        if segment.lower() in _BRIDGE_ROUTES:
            path = "/".join(segments[:index]).rstrip("/")
            break
    normalized = urlunsplit((scheme, netloc, path, "", ""))
    try:
        import httpx
        httpx.URL(normalized)
    except Exception:
        return None
    return normalized


def server_key(url):
    """Host and port of a server URL (without scheme and path) - for the block list and limits per server:
    https://evil.example and http://evil.example/x are the same server for them."""
    normalized = normalize_url(url) if isinstance(url, str) else None
    if normalized is None:
        return url
    return urlsplit(normalized).netloc


def make_address(server_url, local_id):
    return f"{server_url}{ADDRESS_SPLIT}{local_id}"


def split_address(address):
    """Returns (server_url, local_id) or (None, None) if the address is invalid."""
    if not isinstance(address, str) or len(address) > MAX_ADDRESS_LENGTH:
        return None, None
    if address.count(ADDRESS_SPLIT) != 1:
        return None, None
    server_url, local_id = address.split(ADDRESS_SPLIT)
    if not local_id or normalize_url(server_url) != server_url:
        return None, None
    return server_url, local_id


def server_of(address):
    return split_address(address)[0]


def is_valid_address(address):
    return server_of(address) is not None


def is_local(address):
    server_url = server_of(address)
    return server_url is not None and server_url == url_env.base_root
