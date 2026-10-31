from urllib.parse import urlsplit, urlunsplit

from bridge.server import url_env

# Every client IP and every realm address looks like: <server url><|BRIDGE_IP_SPLIT|><local id>
# Example: https://bridge.example.com<|BRIDGE_IP_SPLIT|>3f9a0c...
# The server URL makes the address unique across all Bridge servers and tells everyone where it belongs.
ADDRESS_SPLIT = "<|BRIDGE_IP_SPLIT|>"
MAX_ADDRESS_LENGTH = 512


def normalize_url(url):
    """Returns the canonical form of a server URL or None if it is not a valid http(s) URL."""
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url or ADDRESS_SPLIT in url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
        return None
    if parts.query or parts.fragment or parts.username or parts.password:
        return None
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/"), "", ""))


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
