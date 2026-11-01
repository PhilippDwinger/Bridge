import datetime

from bridge import errors
from bridge.errors.exceptions import Exceptions
from bridge.security.hasher import secrets_equal

STATUS_WAITING = "waiting"      # added by our admin, handshake not (yet) completed
STATUS_CONNECTED = "connected"  # both sides trust each other and share a token

# server_url -> {"url", "status", "token", "added_at", "connected_at", "last_error"}
trusted_servers = {}

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def add_server(server_url):
    if server_url in trusted_servers:
        errors.handle_error(Exceptions.ALREADY_EXISTS, f"Server {server_url} is already trusted")
        return Exceptions.ALREADY_EXISTS
    trusted_servers[server_url] = {
        "url": server_url,
        "status": STATUS_WAITING,
        "token": None,
        "added_at": _now(),
        "connected_at": None,
        "last_error": None,
        # Filled during the handshake - which Bridge version/commit the other server runs (for rolling upgrades)
        "protocol_version": None,
        "commit": None,
    }
    return True

def remove_server(server_url):
    if server_url not in trusted_servers:
        errors.handle_error(Exceptions.KEY_ERROR, f"Server {server_url} is not in the trusted list")
        return Exceptions.KEY_ERROR
    del trusted_servers[server_url]
    return True

def is_trusted(server_url):
    return server_url in trusted_servers

def matches_trusted(server_url):
    """True if a trusted server has the same host and port, ignoring the scheme and path."""
    from bridge.core import address
    key = address.server_key(server_url)
    return any(address.server_key(url) == key for url in trusted_servers)

def get_token(server_url):
    entry = trusted_servers.get(server_url)
    return entry["token"] if entry else None

def set_connected(server_url, token, peer_version=None, commit=None):
    entry = trusted_servers.get(server_url)
    if not entry:
        return False
    entry["token"] = token
    entry["status"] = STATUS_CONNECTED
    entry["connected_at"] = _now()
    entry["last_error"] = None
    if peer_version is not None:
        entry["protocol_version"] = peer_version
    if commit is not None:
        entry["commit"] = commit
    return True

def set_waiting(server_url, error=None):
    entry = trusted_servers.get(server_url)
    if not entry:
        return False
    entry["token"] = None
    entry["status"] = STATUS_WAITING
    entry["connected_at"] = None
    entry["last_error"] = error
    return True

def verify_token(server_url, token):
    expected = get_token(server_url)
    return expected is not None and secrets_equal(expected, token)

def list_servers():
    # Public view without tokens
    return [
        {
            "url": entry["url"],
            "status": entry["status"],
            "added_at": entry["added_at"].isoformat(),
            "connected_at": entry["connected_at"].isoformat() if entry["connected_at"] else None,
            "last_error": entry["last_error"],
            "protocol_version": entry.get("protocol_version"),
            "commit": entry.get("commit"),
        }
        for entry in trusted_servers.values()
    ]
