"""BridgeFriends in RAM: friendships, invitations ("doors"), presence of the clients and the server block list.

friendships: local_ip -> {friend_ip: entry}
    entry: {"friendship_id", "local_ip", "friend_ip", "state", "secret", "created_at", "accepted_at",
            "friend_label", "nickname", "door"}
    state: "active" | "pending_out" (we asked, the other side has to answer) | "pending_in" (we have to answer)
    Two clients of the same server have two entries (one per side) with the same friendship_id and secret.
doors: key (lowercase name or code) -> {"invite_id", "key", "kind", "owner_ip", "label", "salt", "verifier",
            "has_password", "expires_at", "max_uses", "uses", "accept", "created_at"}
    "verifier" is K0 = argon2id(password, salt) - never the password itself (failed attempts: doors.py).
presence: client_ip -> {"presence", "text", "updated_at"}
blocked: server URLs this server does not talk to (no friendships, no friend connections, no relayed messages)
"""
import datetime

friendships = {}
doors = {}
presence = {}
blocked = set()


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def is_blocked(server_url):
    """Blocked by host and port - https://evil.example:443/x is the same server as https://evil.example."""
    from bridge.core import address
    key = address.server_key(server_url)
    return any(address.server_key(url) == key for url in blocked)


# region friendships
def get(local_ip, friend_ip):
    return friendships.get(local_ip, {}).get(friend_ip)

def of_client(local_ip):
    return list(friendships.get(local_ip, {}).values())

def count(local_ip):
    return len(friendships.get(local_ip, {}))

def put(entry):
    friendships.setdefault(entry["local_ip"], {})[entry["friend_ip"]] = entry
    return entry

def remove(local_ip, friend_ip):
    own = friendships.get(local_ip)
    if not own:
        return None
    entry = own.pop(friend_ip, None)
    if not own:
        friendships.pop(local_ip, None)
    return entry

def all_entries():
    for own in friendships.values():
        yield from own.values()

def total():
    return sum(len(own) for own in friendships.values())
# endregion friendships


# region doors
def doors_of(owner_ip):
    return [door for door in doors.values() if door["owner_ip"] == owner_ip]

def remove_door(key):
    return doors.pop(key, None)
# endregion doors


def reset():
    """Admin reset: friendships, doors and presence go - the block list stays (like the trusted list)."""
    friendships.clear()
    doors.clear()
    presence.clear()


# region backup
def _iso(value):
    return value.isoformat() if isinstance(value, datetime.datetime) else value

def _parse(value):
    return datetime.datetime.fromisoformat(value) if isinstance(value, str) else value

def to_state():
    return {
        "friendships": [{key: _iso(value) for key, value in entry.items()} for entry in all_entries()],
        "doors": [{key: _iso(value) for key, value in door.items() if key not in ("fails", "locked_until")}
                  for door in doors.values()],
        "presence": {ip: {key: _iso(value) for key, value in entry.items()} for ip, entry in presence.items()},
        "blocked": sorted(blocked),
    }

def load_state(state):
    reset()
    if not isinstance(state, dict):
        return
    for entry in state.get("friendships") or []:
        put({key: _parse(value) if key in ("created_at", "accepted_at") else value for key, value in entry.items()})
    for door in state.get("doors") or []:
        door = {key: _parse(value) if key in ("created_at", "expires_at") else value for key, value in door.items()}
        doors[door["key"]] = door
    for ip, entry in (state.get("presence") or {}).items():
        presence[ip] = {key: _parse(value) if key == "updated_at" else value for key, value in entry.items()}
    # Union: servers the admin blocked at the start (BRIDGE_BLOCKED / block_server) stay blocked
    blocked.update(url for url in state.get("blocked") or [] if isinstance(url, str))
# endregion backup
