import datetime

# Copies ("mirrors") of realms that live on other servers, kept here because clients of this server are members.
# realm_address -> {"view": dict, "synced_at": datetime, "source": server_url}
# The view is made by the realm server for this server only (see realm/sync.py). It never contains
# access keys or invitation codes.
mirror_storage = {}

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def get_mirror(realm_address):
    return mirror_storage.get(realm_address)

def set_mirror(realm_address, view, source):
    mirror_storage[realm_address] = {"view": view, "synced_at": _now(), "source": source}

def touch(realm_address):
    entry = mirror_storage.get(realm_address)
    if entry is not None:
        entry["synced_at"] = _now()

def remove_mirror(realm_address):
    mirror_storage.pop(realm_address, None)

def addresses():
    return list(mirror_storage)

def reset():
    mirror_storage.clear()
