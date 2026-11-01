import datetime

from bridge.core import protocol

# Encrypted backups OTHER trusted servers gave us to keep (never our own). We cannot read them (no key).
# They may have reached us directly from the owner or relayed by another trusted server (A -> B -> C).
# server_url (the OWNER) -> {"backup": blob, "received_at": datetime, "size": int, "epoch": int}
#   epoch: the owner's version counter inside the blob - a newer epoch replaces an older one (never the other way).
stored_backups = {}

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def cleanup():
    limit = _now() - datetime.timedelta(hours=protocol.stored_backup_hours)
    for server_url in [url for url, entry in stored_backups.items() if entry["received_at"] < limit]:
        del stored_backups[server_url]

def store(server_url, blob, size, epoch=0):
    """Keeps the backup of the server `server_url`. Only a newer (or equal) epoch replaces what we have, so a relayed
    older copy can never overwrite a newer one. Returns False only when we are full."""
    cleanup()
    existing = stored_backups.get(server_url)
    if existing is not None and epoch < existing.get("epoch", 0):
        return True  # we already keep a newer backup of this server - keep it
    if existing is None and len(stored_backups) >= protocol.max_stored_backups:
        return False
    stored_backups[server_url] = {"backup": blob, "received_at": _now(), "size": size, "epoch": epoch}
    return True

def fetch(server_url):
    cleanup()
    entry = stored_backups.get(server_url)
    return entry["backup"] if entry else None

def epoch_of(server_url):
    entry = stored_backups.get(server_url)
    return entry["epoch"] if entry else -1

def held_backups():
    """All backups we currently keep for other servers: (owner_url, blob, size, epoch). For relaying them on."""
    cleanup()
    return [(url, entry["backup"], entry["size"], entry["epoch"]) for url, entry in stored_backups.items()]

def overview():
    cleanup()
    return [
        {"server_url": url, "received_at": entry["received_at"].isoformat(), "size_bytes": entry["size"],
         "epoch": entry["epoch"]}
        for url, entry in stored_backups.items()
    ]

def reset():
    stored_backups.clear()
