import datetime

from bridge.core import protocol

# Encrypted backups OTHER trusted servers gave us to keep. We cannot read them (no key).
# server_url -> {"backup": blob, "received_at": datetime, "size": int}
stored_backups = {}

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def cleanup():
    limit = _now() - datetime.timedelta(hours=protocol.stored_backup_hours)
    for server_url in [url for url, entry in stored_backups.items() if entry["received_at"] < limit]:
        del stored_backups[server_url]

def store(server_url, blob, size):
    cleanup()
    if server_url not in stored_backups and len(stored_backups) >= protocol.max_stored_backups:
        return False
    stored_backups[server_url] = {"backup": blob, "received_at": _now(), "size": size}
    return True

def fetch(server_url):
    cleanup()
    entry = stored_backups.get(server_url)
    return entry["backup"] if entry else None

def overview():
    cleanup()
    return [
        {"server_url": url, "received_at": entry["received_at"].isoformat(), "size_bytes": entry["size"]}
        for url, entry in stored_backups.items()
    ]

def reset():
    stored_backups.clear()
