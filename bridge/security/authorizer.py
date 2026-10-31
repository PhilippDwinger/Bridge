import datetime

from bridge.core import protocol

# Brute force protection: after protocol.max_failed_attempts failures a caller is locked for protocol.lock_minutes.
# key -> {"count": int, "first_failure": datetime, "locked_until": datetime | None}
_failed_attempts = {}

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def is_locked(key) -> bool:
    entry = _failed_attempts.get(key)
    if not entry or not entry["locked_until"]:
        return False
    if _now() >= entry["locked_until"]:
        del _failed_attempts[key]
        return False
    return True

def register_failure(key):
    now = _now()
    entry = _failed_attempts.get(key)
    window = datetime.timedelta(minutes=protocol.lock_minutes)
    if not entry or now - entry["first_failure"] > window:
        entry = {"count": 0, "first_failure": now, "locked_until": None}
        _failed_attempts[key] = entry
    entry["count"] += 1
    if entry["count"] >= protocol.max_failed_attempts:
        entry["locked_until"] = now + window

def register_success(key):
    _failed_attempts.pop(key, None)

def reset():
    _failed_attempts.clear()
