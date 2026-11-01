import datetime

from bridge.core import protocol

# Brute force protection: after max_attempts failures a caller is locked for protocol.lock_minutes.
# key -> {"count": int, "first_failure": datetime, "locked_until": datetime | None}
_failed_attempts = {}
# Rate limits: key -> [datetime of each event inside the window]
_events = {}

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

# region brute force
def is_locked(key) -> bool:
    entry = _failed_attempts.get(key)
    if not entry or not entry["locked_until"]:
        return False
    if _now() >= entry["locked_until"]:
        del _failed_attempts[key]
        return False
    return True

def register_failure(key, max_attempts=None):
    now = _now()
    entry = _failed_attempts.get(key)
    window = datetime.timedelta(minutes=protocol.lock_minutes)
    if not entry or now - entry["first_failure"] > window:
        entry = {"count": 0, "first_failure": now, "locked_until": None}
        _failed_attempts[key] = entry
    entry["count"] += 1
    if entry["count"] >= (max_attempts or protocol.max_failed_attempts):
        entry["locked_until"] = now + window

def register_success(key):
    _failed_attempts.pop(key, None)

def reserve(key, max_attempts=None):
    """Counts an attempt BEFORE it is checked. The check (argon2) takes time - many parallel requests would all
    pass is_locked() first and only count afterwards. False if the key is locked."""
    if is_locked(key):
        return False
    if len(_failed_attempts) > 50000:
        _forget_old()
    register_failure(key, max_attempts)
    return True

def release(key, max_attempts=None):
    """The reserved attempt was right: take it back (without forgetting the other failures)."""
    entry = _failed_attempts.get(key)
    if not entry:
        return
    entry["count"] = max(0, entry["count"] - 1)
    if entry["count"] < (max_attempts or protocol.max_failed_attempts):
        entry["locked_until"] = None
    if entry["count"] == 0:
        _failed_attempts.pop(key, None)

def _forget_old():
    window = datetime.timedelta(minutes=protocol.lock_minutes)
    now = _now()
    for key in [key for key, entry in _failed_attempts.items()
                if now - entry["first_failure"] > window and not (entry["locked_until"] and entry["locked_until"] > now)]:
        del _failed_attempts[key]
# endregion brute force

# region rate limit
def allow_event(key, max_events, window_minutes) -> bool:
    """True if one more event is allowed for key (and counts it), False if the limit is reached."""
    now = _now()
    window_start = now - datetime.timedelta(minutes=window_minutes)
    events = [moment for moment in _events.get(key, []) if moment > window_start]
    if len(events) >= max_events:
        _events[key] = events
        return False
    events.append(now)
    _events[key] = events
    return True
# endregion rate limit

def reset():
    _failed_attempts.clear()
    _events.clear()
