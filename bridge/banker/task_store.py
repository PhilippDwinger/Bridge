import datetime
import time

from bridge.core import protocol

# Open command calls. They make "task" and "response" messages verified:
#   outgoing - on the caller's server: we sent this task for our client and wait for exactly one answer
#   incoming - on the host's server: our client received this task and may answer it exactly once
# Both live on the same server when caller and host are clients of the same server.

# task_id (message_id of the task) -> {"caller_ip", "host_ip", "progress", "expires_at"}
#   progress: what the caller accepts - "off" | "latest" | "all"
outgoing_tasks = {}
# task_id -> {"caller_ip", "host_ip", "conversation_id", "accepts_progress", "progress_window", "progress_count",
#             "expires_at"}
incoming_tasks = {}

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

# Called with (task_id, entry) when an incoming task expired without a response (used by the BridgeAgent)
on_incoming_expired = []

# Open tasks per client: caller_ip (outgoing) / host_ip (incoming) -> count
_open_out = {}
_open_in = {}


def _count(counter, client_ip, delta):
    value = counter.get(client_ip, 0) + delta
    if value > 0:
        counter[client_ip] = value
    else:
        counter.pop(client_ip, None)


# The next task expires no earlier than the last one, so insertion order stays the same as expiry order even if the
# wall clock jumps backwards (NTP). That keeps the stop-at-first-valid cleanup below correct.
_expiry_floor = [None]


def _cleanup(store):
    """Removes expired tasks. All tasks live equally long and are stored in order - so it only looks at the oldest
    ones and stops at the first that is still valid (no full scan on every access)."""
    now = _now()
    expired = []
    for task_id, entry in store.items():
        if entry["expires_at"] > now:
            break
        expired.append(task_id)
    for task_id in expired:
        entry = store.pop(task_id)
        if store is incoming_tasks:
            _count(_open_in, entry["host_ip"], -1)
            for callback in on_incoming_expired:
                callback(task_id, entry)
        else:
            _count(_open_out, entry["caller_ip"], -1)


def open_count(client_ip):
    """Open tasks a client called / received and did not get an answer for / did not answer yet."""
    _cleanup(outgoing_tasks)
    _cleanup(incoming_tasks)
    return _open_out.get(client_ip, 0), _open_in.get(client_ip, 0)

def _expires_at():
    candidate = _now() + datetime.timedelta(minutes=protocol.command_response_minutes)
    if _expiry_floor[0] is not None and candidate < _expiry_floor[0]:
        candidate = _expiry_floor[0]
    _expiry_floor[0] = candidate
    return candidate

# region outgoing (caller side)
def add_outgoing(task_id, caller_ip, host_ip, progress="off"):
    _cleanup(outgoing_tasks)
    if task_id in outgoing_tasks:
        remove_outgoing(task_id)
    outgoing_tasks[task_id] = {"caller_ip": caller_ip, "host_ip": host_ip, "progress": progress,
                               "sent_at": time.time(), "expires_at": _expires_at()}
    _count(_open_out, caller_ip, 1)

def get_outgoing(task_id):
    _cleanup(outgoing_tasks)
    return outgoing_tasks.get(task_id) if isinstance(task_id, str) else None

def remove_outgoing(task_id):
    entry = outgoing_tasks.pop(task_id, None)
    if entry is not None:
        _count(_open_out, entry["caller_ip"], -1)
# endregion outgoing

# region incoming (host side)
def add_incoming(task_id, caller_ip, host_ip, conversation_id, accepts_progress=False):
    _cleanup(incoming_tasks)
    if task_id in incoming_tasks:
        remove_incoming(task_id)
    _count(_open_in, host_ip, 1)
    incoming_tasks[task_id] = {
        "caller_ip": caller_ip,
        "host_ip": host_ip,
        "conversation_id": conversation_id,
        "accepts_progress": bool(accepts_progress),
        # Rate limit for progress: start of the current second (unix time) and how many were sent in it
        "progress_window": 0.0,
        "progress_count": 0,
        "expires_at": _expires_at(),
    }

def get_incoming(task_id):
    _cleanup(incoming_tasks)
    return incoming_tasks.get(task_id) if isinstance(task_id, str) else None

def remove_incoming(task_id):
    entry = incoming_tasks.pop(task_id, None)
    if entry is not None:
        _count(_open_in, entry["host_ip"], -1)
# endregion incoming

def reset():
    outgoing_tasks.clear()
    incoming_tasks.clear()
    _open_out.clear()
    _open_in.clear()
    _expiry_floor[0] = None


def rebuild_counts():
    """After a restore from the backup (the stores were filled directly)."""
    _open_out.clear()
    _open_in.clear()
    for entry in outgoing_tasks.values():
        _count(_open_out, entry["caller_ip"], 1)
    for entry in incoming_tasks.values():
        _count(_open_in, entry["host_ip"], 1)
