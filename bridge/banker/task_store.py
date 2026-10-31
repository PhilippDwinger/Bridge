import datetime

from bridge.core import protocol

# Open command calls. They make "task" and "response" messages verified:
#   outgoing - on the caller's server: we sent this task for our client and wait for exactly one answer
#   incoming - on the host's server: our client received this task and may answer it exactly once
# Both live on the same server when caller and host are clients of the same server.

# task_id (message_id of the task) -> {"caller_ip", "host_ip", "expires_at"}
outgoing_tasks = {}
# task_id -> {"caller_ip", "host_ip", "conversation_id", "expires_at"}
incoming_tasks = {}

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def _cleanup(store):
    now = _now()
    for task_id in [task_id for task_id, entry in store.items() if entry["expires_at"] <= now]:
        del store[task_id]

def _expires_at():
    return _now() + datetime.timedelta(minutes=protocol.command_response_minutes)

# region outgoing (caller side)
def add_outgoing(task_id, caller_ip, host_ip):
    _cleanup(outgoing_tasks)
    outgoing_tasks[task_id] = {"caller_ip": caller_ip, "host_ip": host_ip, "expires_at": _expires_at()}

def get_outgoing(task_id):
    _cleanup(outgoing_tasks)
    return outgoing_tasks.get(task_id) if isinstance(task_id, str) else None

def remove_outgoing(task_id):
    outgoing_tasks.pop(task_id, None)
# endregion outgoing

# region incoming (host side)
def add_incoming(task_id, caller_ip, host_ip, conversation_id):
    _cleanup(incoming_tasks)
    incoming_tasks[task_id] = {
        "caller_ip": caller_ip,
        "host_ip": host_ip,
        "conversation_id": conversation_id,
        "expires_at": _expires_at(),
    }

def get_incoming(task_id):
    _cleanup(incoming_tasks)
    return incoming_tasks.get(task_id) if isinstance(task_id, str) else None

def remove_incoming(task_id):
    incoming_tasks.pop(task_id, None)
# endregion incoming

def reset():
    outgoing_tasks.clear()
    incoming_tasks.clear()
