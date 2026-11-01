# Planned messages (send_in_seconds / send_at) - they wait here on the sender's server until it is time.
# message_id -> {"client_key", "send_at", "message", "lifetime_seconds", "default_lifetime", "created_at"}
#   lifetime_seconds: the lifetime counts from the real send time (expires_in_seconds)
#   default_lifetime: no lifetime given - the normal one, also from the real send time
scheduled = {}
# Results of sent planned messages, per client (newest first, a few per client)
# client_key -> [{"message_id", "recipient_ip", "state", "error", "sent_at", "late_by_seconds"}]
results = {}
MAX_RESULTS_PER_CLIENT = 50


def add(message_id, entry):
    scheduled[message_id] = entry

def get(message_id):
    return scheduled.get(message_id)

def remove(message_id):
    return scheduled.pop(message_id, None)

def count_for(client_key):
    return sum(1 for entry in scheduled.values() if entry["client_key"] == client_key)

def bytes_for(client_key):
    return sum(entry["message"].size_bytes for entry in scheduled.values() if entry["client_key"] == client_key)

def total_bytes():
    return sum(entry["message"].size_bytes for entry in scheduled.values())

def remove_client(client_key):
    """A client was removed: its planned messages and results go too."""
    for message_id in [message_id for message_id, entry in scheduled.items() if entry["client_key"] == client_key]:
        scheduled.pop(message_id, None)
    results.pop(client_key, None)

def of_client(client_key):
    return [(message_id, entry) for message_id, entry in scheduled.items() if entry["client_key"] == client_key]

def due(now):
    return [(message_id, entry) for message_id, entry in scheduled.items() if entry["send_at"] <= now]

def add_result(client_key, result):
    entries = results.setdefault(client_key, [])
    entries.insert(0, result)
    del entries[MAX_RESULTS_PER_CLIENT:]

def reset():
    scheduled.clear()
    results.clear()
