import datetime

from bridge.core import protocol

# Message status for /message/status.
#   statuses - on the RECIPIENT's server: what happened to the message
#   sent     - on the SENDER's server: which messages our clients sent, so we know where to ask
WAITING = "waiting"      # in the recipient's mailbox
TAKEN = "taken"          # polled, safe message not confirmed yet
DELIVERED = "delivered"  # completely received
EXPIRED = "expired"      # nobody fetched it in time

# message_id -> {"sender_ip", "recipient_ip", "state", "updated_at"}
statuses = {}
# message_id -> {"sender_ip", "recipient_ip", "content_type", "created_at"}
sent = {}

def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def _cleanup(store, time_key):
    limit = _now() - datetime.timedelta(minutes=protocol.message_status_minutes)
    for message_id in [message_id for message_id, entry in store.items() if entry[time_key] < limit]:
        del store[message_id]
    # Oldest entries go first if there are too many (dicts keep insertion order)
    while len(store) > protocol.max_message_status_entries:
        del store[next(iter(store))]

def set_status(message, state):
    entry = statuses.get(message.message_id)
    if entry is None:
        _cleanup(statuses, "updated_at")
        entry = {"sender_ip": message.sender_ip, "recipient_ip": message.recipient_ip}
        statuses[message.message_id] = entry
    entry["state"] = state
    entry["updated_at"] = _now()

def get_status(message_id):
    return statuses.get(message_id) if isinstance(message_id, str) else None

def remember_sent(message):
    _cleanup(sent, "created_at")
    sent[message.message_id] = {
        "sender_ip": message.sender_ip,
        "recipient_ip": message.recipient_ip,
        "content_type": str(message.content_type),
        "created_at": _now(),
    }

def get_sent(message_id):
    return sent.get(message_id) if isinstance(message_id, str) else None

def reset():
    statuses.clear()
    sent.clear()
