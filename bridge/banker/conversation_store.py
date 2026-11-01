import collections

# Conversations (like "Follow stream" in Wireshark): every server keeps the stream of the messages its own clients
# sent or received, per conversation_id. Newest activity last (LRU), see messenger/conversations.py.
# conversation_id -> {"conversation_id", "title", "record", "started_by", "participants", "group", "created_at",
#                     "last_at", "closed", "entries", "next_seq", "content_bytes", "by_message"}
conversations = collections.OrderedDict()
# conversation_id -> asyncio.Event (wakes up clients that follow the stream live) - not part of the backup
signals = {}


def get(conversation_id):
    return conversations.get(conversation_id) if isinstance(conversation_id, str) else None

def touch(conversation_id):
    conversations.move_to_end(conversation_id)

def add(conversation):
    conversations[conversation["conversation_id"]] = conversation

def remove(conversation_id):
    conversations.pop(conversation_id, None)
    signals.pop(conversation_id, None)

def oldest():
    return next(iter(conversations), None)

def reset():
    conversations.clear()
    signals.clear()
