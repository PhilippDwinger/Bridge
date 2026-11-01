import asyncio

# client_key -> Mailbox
mailbox_storage = {}
# client_key -> asyncio.Event, set when something arrives. Used when a client polls and waits (long polling).
_signals = {}
# True while the server stops: waiting polls answer right away instead of holding up the shutdown
closing = False

def get_mailbox(client_key):
    return mailbox_storage.get(client_key)

def set_mailbox(client_key, mailbox):
    mailbox_storage[client_key] = mailbox

def remove_mailbox(client_key):
    mailbox_storage.pop(client_key, None)
    _signals.pop(client_key, None)

def get_signal(client_key):
    signal = _signals.get(client_key)
    if signal is None:
        signal = asyncio.Event()
        _signals[client_key] = signal
    return signal

def notify(client_key):
    # Wakes up a client that is waiting in a poll. Nothing is sent to the client - its own request just returns.
    signal = _signals.get(client_key)
    if signal is not None:
        signal.set()

def wake_all_for_shutdown():
    """The server stops: every waiting poll returns now (empty), so the stop and the last backup are not held up."""
    global closing
    closing = True
    for signal in _signals.values():
        signal.set()

def reset():
    mailbox_storage.clear()
    _signals.clear()


def opening():
    """The server starts (again in the same process): long polls wait normally again."""
    global closing
    closing = False
