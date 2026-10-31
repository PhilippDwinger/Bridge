import datetime
from warnings import warn

from bridge.errors.exceptions import Exceptions, BridgeWarning, is_exception

error_bank = {}

def _add_error(error, msg=None):
    global error_bank
    now = datetime.datetime.now(datetime.timezone.utc)
    if not error in error_bank:
        error_bank[error] = {
            "error": error,
            "amount": 1,
            "first_seen": now,
            "last_seen": now,
            "last_message": msg,
        }
    else:
        entry = error_bank[error]
        entry["amount"] += 1
        entry["last_seen"] = now
        entry["last_message"] = msg

def add_error(error, depth=0, msg=None):
    if depth > 1:
        warn(
            f"[Bridge TRACKER] Tracking depth {depth} exceeds the limit of 1 - "
            f"the tracker keeps failing while recording errors.",
            BridgeWarning,
            stacklevel=2,
        )

    if not is_exception(error):
        warn(
            f"[Bridge TRACKER] Could not record {error!r}: it is not an Exceptions entry. "
            f"Recording '{Exceptions.ERROR_TRACKING_ERROR.name}' instead.",
            BridgeWarning,
            stacklevel=2,
        )
        add_error(Exceptions.ERROR_TRACKING_ERROR, depth=depth+1, msg=msg)
        return
    _add_error(error, msg)

def get_errors():
    global error_bank
    return error_bank
