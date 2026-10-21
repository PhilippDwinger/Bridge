from warnings import warn

from bridge.errors.exceptions import Exceptions, is_exception

error_bank = {}

def _add_error(error):
    global error_bank
    if not error in error_bank:
        error_bank[error] = {
            "error": error,
            "amount": 1
        }
    else:
        error_bank[error]["amount"] += 1

def add_error(error, depth=0):
    if depth > 1:
        warn("To deep!")

    if not is_exception(error):
        warn("Could not add error")
        add_error(Exceptions.ERROR_TRACKING_ERROR, depth=depth+1)
        return
    _add_error(error)

def get_errors():
    global error_bank
    return error_bank