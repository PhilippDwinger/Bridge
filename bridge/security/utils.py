from bridge import errors
from bridge.errors.exceptions import Exceptions


def pcall(function, *args, **kwargs):
    try:
        return True, function(*args, **kwargs)
    except Exception as error:
        return False, error

def save_pick(structure : dict | object, key):
    if isinstance(structure, dict):
        try:
            value = structure[key]
            return True, value
        except Exception as error:
            return False, error
    elif hasattr(structure, "__dict__"):
        try:
            value = getattr(structure, key)
            return True, value
        except Exception as error:
            return False, error
    else:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Wrong type: {type(structure).__name__}")
        return False, Exceptions.ARGUMENT_ERROR