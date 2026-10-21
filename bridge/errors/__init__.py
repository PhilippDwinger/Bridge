import traceback
import warnings

from fastapi import HTTPException

from bridge.errors import tracker
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.core import protocol


def handle_error_handling_error(msg : str, http_error=False, kill_instance=False) -> None:
    if kill_instance:
        raise RuntimeError(
            f"""
            =========================================
            ==========        Error        ==========
            =========================================
            Error: {Exceptions.ERROR_HANDLING_ERROR.name}
            Reason: {Exceptions.ERROR_HANDLING_ERROR.default_message}
            Traceback: {traceback.format_exc()}
            Origin error message: {msg}
            """
        )
    else:
        if protocol.debug_warnings:
            warnings.warn(
                message=Exceptions.ERROR_HANDLING_ERROR.default_message,
                stacklevel=2,
            )
        if http_error:
            raise HTTPException(
                status_code=Exceptions.ERROR_HANDLING_ERROR.status_code,
                detail=Exceptions.ERROR_HANDLING_ERROR.default_message,
            )

def _handle_error(error, msg, http_error=False, kill_instance=False) -> None:
    if kill_instance:
        raise RuntimeError(
            f"""
                    =========================================
                    ==========        Error        ==========
                    =========================================
                    Error: {error.name}
                    Reason: {error.default_message}
                    Traceback: {traceback.format_exc()}
                    Origin error message: {msg}
                    """
        )
    else:
        if protocol.debug_warnings:
            warnings.warn(
                message=error.default_message,
                stacklevel=3,
            )
        if http_error:
            raise HTTPException(
                status_code=error.status_code,
                detail=error.default_message,
            )

def handle_error(error = Exceptions.UNKNOWN_ERROR, msg: str = "N/A", http_error: bool = False, force_kill_instance=False) -> None:
    if http_error is None or not isinstance(http_error, bool):
        handle_error_handling_error(msg, False, force_kill_instance)
        return
    if not is_exception(error):
        handle_error_handling_error(msg, http_error, force_kill_instance)
        return
    if not msg or not isinstance(msg, str):
        msg = "N/A"
    kill_instance = False
    if force_kill_instance:
        kill_instance = True
    elif error.type and isinstance(error.type, str):
        if error.type == "error":
            kill_instance = True
    try:
        tracker.add_error(error)
    except Exception:
        _handle_error(Exceptions.ERROR_TRACKING_ERROR,"Error while adding error to tracker!", http_error, False)
    _handle_error(error, msg, http_error, kill_instance)

def debug_print(msg):
    if protocol.debug:
        stack = traceback.format_stack(limit=None)
        stack = stack[-2]
        print("[DEBUG]", msg, stack)