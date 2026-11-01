import contextvars
import datetime
import os
import sys
import traceback
import warnings

from fastapi import HTTPException

from bridge.errors import tracker
from bridge.errors.exceptions import Exceptions, ExceptionInfo, BridgeWarning, is_exception, get_exception_id
from bridge.core import protocol

# Python shows a warning only once per code line by default. Bridge warnings are shown every time.
warnings.simplefilter("always", BridgeWarning)

# region report formatting
_ERRORS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_ERRORS_DIR))

_SEVERITY_LABELS = {
    "warning": "WARNING",
    "important": "IMPORTANT",
    "error": "ERROR",
}

def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _short_path(path: str) -> str:
    try:
        relative_path = os.path.relpath(path, _PROJECT_ROOT)
    except ValueError:  # different drive on Windows
        return path
    if relative_path.startswith(".."):
        return path
    return relative_path

def _caller_frames() -> list:
    # Call stack without the frames of the errors package itself (innermost frame last)
    return [
        frame for frame in traceback.extract_stack()
        if os.path.dirname(os.path.abspath(frame.filename)) != _ERRORS_DIR
    ]

def _origin() -> str:
    frames = _caller_frames()
    if not frames:
        return "unknown"
    frame = frames[-1]
    return f"{_short_path(frame.filename)}:{frame.lineno} in {frame.name}()"

def _stack_text() -> str:
    # Inside an except block: show the exception traceback, otherwise the call stack
    if sys.exc_info()[0] is not None:
        return traceback.format_exc().rstrip()
    return "".join(traceback.format_list(_caller_frames())).rstrip()

def _occurrences(error: ExceptionInfo) -> int | None:
    entry = tracker.get_errors().get(error)
    if not entry:
        return None
    return entry.get("amount")

def _format_report(error: ExceptionInfo, msg: str, reason: str | None = None, with_stack: bool = False) -> str:
    severity = _SEVERITY_LABELS.get(error.type, str(error.type).upper())
    status = f"HTTP {error.status_code}" if error.status_code is not None else "no HTTP status"
    if not msg or msg == "N/A":
        msg = "(no specific message given)"
    lines = [
        f"[Bridge {severity}] {error.name} ({status})",
        f"  Message : {msg}",
        f"  Reason  : {error.default_message or 'N/A'}",
    ]
    if reason:
        lines.append(f"  Detail  : {reason}")
    if error.hint:
        lines.append(f"  Hint    : {error.hint}")
    lines.append(f"  Origin  : {_origin()}")
    count = _occurrences(error)
    if count:
        lines.append(f"  Count   : {count}x since start")
    lines.append(f"  Time    : {_now()}")
    if with_stack:
        lines.append("  Stack   :")
        lines.extend(f"    {line}" for line in _stack_text().splitlines())
    return "\n".join(lines)

def _format_fatal_report(error: ExceptionInfo, msg: str, reason: str | None = None) -> str:
    border = "=" * 70
    return "\n".join([
        "",
        border,
        f"{'BRIDGE INSTANCE STOPPED':^70}",
        border,
        _format_report(error, msg, reason, with_stack=True),
        border,
    ])

# Extra details for the client about the HTTP error of the current request (e.g. which argument is wrong).
# Per request (contextvars), so parallel requests never see each other's details.
_client_details = contextvars.ContextVar("bridge_client_details", default=None)

def set_client_details(**details):
    """Public details for the next HTTP error of this request. Only things the client may see - no internals!"""
    _client_details.set(details)

def pop_client_details():
    details = _client_details.get()
    _client_details.set(None)
    return details

def _http_detail(error: ExceptionInfo) -> dict:
    # Only public information - msg, hint and stack stay in the server log.
    # "error" is a stable id clients can check in code (e.g. "MAILBOX_FULL").
    detail = {
        "error": get_exception_id(error) or "UNKNOWN_ERROR",
        "name": error.name,
        "message": error.default_message or "N/A",
    }
    extra = pop_client_details()
    if extra:
        detail["details"] = extra
    return detail
# endregion report formatting

def http_exception(error) -> HTTPException:
    """Builds the HTTPException for an Exceptions entry without reporting it again (it was reported where it happened)."""
    if not is_exception(error):
        error = Exceptions.UNKNOWN_ERROR
    return HTTPException(
        status_code=error.status_code or 500,
        detail=_http_detail(error),
    )

def handle_error_handling_error(msg : str, http_error=False, kill_instance=False, reason: str | None = None) -> None:
    error = Exceptions.ERROR_HANDLING_ERROR
    if kill_instance:
        raise RuntimeError(_format_fatal_report(error, msg, reason))
    else:
        if protocol.debug_warnings:
            warnings.warn(
                message=_format_report(error, msg, reason),
                category=BridgeWarning,
                stacklevel=3,
            )
        if http_error:
            raise HTTPException(
                status_code=error.status_code,
                detail=_http_detail(error),
            )

def _handle_error(error, msg, http_error=False, kill_instance=False) -> None:
    if kill_instance:
        raise RuntimeError(_format_fatal_report(error, msg))
    else:
        if protocol.debug_warnings:
            warnings.warn(
                message=_format_report(error, msg),
                category=BridgeWarning,
                stacklevel=3,
            )
        if http_error:
            raise HTTPException(
                status_code=error.status_code,
                detail=_http_detail(error),
            )

def handle_error(error = Exceptions.UNKNOWN_ERROR, msg: str = "N/A", http_error: bool = False, force_kill_instance=False) -> None:
    if http_error is None or not isinstance(http_error, bool):
        handle_error_handling_error(
            msg, False, force_kill_instance,
            reason=f"'http_error' must be a bool, got {type(http_error).__name__} ({http_error!r})",
        )
        return
    if not is_exception(error):
        handle_error_handling_error(
            msg, http_error, force_kill_instance,
            reason=f"'error' must be an Exceptions entry, got {type(error).__name__} ({error!r})",
        )
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
        tracker.add_error(error, msg=msg)
    except Exception as tracking_exception:
        _handle_error(
            Exceptions.ERROR_TRACKING_ERROR,
            f"Error while adding '{error.name}' to the tracker: {type(tracking_exception).__name__}: {tracking_exception}",
            http_error,
            False,
        )
    _handle_error(error, msg, http_error, kill_instance)

def debug_print(msg):
    if protocol.debug:
        print(f"[Bridge DEBUG {datetime.datetime.now():%H:%M:%S}] {msg}  <- {_origin()}")
