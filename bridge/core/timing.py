"""Times from clients - the same rules everywhere (lifetime of messages, scheduled messages, ...).

A time is given either
- as a timer:        "<name>_in_seconds": 90
- or as a point:     "<name>_at": "2026-11-01T09:00:00+01:00"  (ISO 8601 with offset or "Z")
                     "<name>_at": "2026-11-01T09:00:00" + "timezone": "Europe/Berlin"  (IANA name, summer time is handled)
A point without any timezone is rejected (TIMEZONE_MISSING) - Bridge never guesses.
Bridge answers always in UTC (ISO 8601 with "+00:00").
"""
import datetime
import math

from bridge import errors
from bridge.errors.exceptions import Exceptions

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # pragma: no cover
    ZoneInfo = None
    ZoneInfoNotFoundError = Exception


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def _fail(error, problem):
    errors.handle_error(error, problem)
    errors.set_client_details(problems=[problem])
    return error


def zone(timezone_name):
    """ZoneInfo for an IANA name or an exception."""
    if not isinstance(timezone_name, str) or not timezone_name.strip() or len(timezone_name) > 64:
        return _fail(Exceptions.ARGUMENT_ERROR, "'timezone' must be an IANA name like 'Europe/Berlin' or 'UTC'")
    if ZoneInfo is None:
        return _fail(Exceptions.ARGUMENT_ERROR, "This server cannot handle timezone names - use an offset like +01:00")
    try:
        return ZoneInfo(timezone_name.strip())
    except (ZoneInfoNotFoundError, ValueError):
        # On Windows Python needs the package "tzdata" for timezone names
        return _fail(Exceptions.ARGUMENT_ERROR,
                     f"Unknown timezone {timezone_name!r} (IANA name like 'Europe/Berlin' - on Windows the server needs 'pip install tzdata')")


def parse_point(text, timezone_name=None, field="time"):
    """ISO 8601 text -> aware datetime in UTC, or an exception (with details for the client)."""
    if not isinstance(text, str) or not text.strip() or len(text) > 64:
        return _fail(Exceptions.ARGUMENT_ERROR, f"'{field}' must be an ISO 8601 time like 2026-11-01T09:00:00+01:00")
    try:
        value = datetime.datetime.fromisoformat(text.strip())
    except ValueError:
        return _fail(Exceptions.ARGUMENT_ERROR, f"'{field}' is no ISO 8601 time: {text!r} (example: 2026-11-01T09:00:00+01:00)")
    if not 1970 <= value.year <= 9000:
        return _fail(Exceptions.ARGUMENT_ERROR, f"'{field}' must be between the years 1970 and 9000")
    if value.tzinfo is None:
        if timezone_name is None:
            return _fail(Exceptions.TIMEZONE_MISSING,
                         f"'{field}' has no timezone - add an offset (+01:00 / Z) or the field 'timezone' (e.g. 'Europe/Berlin')")
        tz = zone(timezone_name)
        if not isinstance(tz, datetime.tzinfo):
            return tz
        naive = value
        value = value.replace(tzinfo=tz)
        try:
            # Summer time: a local time can be missing (clocks jump forward) or exist twice (they go back).
            # Bridge never guesses - the client has to give the offset then.
            if value.astimezone(datetime.timezone.utc).astimezone(tz).replace(tzinfo=None) != naive:
                return _fail(Exceptions.ARGUMENT_ERROR,
                             f"'{field}' {naive.isoformat()} does not exist in {timezone_name} (summer time change) - "
                             f"use an offset like +01:00")
            if value.replace(fold=0).utcoffset() != value.replace(fold=1).utcoffset():
                return _fail(Exceptions.ARGUMENT_ERROR,
                             f"'{field}' {naive.isoformat()} exists twice in {timezone_name} (summer time ends) - "
                             f"add the offset, e.g. +02:00 or +01:00")
        except (OverflowError, ValueError):
            return _fail(Exceptions.ARGUMENT_ERROR, f"'{field}' is out of range")
    try:
        return value.astimezone(datetime.timezone.utc)
    except (OverflowError, ValueError):
        return _fail(Exceptions.ARGUMENT_ERROR, f"'{field}' is out of range")


def resolve(seconds=None, at=None, timezone_name=None, name="time", allow_negative=False):
    """A timer (seconds from now) or a point in time -> UTC datetime, None if neither is given, or an exception."""
    if seconds is not None and at is not None:
        return _fail(Exceptions.ARGUMENT_ERROR, f"Use either '{name}_in_seconds' or '{name}_at', not both")
    if seconds is not None:
        if (isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds)
                or (seconds < 0 and not allow_negative)):
            return _fail(Exceptions.ARGUMENT_ERROR, f"'{name}_in_seconds' must be a number >= 0")
        if abs(seconds) > 3650 * 24 * 3600:
            return _fail(Exceptions.ARGUMENT_ERROR, f"'{name}_in_seconds' is too far away")
        return now() + datetime.timedelta(seconds=seconds)
    if at is not None:
        return parse_point(at, timezone_name, f"{name}_at")
    return None


def iso(value):
    return value.astimezone(datetime.timezone.utc).isoformat() if value is not None else None
