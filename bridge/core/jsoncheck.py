"""Checks for JSON values from clients and other servers: values Python's json accepts that break later answers."""
import math

MAX_DEPTH = 64
# Numbers in fields (seconds, counts, ...) - bigger values are never meant and break float()/timedelta()
MAX_FIELD_NUMBER = 1e15


def json_problem(value, depth=0):
    """Values JSON allows in Python but that break later answers: NaN/Infinity and broken unicode (lone surrogates)."""
    if depth > MAX_DEPTH:
        return "nested too deep"
    if isinstance(value, float) and not math.isfinite(value):
        return "NaN / Infinity is not allowed"
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return "text with broken unicode (lone surrogate)"
    elif isinstance(value, dict):
        for key, item in value.items():
            problem = json_problem(key, depth + 1) or json_problem(item, depth + 1)
            if problem:
                return problem
    elif isinstance(value, list):
        for item in value:
            problem = json_problem(item, depth + 1)
            if problem:
                return problem
    return None


def number_problem(value):
    """For number fields: bool is no number, NaN/Infinity and absurdly big numbers are refused."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "must be a number"
    if isinstance(value, float) and not math.isfinite(value):
        return "NaN / Infinity is not allowed"
    if abs(value) > MAX_FIELD_NUMBER:
        return "number is too big"
    return None
