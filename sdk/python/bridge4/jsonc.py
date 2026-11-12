"""Strict JSON in, canonical JSON (RFC 8785) out - exactly the rules of the Rust core (docs/04 §1, Z3):
size first, UTF-8 only, no duplicate keys, integers within ±(2^53-1) only (no floats, no -0), depth at most 32, no lone
surrogates. Canonical form: keys sorted by UTF-16 code units, minimal escapes, integers as decimals."""

import json

from .errors import BridgeError, bad_format

MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_DEPTH = 32


def _no_float(text):
    raise bad_format("floating point numbers are not allowed")


def _int(text):
    if text == "-0":
        raise bad_format("-0 is not allowed")
    value = int(text)
    if abs(value) > MAX_SAFE_INTEGER:
        raise bad_format("integer outside ±(2^53-1)")
    return value


def _constant(text):
    raise bad_format(f"{text} is not allowed")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise bad_format(f"duplicate key {key!r}")
        result[key] = value
    return result


def depth(value) -> int:
    """Nesting depth (a scalar is 0, ``[]`` is 1); stops counting above the limit."""
    stack = [(value, 0)]
    deepest = 0
    while stack:
        item, level = stack.pop()
        if isinstance(item, (dict, list)):
            level += 1
            deepest = max(deepest, level)
            if deepest > MAX_DEPTH:
                return deepest
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, level) for child in children)
    return deepest


def _check_strings(value):
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            item.encode("utf-8")  # lone surrogates raise
        elif isinstance(item, dict):
            for key, child in item.items():
                key.encode("utf-8")
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)


def parse_strict(data, max_bytes: int):
    """Parses bytes (or str) as strict Bridge JSON; ``max_bytes`` is checked before anything else."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if len(data) > max_bytes:
        raise BridgeError("TOO_LARGE", f"json over {max_bytes} bytes")
    try:
        text = bytes(data).decode("utf-8")
        value = json.loads(
            text, parse_float=_no_float, parse_int=_int, parse_constant=_constant, object_pairs_hook=_pairs
        )
        _check_strings(value)
    except BridgeError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise bad_format(f"json: {error}") from None
    if depth(value) > MAX_DEPTH:
        raise bad_format(f"nesting deeper than {MAX_DEPTH}")
    return value


def _escape(text: str, out: list):
    out.append('"')
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')


def _write(value, out: list, level: int):
    if level > MAX_DEPTH:
        raise bad_format("nesting too deep")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise bad_format("only integers within ±(2^53-1) are allowed")
        out.append(str(value))
    elif isinstance(value, str):
        value.encode("utf-8")
        _escape(value, out)
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _write(item, out, level + 1)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        for index, key in enumerate(sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))):
            if not isinstance(key, str):
                raise bad_format("keys must be strings")
            if index:
                out.append(",")
            _escape(key, out)
            out.append(":")
            _write(value[key], out, level + 1)
        out.append("}")
    else:
        raise bad_format(f"not a JSON value: {type(value).__name__}")


def canonical(value) -> bytes:
    """Canonical JSON bytes of a strict Bridge value."""
    out = []
    _write(value, out, 0)
    return "".join(out).encode("utf-8")


def canonical_without(obj: dict, skip) -> bytes:
    return canonical({key: value for key, value in obj.items() if key not in skip})
