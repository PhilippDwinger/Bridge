"""Base32 for IDs (RFC 4648, lower case, no padding) and Base64url without padding, canonical only (docs/04 §1)."""

import base64

from .errors import BridgeError, bad_format

_B32 = "abcdefghijklmnopqrstuvwxyz234567"


def base32(data: bytes) -> str:
    out = []
    buffer = 0
    bits = 0
    for byte in data:
        buffer = (buffer << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(_B32[(buffer >> bits) & 31])
    if bits > 0:
        out.append(_B32[(buffer << (5 - bits)) & 31])
    return "".join(out)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).decode("ascii").rstrip("=")


def b64_var(text, field: str, max_bytes: int) -> bytes:
    """Decodes canonical Base64url (no padding, one spelling per value) of at most ``max_bytes``."""
    if not isinstance(text, str):
        raise bad_format(f"{field}: not a string")
    if len(text) > ((max_bytes + 2) // 3) * 4 + 4:
        raise BridgeError("TOO_LARGE", field)
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in text):
        raise bad_format(f"{field}: not base64url")
    if len(text) % 4 == 1:
        raise bad_format(f"{field}: not base64url")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise bad_format(f"{field}: not base64url") from None
    if b64(data) != text:
        raise bad_format(f"{field}: not canonical base64url")
    if len(data) > max_bytes:
        raise BridgeError("TOO_LARGE", field)
    return data


def b64_fixed(text, field: str, size: int) -> bytes:
    data = b64_var(text, field, size)
    if len(data) != size:
        raise bad_format(f"{field}: expected {size} bytes")
    return data
