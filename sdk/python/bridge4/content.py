"""The plaintext inside an envelope (docs/04 §4 "Klartext")."""

import json as _json
import re

from .encoding import b64, b64_fixed, b64_var
from .errors import bad_format, BridgeError
from .jsonc import canonical, parse_strict
from .keys import KeyCard

MAX_PLAINTEXT_BYTES = 180 * 1024
TYPES = ("direct", "task", "response", "progress", "event", "instruction", "stream")
_CTYPE = re.compile(r"^[A-Za-z0-9/.+\-;=_]{1,64}$")


class Content:
    """``kind`` (direct, task, response, …), ``ctype``, and exactly one of ``text`` / ``data`` (``stream`` heads are
    read but not made by this SDK). ``reply``: the envelope ID this answers. ``card``: the sender's card."""

    def __init__(self, kind="direct", ctype="text/plain", text=None, data=None, reply=None, card=None, stream=None):
        self.kind = kind
        self.ctype = ctype
        self.text = text
        self.data = data
        self.reply = reply
        self.card = card
        self.stream = stream

    @classmethod
    def of_text(cls, text: str, kind: str = "direct") -> "Content":
        return cls(kind=kind, ctype="text/plain", text=text)

    @classmethod
    def of_data(cls, data: bytes, ctype: str = "application/octet-stream", kind: str = "direct") -> "Content":
        return cls(kind=kind, ctype=ctype, data=bytes(data))

    @classmethod
    def of_json(cls, value, kind: str = "task") -> "Content":
        return cls(kind=kind, ctype="application/json", data=canonical(value))

    def json(self):
        """The payload as JSON (strict)."""
        payload = self.data if self.data is not None else (self.text or "").encode("utf-8")
        return parse_strict(payload, MAX_PLAINTEXT_BYTES)

    def to_bytes(self) -> bytes:
        if self.kind not in TYPES or self.kind == "stream":
            raise bad_format("type: unknown (streams are not made by this SDK)")
        if not _CTYPE.match(self.ctype or ""):
            raise bad_format("ctype: bad")
        obj = {"v": 4, "type": self.kind, "ctype": self.ctype}
        if (self.text is None) == (self.data is None):
            raise bad_format("content: exactly one of text, data")
        if self.text is not None:
            obj["body"] = self.text
        else:
            obj["data"] = b64(self.data)
        if self.reply is not None:
            obj["reply"] = b64(self.reply)
        if self.card is not None:
            obj["card"] = self.card.to_value()
        data = canonical(obj)
        if len(data) > MAX_PLAINTEXT_BYTES:
            raise BridgeError("TOO_LARGE", "content")
        return data

    @classmethod
    def parse(cls, data: bytes) -> "Content":
        obj = parse_strict(data, MAX_PLAINTEXT_BYTES)
        if not isinstance(obj, dict) or obj.get("v") != 4:
            raise bad_format("content: wrong version")
        kind = obj.get("type")
        if kind not in TYPES:
            raise bad_format("type: unknown")
        ctype = obj.get("ctype")
        if not isinstance(ctype, str) or not _CTYPE.match(ctype):
            raise bad_format("ctype: bad")
        has = (("body" in obj), ("data" in obj), ("stream" in obj))
        content = cls(kind=kind, ctype=ctype)
        if has == (True, False, False) and kind != "stream":
            if not isinstance(obj["body"], str):
                raise bad_format("body: not a string")
            content.text = obj["body"]
        elif has == (False, True, False) and kind != "stream":
            content.data = b64_var(obj["data"], "data", MAX_PLAINTEXT_BYTES)
        elif has == (False, False, True) and kind == "stream":
            content.stream = obj["stream"]
        else:
            raise bad_format("content: exactly one of body, data, stream (stream only for streams)")
        if "reply" in obj:
            content.reply = b64_fixed(obj["reply"], "reply", 16)
        if "card" in obj:
            content.card = KeyCard.from_value(obj["card"])
        return content

    def __repr__(self):
        payload = self.text if self.text is not None else f"<{len(self.data or b'')} bytes>"
        return f"Content({self.kind}, {self.ctype}, {payload!r})"


del _json
