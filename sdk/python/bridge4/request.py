"""Signed requests (``rq``, docs/04 §7): bound to one node, valid ±5 minutes, random nonce."""

import re

from . import crypto
from .encoding import b64, b64_fixed
from .errors import BridgeError, bad_format, bad_signature
from .jsonc import canonical, canonical_without, parse_strict
from .keys import check_id

MAX_REQUEST_BYTES = 64 * 1024
CLOCK_SKEW_MS = 5 * 60 * 1000
_OP = re.compile(r"^[a-z-]{1,24}$")


class SignedRequest:
    def __init__(self, raw: dict):
        self.raw = raw
        self.aud = raw["aud"]
        self.iss = raw["iss"]
        self.iat = raw["iat"]
        self.op = raw["op"]
        self.body = raw["body"]
        self.signature = b64_fixed(raw["sig"], "sig", 64)

    @classmethod
    def sign(cls, signer, aud: str, op: str, body: dict, iat: int, nonce: bytes = None) -> "SignedRequest":
        """Signs ``op`` with ``body`` for the node ``aud``. ``nonce`` is random unless given (tests only)."""
        nonce = crypto.random_bytes(16) if nonce is None else nonce
        raw = {"v": 4, "t": "rq", "aud": aud, "iss": signer.id, "iat": iat, "n": b64(nonce), "op": op, "body": body}
        raw["sig"] = b64(signer.sign_canonical("rq", canonical(raw)))
        request = cls.from_value(raw)
        if len(request.to_bytes()) > MAX_REQUEST_BYTES:
            raise BridgeError("TOO_LARGE", "request")
        return request

    @classmethod
    def parse(cls, data) -> "SignedRequest":
        return cls.from_value(parse_strict(data, MAX_REQUEST_BYTES))

    @classmethod
    def from_value(cls, value) -> "SignedRequest":
        if not isinstance(value, dict) or value.get("v") != 4 or value.get("t") != "rq":
            raise bad_format("request: wrong version or type")
        if not isinstance(value.get("op"), str) or not _OP.match(value["op"]):
            raise bad_format("op: bad name")
        if not isinstance(value.get("body"), dict):
            raise bad_format("body: not an object")
        iat = value.get("iat")
        if not isinstance(iat, int) or isinstance(iat, bool) or iat < 0:
            raise bad_format("iat")
        check_id(value.get("aud"))
        check_id(value.get("iss"))
        b64_fixed(value.get("n"), "n", 16)
        b64_fixed(value.get("sig"), "sig", 64)
        return cls(dict(value))

    def check(self, node: str, now_ms: int) -> None:
        if self.aud != node:
            raise bad_signature()
        if self.iat > now_ms + CLOCK_SKEW_MS:
            raise BridgeError("NOT_YET_VALID")
        if now_ms - self.iat > CLOCK_SKEW_MS:
            raise BridgeError("EXPIRED")

    def verify(self, card) -> None:
        if card.id != self.iss:
            raise bad_signature()
        crypto.verify(card.sign, "rq", canonical_without(self.raw, ("sig",)), self.signature)

    def to_value(self) -> dict:
        return dict(self.raw)

    def to_bytes(self) -> bytes:
        return canonical(self.raw)
