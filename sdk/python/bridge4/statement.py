"""Signed statements (docs/04 §3): one signer (``iss`` + ``sig``) or several (``sigs``, strictly ascending)."""

import re

from . import crypto
from .encoding import b64, b64_fixed
from .errors import BridgeError, bad_format, bad_signature
from .jsonc import canonical, canonical_without, parse_strict
from .keys import check_id

MAX_STATEMENT_BYTES = 64 * 1024
MAX_SIGNERS = 16
MAX_LIFETIME_MS = 2 * 366 * 24 * 3600 * 1000
CLOCK_SKEW_MS = 5 * 60 * 1000
RESERVED = ("env", "key", "rq", "pow", "part")
_KIND = re.compile(r"^[a-z]{1,16}$")


class Statement:
    """A statement whose form is checked; signatures with :meth:`verify`."""

    def __init__(self, raw: dict, signers):
        self.raw = raw
        self.kind = raw["t"]
        self.net = raw["net"]
        self.iat = raw["iat"]
        self.exp = raw["exp"]
        self.body = raw["body"]
        self.signers = signers  # [(id, signature bytes)]

    @classmethod
    def parse(cls, data, max_bytes: int = MAX_STATEMENT_BYTES) -> "Statement":
        return cls.from_value(parse_strict(data, max_bytes), max_bytes)

    @classmethod
    def from_value(cls, value, max_bytes: int = MAX_STATEMENT_BYTES) -> "Statement":
        if not isinstance(value, dict):
            raise bad_format("statement: not an object")
        if len(canonical(value)) > max_bytes:
            raise BridgeError("TOO_LARGE", "statement")
        if value.get("v") != 4:
            raise bad_format("statement: wrong version")
        kind = value.get("t")
        if not isinstance(kind, str) or not _KIND.match(kind) or kind in RESERVED:
            raise bad_format("statement: bad kind")
        check_id(value.get("net"))
        iat, exp = value.get("iat"), value.get("exp")
        if not all(isinstance(x, int) and not isinstance(x, bool) for x in (iat, exp)):
            raise bad_format("statement: iat/exp")
        if iat < 0 or exp <= iat or exp - iat > MAX_LIFETIME_MS:
            raise bad_format("statement: bad iat/exp")
        if not isinstance(value.get("body"), dict):
            raise bad_format("statement: body must be an object")
        if "sig" in value and "sigs" not in value:
            signers = [(check_id(value.get("iss")), b64_fixed(value["sig"], "sig", 64))]
        elif "sigs" in value and "sig" not in value and isinstance(value["sigs"], list) and 1 <= len(value["sigs"]) <= MAX_SIGNERS:
            if "iss" in value:
                raise bad_format("statement: iss together with sigs")
            signers = []
            for entry in value["sigs"]:
                if not isinstance(entry, dict) or set(entry) != {"iss", "sig"}:
                    raise bad_format("sigs: entries are exactly {iss, sig}")
                issuer = check_id(entry["iss"])
                if signers and signers[-1][0].encode() >= issuer.encode():
                    raise bad_format("sigs: signers must be strictly ascending by iss")
                signers.append((issuer, b64_fixed(entry["sig"], "sig", 64)))
        else:
            raise bad_format("statement: needs either sig or sigs (1..=16)")
        return cls(dict(value), signers)

    @classmethod
    def sign(cls, kind: str, net: str, iat: int, exp: int, body: dict, signer) -> "Statement":
        raw = {"v": 4, "t": kind, "net": net, "iat": iat, "exp": exp, "body": body, "iss": signer.id}
        raw["sig"] = b64(signer.sign_canonical(kind, canonical(raw)))
        return cls.from_value(raw)

    @classmethod
    def sign_multi(cls, kind: str, net: str, iat: int, exp: int, body: dict, signers) -> "Statement":
        raw = {"v": 4, "t": kind, "net": net, "iat": iat, "exp": exp, "body": body}
        data = canonical(raw)
        ordered = sorted(signers, key=lambda s: s.id.encode())
        raw["sigs"] = [{"iss": s.id, "sig": b64(s.sign_canonical(kind, data))} for s in ordered]
        return cls.from_value(raw)

    def claimed_signers(self):
        return [issuer for issuer, _ in self.signers]

    def verify(self, cards, threshold: int = 1):
        """Verifies every listed signature with ``cards`` (verified key cards); fails below ``threshold``."""
        data = canonical_without(self.raw, ("sigs",) if "sigs" in self.raw else ("sig",))
        valid = []
        for issuer, signature in self.signers:
            card = next((c for c in cards if c.id == issuer), None)
            if card is None:
                raise bad_signature()
            crypto.verify(card.sign, self.kind, data, signature)
            valid.append(issuer)
        if threshold == 0 or len(valid) < threshold:
            raise bad_signature()
        return valid

    def check_time(self, now_ms: int) -> None:
        if self.iat > now_ms + CLOCK_SKEW_MS:
            raise BridgeError("NOT_YET_VALID")
        if now_ms >= self.exp:
            raise BridgeError("EXPIRED")

    def to_value(self) -> dict:
        return dict(self.raw)

    def canonical_bytes(self) -> bytes:
        return canonical(self.raw)

    def hash(self) -> str:
        return b64(crypto.sha256(canonical_without(self.raw, ("sig", "sigs"))))
