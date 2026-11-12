"""Envelopes (docs/04 §4): signed by the sender, encrypted for exactly one recipient. Invariant N1: the one-time key
and the nonce are made here from the system's random source - the API takes neither."""

from . import crypto
from .encoding import b64, b64_fixed, b64_var
from .errors import BridgeError, bad_format, bad_signature
from .jsonc import canonical, canonical_without, depth, parse_strict
from .keys import check_id

MAX_ENVELOPE_BYTES = 256 * 1024
MAX_PLAINTEXT_BYTES = 180 * 1024
MAX_TTL_SECONDS = 7 * 24 * 3600
CLOCK_SKEW_MS = 5 * 60 * 1000
KINDS = ("msg", "req", "res", "evt", "ack")
_INFO = b"bridge4/env/v1"


def _key(shared: bytes, epk: bytes, recipient_box: bytes, envelope_id: bytes) -> bytes:
    return crypto.derive_key(shared, epk + recipient_box, _INFO + envelope_id)


class Envelope:
    def __init__(self, raw: dict):
        self.raw = raw
        self.id = b64_fixed(raw["id"], "id", 16)
        self.net = raw["net"]
        self.dnet = raw.get("dnet")
        self.sender = raw["from"]
        self.to = raw["to"]
        self.kind = raw["kind"]
        self.iat = raw["iat"]
        self.ttl = raw["ttl"]
        self.epk = b64_fixed(raw["epk"], "epk", 32)
        self.nonce = b64_fixed(raw["n"], "n", 12)
        self.ciphertext = b64_var(raw["ct"], "ct", MAX_PLAINTEXT_BYTES + 16)
        self.signature = b64_fixed(raw["sig"], "sig", 64)

    @classmethod
    def seal(cls, sender, net: str, to_card, plaintext: bytes, iat: int, ttl: int = 600, kind: str = "msg",
             dnet: str = None) -> "Envelope":
        if len(plaintext) > MAX_PLAINTEXT_BYTES:
            raise BridgeError("TOO_LARGE", "plaintext")
        if not 0 < ttl <= MAX_TTL_SECONDS or iat < 0 or kind not in KINDS:
            raise bad_format("ttl/iat/kind out of range")
        if dnet is not None and (check_id(dnet) == net):
            raise bad_format("dnet: must be another network than net")
        envelope_id = crypto.random_bytes(16)
        nonce = crypto.random_bytes(12)
        epk, shared = crypto.agree_one_time(to_card.box)
        key = _key(shared, epk, to_card.box, envelope_id)
        raw = {"v": 4, "t": "env", "id": b64(envelope_id), "net": net, "from": sender.id, "to": to_card.id,
               "iat": iat, "ttl": ttl, "kind": kind, "epk": b64(epk), "n": b64(nonce)}
        if dnet is not None:
            raw["dnet"] = dnet
        raw["ct"] = b64(crypto.aead_seal(key, nonce, plaintext, canonical(raw)))
        raw["sig"] = b64(sender.sign_canonical("env", canonical(raw)))
        return cls.from_value(raw)

    @classmethod
    def parse(cls, data) -> "Envelope":
        return cls.from_value(parse_strict(data, MAX_ENVELOPE_BYTES))

    @classmethod
    def from_value(cls, value) -> "Envelope":
        if not isinstance(value, dict):
            raise bad_format("envelope: not an object")
        if depth(value) > 8:
            raise bad_format("envelope: nested too deep")
        if value.get("v") != 4 or value.get("t") != "env":
            raise bad_format("envelope: wrong version or type")
        iat, ttl = value.get("iat"), value.get("ttl")
        if not all(isinstance(x, int) and not isinstance(x, bool) for x in (iat, ttl)):
            raise bad_format("iat/ttl")
        if iat < 0 or not 0 < ttl <= MAX_TTL_SECONDS:
            raise bad_format("iat/ttl out of range")
        ciphertext = b64_var(value.get("ct"), "ct", MAX_PLAINTEXT_BYTES + 16)
        if len(ciphertext) < 16:
            raise bad_format("ct: too short")
        net = check_id(value.get("net"))
        if "dnet" in value and check_id(value["dnet"]) == net:
            raise bad_format("dnet: must be another network than net")
        check_id(value.get("from"))
        check_id(value.get("to"))
        if value.get("kind") not in KINDS:
            raise bad_format("kind: unknown")
        b64_fixed(value.get("id"), "id", 16)
        b64_fixed(value.get("epk"), "epk", 32)
        b64_fixed(value.get("n"), "n", 12)
        b64_fixed(value.get("sig"), "sig", 64)
        return cls(dict(value))

    def expires_at(self) -> int:
        return self.iat + self.ttl * 1000

    def check_time(self, now_ms: int) -> None:
        if self.iat > now_ms + CLOCK_SKEW_MS:
            raise BridgeError("NOT_YET_VALID")
        if now_ms >= self.expires_at():
            raise BridgeError("EXPIRED")

    def verify(self, sender_card) -> None:
        if sender_card.id != self.sender:
            raise bad_signature()
        crypto.verify(sender_card.sign, "env", canonical_without(self.raw, ("sig",)), self.signature)

    def open(self, recipient, sender_card) -> bytes:
        """Verifies the sender's signature and decrypts (only the recipient can)."""
        self.verify(sender_card)
        if recipient.id != self.to:
            raise BridgeError("CANNOT_OPEN")
        shared = recipient.agree(self.epk)
        key = _key(shared, self.epk, recipient.box_public, self.id)
        return crypto.aead_open(key, self.nonce, self.ciphertext, canonical_without(self.raw, ("ct", "sig")))

    def to_value(self) -> dict:
        return dict(self.raw)

    def to_bytes(self) -> bytes:
        return canonical(self.raw)
