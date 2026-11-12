"""Proof-of-work puzzles (docs/04 §8): find 8 bytes ``c`` with SHA-256(JCS(puzzle) ‖ c) having ``bits`` leading zeros."""

import hashlib

from . import crypto
from .encoding import b64_fixed
from .errors import bad_format, bad_signature
from .jsonc import canonical, canonical_without
from .keys import check_id

MAX_POW_BITS = 28


class Puzzle:
    def __init__(self, raw: dict):
        if not isinstance(raw, dict) or raw.get("v") != 4 or raw.get("t") != "pow":
            raise bad_format("puzzle: wrong version or type")
        bits = raw.get("bits")
        if not isinstance(bits, int) or isinstance(bits, bool) or not 0 <= bits <= MAX_POW_BITS:
            raise bad_format("bits")
        b64_fixed(raw.get("nonce"), "nonce", 16)
        check_id(raw.get("node"))
        if not isinstance(raw.get("exp"), int):
            raise bad_format("exp")
        self.signature = b64_fixed(raw.get("sig"), "sig", 64)
        self.raw = dict(raw)
        self.bits = bits
        self.node = raw["node"]
        self.canonical = canonical(self.raw)

    def verify(self, node_card) -> None:
        if node_card.id != self.node:
            raise bad_signature()
        crypto.verify(node_card.sign, "pow", canonical_without(self.raw, ("sig",)), self.signature)

    def solve(self, max_tries: int = 1 << 30):
        """The first ``c`` (big endian counter from 0) - or ``None`` within ``max_tries``."""
        prefix = hashlib.sha256(self.canonical)
        for counter in range(max_tries):
            candidate = counter.to_bytes(8, "big")
            digest = prefix.copy()
            digest.update(candidate)
            if crypto.leading_zero_bits(digest.digest()) >= self.bits:
                return candidate
        return None

    def check_solution(self, solution: bytes) -> bool:
        return crypto.leading_zero_bits(crypto.sha256(self.canonical + solution)) >= self.bits
