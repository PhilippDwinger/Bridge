"""All cryptographic primitives of the SDK in one place (docs/02 §4, rule Z10: only the reviewed ``cryptography``
library): Ed25519 with domain separation and strict checks, X25519 (no all-zero results), HKDF-SHA256,
ChaCha20-Poly1305, SHA-256. Other modules never touch the library directly."""

import hashlib
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import BridgeError, bad_signature

# Order of the Ed25519 base point.
_L = 2**252 + 27742317777372353535851937790883648493


def _weak_encodings():
    """The 14 encodings of the 8 points of small order (7 values, sign bit clear and set)."""
    values = [
        bytes(32),
        bytes([1]) + bytes(31),
        bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    ]
    for low in (0xEC, 0xED, 0xEE):
        values.append(bytes([low]) + b"\xff" * 30 + b"\x7f")
    out = set()
    for value in values:
        out.add(value)
        out.add(value[:31] + bytes([value[31] | 0x80]))
    return frozenset(out)


WEAK_KEYS = _weak_encodings()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def random_bytes(size: int) -> bytes:
    return os.urandom(size)


def _domain(domain: str, message: bytes) -> bytes:
    return b"bridge4/" + domain.encode("ascii") + b"\n" + message


def sign_public(sign_secret: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(sign_secret).public_key().public_bytes_raw()


def box_public(box_secret: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(box_secret).public_key().public_bytes_raw()


def sign(sign_secret: bytes, domain: str, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(sign_secret).sign(_domain(domain, message))


def verify(public: bytes, domain: str, message: bytes, signature: bytes) -> None:
    """Strict verification like the core: weak (small-order) keys and R values, and non-canonical S, are refused."""
    if len(public) != 32 or len(signature) != 64:
        raise bad_signature()
    if public in WEAK_KEYS or signature[:32] in WEAK_KEYS:
        raise bad_signature()
    if int.from_bytes(signature[32:], "little") >= _L:
        raise bad_signature()
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, _domain(domain, message))
    except (InvalidSignature, ValueError):
        raise bad_signature() from None


def _agree(secret: X25519PrivateKey, peer: bytes) -> bytes:
    try:
        shared = secret.exchange(X25519PublicKey.from_public_bytes(peer))
    except ValueError:
        raise BridgeError("CANNOT_OPEN") from None
    if shared == bytes(32):
        raise BridgeError("CANNOT_OPEN")
    return shared


def agree_one_time(peer: bytes):
    """A new one-time key pair (N1: only made here) agreed with ``peer``: (one-time public key, shared secret)."""
    secret = X25519PrivateKey.generate()
    return secret.public_key().public_bytes_raw(), _agree(secret, peer)


def agree_static(box_secret: bytes, peer: bytes) -> bytes:
    return _agree(X25519PrivateKey.from_private_bytes(box_secret), peer)


def derive_key(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def aead_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise BridgeError("CANNOT_OPEN") from None


def leading_zero_bits(digest: bytes) -> int:
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        return bits + (8 - byte.bit_length())
    return bits
