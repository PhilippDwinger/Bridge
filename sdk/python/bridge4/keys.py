"""Identities (secret) and key cards (public, self-signed) - docs/04 §2."""

import os
import re
import tempfile

from . import crypto
from .encoding import b64, b64_fixed, base32
from .errors import BridgeError, bad_format, bad_signature
from .jsonc import canonical, canonical_without, depth, parse_strict

PROTOCOL_VERSION = 4
MAX_KEY_CARD_BYTES = 2048
MAX_NAME_CHARS = 64
MAX_URLS = 4
ROLES = ("client", "node", "net", "admin", "app")
_ID = re.compile(r"^[a-z2-7]{32}$")


def check_id(text) -> str:
    if not isinstance(text, str) or not _ID.match(text):
        raise bad_format("id: expected 32 characters of base32")
    return text


def id_of(sign_public: bytes) -> str:
    return base32(crypto.sha256(sign_public)[:20])


def _authority_ok(authority: str) -> bool:
    port = None
    if authority.startswith("["):
        if "]" not in authority:
            return False
        ip, after = authority[1:].split("]", 1)
        if not ip or ":" not in ip or any(c not in "0123456789abcdefABCDEF:." for c in ip):
            return False
        try:
            import ipaddress

            ipaddress.IPv6Address(ip)
        except ValueError:
            return False
        if after:
            if not after.startswith(":"):
                return False
            port = after[1:]
    else:
        host, _, rest = authority.partition(":")
        if ":" in authority:
            port = rest
        labels = host.split(".")
        if not host or any(
            not label or any(not (c.isascii() and (c.isalnum() or c in "-_")) for c in label) for label in labels
        ):
            return False
    if port is not None:
        if not port or len(port) > 5 or not port.isascii() or not port.isdigit() or not 0 < int(port) <= 65535:
            return False
    return True


def check_url(url) -> str:
    """One rule for every address (docs/06 §2): ``http(s)://host[:port][/path]``, at most 200 characters."""
    ok = isinstance(url, str) and len(url) <= 200
    if ok:
        rest = url[8:] if url.startswith("https://") else url[7:] if url.startswith("http://") else None
        ok = rest is not None
        if ok:
            slash = rest.find("/")
            authority, path = (rest, "") if slash < 0 else (rest[:slash], rest[slash:])
            ok = _authority_ok(authority) and (
                path == ""
                or (
                    path.startswith("/")
                    and all(c.isascii() and (c.isalnum() or c in "/-._~") for c in path)
                    and all(segment not in (".", "..") for segment in path.split("/"))
                )
            )
    if not ok:
        raise bad_format("url: expected http(s)://host[:port][/path]")
    return url


class KeyCard:
    """A verified key card. Construct with :meth:`parse` / :meth:`from_value` (always checked)."""

    def __init__(self, raw: dict):
        self.raw = raw
        self.id = raw["id"]
        self.sign = b64_fixed(raw["sign"], "sign", 32)
        self.box = b64_fixed(raw["box"], "box", 32)
        self.role = raw["role"]
        self.urls = list(raw.get("urls", []))

    @classmethod
    def parse(cls, data) -> "KeyCard":
        return cls.from_value(parse_strict(data, MAX_KEY_CARD_BYTES))

    @classmethod
    def from_value(cls, value) -> "KeyCard":
        if not isinstance(value, dict):
            raise bad_format("key card: not an object")
        if depth(value) > 4 or len(canonical(value)) > MAX_KEY_CARD_BYTES:
            raise BridgeError("TOO_LARGE", "key card")
        if value.get("v") != PROTOCOL_VERSION or value.get("t") != "key":
            raise bad_format("key card: wrong version or type")
        check_id(value.get("id"))
        sign = b64_fixed(value.get("sign"), "sign", 32)
        b64_fixed(value.get("box"), "box", 32)
        if value.get("role") not in ROLES:
            raise bad_format("role: unknown")
        if "name" in value:
            name = value["name"]
            if not isinstance(name, str) or len(name) > MAX_NAME_CHARS:
                raise bad_format("name: too long or not a string")
        iat = value.get("iat")
        if not isinstance(iat, int) or isinstance(iat, bool) or iat < 0:
            raise bad_format("iat")
        urls = value.get("urls")
        if urls is not None:
            if not isinstance(urls, list) or not 1 <= len(urls) <= MAX_URLS or len(set(map(str, urls))) != len(urls):
                raise bad_format("urls: 1..=4 distinct addresses")
            for url in urls:
                check_url(url)
        if "tls" in value:
            b64_fixed(value["tls"], "tls", 32)
        if (urls is not None or "tls" in value) and value["role"] != "node":
            raise bad_format("urls/tls: only on node cards")
        signature = b64_fixed(value.get("sig"), "sig", 64)
        if id_of(sign) != value["id"]:
            raise bad_signature()
        crypto.verify(sign, "key", canonical_without(value, ("sig",)), signature)
        return cls(dict(value))

    def to_value(self) -> dict:
        return dict(self.raw)

    def to_bytes(self) -> bytes:
        return canonical(self.raw)

    def __eq__(self, other):
        return isinstance(other, KeyCard) and self.to_bytes() == other.to_bytes()

    def __repr__(self):
        return f"KeyCard({self.id}, {self.role})"


class Identity:
    """A secret identity: Ed25519 for signing, X25519 for receiving. Never print or log the secrets."""

    def __init__(self, sign_secret: bytes, box_secret: bytes):
        if len(sign_secret) != 32 or len(box_secret) != 32:
            raise bad_format("secrets are 32 bytes")
        self._sign = bytes(sign_secret)
        self._box = bytes(box_secret)
        self.sign_public = crypto.sign_public(self._sign)
        self.box_public = crypto.box_public(self._box)
        self.id = id_of(self.sign_public)

    @classmethod
    def generate(cls) -> "Identity":
        return cls(crypto.random_bytes(32), crypto.random_bytes(32))

    @classmethod
    def load(cls, path: str) -> "Identity":
        """Loads a key file ``{"v":4,"t":"secret","sign","box"}`` (the node's format)."""
        with open(path, "rb") as file:
            value = parse_strict(file.read(4096), 1024)
        if not isinstance(value, dict) or value.get("v") != 4 or value.get("t") != "secret":
            raise bad_format("key file: wrong form")
        return cls(b64_fixed(value.get("sign"), "sign", 32), b64_fixed(value.get("box"), "box", 32))

    @classmethod
    def load_or_create(cls, path: str) -> "Identity":
        """Loads ``path``, or creates a new identity there (readable by the owner only). A damaged file is an error."""
        if os.path.exists(path):
            return cls.load(path)
        identity = cls.generate()
        identity.save(path)
        return identity

    def save(self, path: str) -> None:
        """Writes the key file (new files only; owner-only on Unix). Whoever has it *is* this identity."""
        data = canonical({"v": 4, "t": "secret", "sign": b64(self._sign), "box": b64(self._box)})
        folder = os.path.dirname(os.path.abspath(path))
        handle, temporary = tempfile.mkstemp(dir=folder, prefix=".bridge4-key-")
        try:
            with os.fdopen(handle, "wb") as file:
                file.write(data)
            if os.name == "posix":
                os.chmod(temporary, 0o600)
            if os.path.exists(path):
                raise BridgeError("EXISTS", f"{path} exists - not overwritten")
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.remove(temporary)

    def key_card(self, role: str = "client", name=None, iat: int = 0, urls=None, tls=None) -> KeyCard:
        if role not in ROLES:
            raise bad_format("role: unknown")
        card = {"v": 4, "t": "key", "id": self.id, "sign": b64(self.sign_public), "box": b64(self.box_public),
                "role": role, "iat": iat}
        if name is not None:
            card["name"] = name
        if urls:
            card["urls"] = list(urls)
        if tls is not None:
            card["tls"] = b64(tls)
        card["sig"] = b64(self.sign_canonical("key", canonical(card)))
        return KeyCard.from_value(card)

    def sign_canonical(self, domain: str, data: bytes) -> bytes:
        return crypto.sign(self._sign, domain, data)

    def agree(self, peer: bytes) -> bytes:
        return crypto.agree_static(self._box, peer)

    def secret_bytes(self):
        """(sign secret, box secret) - handle with care."""
        return self._sign, self._box

    def __repr__(self):
        return f"Identity({self.id})"
