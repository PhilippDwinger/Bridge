"""Join links (docs/06 §7): ``bridge4://join?net=<id>&gw=<url>&code=<code>&node=<id>&tls=<pin>``."""

import re

from .encoding import b64_fixed
from .errors import BridgeError, bad_format
from .keys import check_id, check_url

PREFIX = "bridge4://join?"
MAX_LINK_CHARS = 1024
_CODE = re.compile(r"^[A-Za-z0-9-]{4,64}$")


def _decode(text: str) -> str:
    out = bytearray()
    index = 0
    data = text.encode("utf-8")
    while index < len(data):
        if data[index] == ord("%"):
            hexpart = data[index + 1:index + 3]
            if len(hexpart) != 2 or not all(chr(c) in "0123456789abcdefABCDEF" for c in hexpart):
                raise bad_format("join link: bad % escape")
            out.append(int(hexpart, 16))
            index += 3
        else:
            out.append(data[index])
            index += 1
    if not all(0x21 <= byte <= 0x7E for byte in out):
        raise bad_format("join link: only printable ASCII")
    return out.decode("ascii")


class JoinLink:
    def __init__(self, net, gateway, code=None, node=None, tls=None):
        self.net, self.gateway, self.code, self.node, self.tls = net, gateway, code, node, tls

    @classmethod
    def parse(cls, text: str) -> "JoinLink":
        if len(text) > MAX_LINK_CHARS:
            raise BridgeError("TOO_LARGE", "join link")
        text = text.strip()
        if not text.startswith(PREFIX):
            raise bad_format(f"join link: must start with {PREFIX}")
        found = {}
        for count, pair in enumerate(text[len(PREFIX):].split("&")):
            if count >= 8:
                raise bad_format("join link: too many parameters")
            if "=" not in pair:
                raise bad_format("join link: key=value")
            key, value = pair.split("=", 1)
            if key not in ("net", "gw", "code", "node", "tls"):
                continue
            if key in found:
                raise bad_format(f"join link: {key} twice")
            found[key] = _decode(value)
        if "net" not in found or "gw" not in found:
            raise bad_format("join link: net and gw needed")
        net = check_id(found["net"])
        gateway = check_url(found["gw"])
        code = found.get("code")
        if code is not None and not _CODE.match(code):
            raise bad_format("code: 4-64 characters of A-Z, a-z, 0-9 and -")
        node = found.get("node")
        if node is not None:
            check_id(node)
            if node == net:
                raise bad_format("join link: node is the network key, not a gateway")
        tls = b64_fixed(found["tls"], "join link: tls", 32) if "tls" in found else None
        if tls is not None and node is None:
            raise bad_format("join link: tls needs node")
        return cls(net, gateway, code, node, tls)
