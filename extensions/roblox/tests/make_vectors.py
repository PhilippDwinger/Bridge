"""Test vectors for test_units.luau (SHA-256, Base64, zlib) made with Python's own libraries."""
import base64
import hashlib
import json
import random
import sys
import zlib

random.seed(7)
texts = ["", "abc", "a" * 55, "a" * 56, "a" * 64, "a" * 119, "Grüße 🚀 ü€",
         json.dumps({"players": [{"u": i, "n": "Player%d" % i, "p": [i * 1.5, 3, 4]} for i in range(200)]}),
         "".join(random.choice("abcdefghij ") for _ in range(70000)),
         bytes(random.getrandbits(8) for _ in range(5000)).hex()]
cases = []
for text in texts:
    raw = text.encode("utf-8")
    for level in (0, 1, 6, 9):
        cases.append({"text_b64": base64.b64encode(raw).decode(), "sha256": hashlib.sha256(raw).hexdigest(),
                      "zlib_b64": base64.b64encode(zlib.compress(raw, level)).decode(), "level": level})
with open(sys.argv[1] if len(sys.argv) > 1 else "vectors.json", "w", encoding="utf-8") as handle:
    json.dump(cases, handle)
print(f"{len(cases)} vectors")
