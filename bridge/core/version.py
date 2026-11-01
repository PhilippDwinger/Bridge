"""Which code version this server runs - for rolling upgrades across the mesh.

- protocol_version: the wire/protocol version (bridge/core/protocol.py). Two servers can talk when their MAJOR
  version matches (3.x <-> 3.y), so a mesh can update one server at a time.
- commit: the exact code this server runs. Taken from a VERSION file (written at deploy) if present, otherwise
  from git. "unknown" when neither is available (e.g. a plain copy without .git).
"""
import functools
import os
import subprocess

from bridge.core import protocol

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def protocol_version():
    return protocol.current_protocol.version


@functools.lru_cache(maxsize=1)
def commit():
    version_file = os.path.join(_ROOT, "VERSION")
    try:
        if os.path.isfile(version_file):
            with open(version_file, encoding="utf-8") as handle:
                text = handle.read().strip()
            if text:
                return text[:40]
    except OSError:
        pass
    try:
        result = subprocess.run(["git", "-C", _ROOT, "rev-parse", "--short", "HEAD"],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


def info():
    return {"protocol_version": protocol_version(), "commit": commit()}
