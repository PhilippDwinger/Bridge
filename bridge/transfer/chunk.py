import sys
import json

from bridge.transfer import protocol


def get_size_dict(obj, seen=None):
    if seen is None:
        seen = set()

    obj_id = id(obj)

    if obj_id in seen:
        return 0

    seen.add(obj_id)
    size = sys.getsizeof(obj)

    if isinstance(obj, dict):
        size += sum(get_size_dict(key, seen) + get_size_dict(value, seen) for key, value in obj.items())
    elif isinstance(obj, (list, tuple, set, frozenset)):
        size += sum(get_size_dict(item, seen) for item in obj)

    return size / 1024

def get_size_string(string: str):
    size_bytes = len(json.dumps(string).encode("utf-8"))
    size_kb = size_bytes / 1024
    return size_kb

def encode_direct(value):
    if isinstance(value, set):
        value = {"__type__": "set", "value": list(value)}
    return json.dumps(value)

def decode_direct(value):
    value = json.loads(value)
    if isinstance(value, dict) and value.get("__type__") == "set":
        return set(value["value"])
    return value

def encode_indirect(value):
    if isinstance(value, set):
        return {"__type__": "set", "value": [encode_indirect(v) for v in value]}
    if isinstance(value, dict):
        return {k: encode_indirect(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode_indirect(v) for v in value]
    return value

def decode_indirect(value):
    if isinstance(value, str):
        value = json.loads(value)
    if isinstance(value, dict):
        if value.get("__type__") == "set":
            return set(decode_indirect(v) for v in value["value"])
        return {k: decode_indirect(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decode_indirect(v) for v in value]
    return value

def split_string(text: str, max_kb: float) -> list[tuple[int, str]]:
    max_bytes = int(max_kb * 1024)
    chunks = []
    current_chunk = ""
    current_size = 0

    for char in text:
        char_size = len(char.encode("utf-8"))

        if current_size + char_size > max_bytes:
            chunks.append((len(chunks), current_chunk))
            current_chunk = ""
            current_size = 0

        current_chunk += char
        current_size += char_size

    if current_chunk:
        chunks.append((len(chunks), current_chunk))

    return chunks

def chunk_string(string: str):
    kb_cap = protocol.get_current_version_data()["max_kb_per_chunk"]
    return split_string(string, kb_cap)