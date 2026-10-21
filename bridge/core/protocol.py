from dataclasses import dataclass

debug = True
debug_warnings = True

@dataclass(frozen=True)
class ProtocolVersion:
    version: str
    chunk_size_kib: int

protocol_3_0 = ProtocolVersion(
    version="3.0",
    chunk_size_kib=4
)

current_protocol = protocol_3_0