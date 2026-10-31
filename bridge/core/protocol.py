from dataclasses import dataclass

# region debug
debug = True
debug_warnings = True
# endregion debug

# region wire protocol
@dataclass(frozen=True)
class ProtocolVersion:
    version: str
    # Size of one chunk when a "safe" message is fetched in parts
    chunk_size_kib: int
    # "fast" messages are delivered in one piece, so they are kept small
    max_fast_message_kib: int
    # Upper limit for "safe" messages (sent in chunks)
    max_safe_message_kib: int

protocol_3_0 = ProtocolVersion(
    version="3.0",
    chunk_size_kib=4,
    max_fast_message_kib=64,
    max_safe_message_kib=1024,
)

current_protocol = protocol_3_0
# endregion wire protocol

# region server limits (not part of the wire protocol)
session_lifetime_minutes = 60
message_lifetime_minutes = 10
# How long the host of a command has to answer the task
command_response_minutes = 60

# Registration limits
max_clients = 10_000
# Per caller address (host of the HTTP request)
max_registrations_per_host = 30
registration_window_minutes = 60
# When the server is full, clients without any request for this long are removed to make room
inactive_client_days = 7

# Invitation codes for realms
code_length = 8
# No 0/O, 1/I/L - easy to read and type
code_alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
default_code_minutes = 60

# Brute force protection for login, admin password, access keys and codes
max_failed_attempts = 5
lock_minutes = 5
# Wrong access keys/codes from all clients of one other server together
max_failed_attempts_per_server = 50

# Server to server communication
s2s_timeout_seconds = 5
# Keep True in production. Set to False only for local tests with self-signed certificates.
s2s_verify_tls = True
# endregion server limits
