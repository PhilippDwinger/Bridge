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

def compatible(peer_version):
    """Two servers can talk when they share the same MAJOR protocol version (3.x <-> 3.y). A server that sends no
    version (older build) is treated as compatible, so a rolling upgrade never breaks an existing mesh."""
    if not isinstance(peer_version, str) or not peer_version:
        return True
    return peer_version.split(".")[0] == current_protocol.version.split(".")[0]

# Behind a TLS proxy (e.g. nginx on an Oracle VM, or a platform like Render): read X-Forwarded-For so the rate
# limits see the real client address instead of the proxy. Set via BRIDGE_TRUST_PROXY. Only turn this on when a
# trusted proxy sits in front - otherwise clients could fake their address.
trust_proxy = False
# endregion wire protocol

# region server limits (not part of the wire protocol)
session_lifetime_minutes = 60
# A client keeps at most this many login sessions - a new login drops its oldest one
max_sessions_per_client = 20
message_lifetime_minutes = 10
# A message can get its own lifetime (expires_in_seconds / expires_at, mode "temporary") up to this long
max_message_lifetime_minutes = 7 * 24 * 60
# Mode "compressed": size of the original JSON / of the compressed data that is transferred
max_compressed_original_kib = 8 * 1024
# Conversations (streams like in Wireshark): "all" (every conversation, metadata only) | "started" | "off"
conversation_mode = "all"
max_conversations = 20_000
max_conversation_entries = 500
max_conversation_content_kib = 2048
conversation_idle_hours = 24

# Scheduled messages (send_in_seconds / send_at)
max_schedule_days = 30
max_scheduled_per_client = 1000
max_broadcast_recipients = 100
# Planned messages wait in RAM - byte budget per client and in total
max_scheduled_mb_per_client = 64
max_scheduled_mb_total = 1024
# Limits so one client cannot fill the server
max_realms_per_owner = 50
max_codes_per_realm = 500
max_access_keys_per_realm = 500
max_commands_per_realm = 1000
max_commands_per_host_per_realm = 50
max_signature_kib = 8
max_conversations_per_client = 500
max_conversation_content_total_mb = 256
# Byte budget of a mailbox (contents count, not only the number of messages) and of one sender in it
max_mailbox_mb = 64
max_mailbox_mb_per_sender = 16
# How long the host of a command has to answer the task
command_response_minutes = 60
# Open tasks per client: called and not answered yet / received and not answered yet
max_open_tasks_per_client = 1000

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
# One caller address can share many clients (e.g. behind NAT or a reverse proxy), so it may fail this many times
# more often than a single account before it is locked - and any successful login from it clears that counter again.
login_host_attempt_multiplier = 12

# Pull only: Bridge never sends anything to a client by itself. A client can ask and wait up to
# this long for something to arrive (long polling) - it is still the client's request.
max_wait_seconds = 25
# One poll can take several one-piece messages at once ("max_messages"), so clients with a request budget
# (e.g. Roblox game servers: 500 HTTP requests per minute) still keep up with many small events.
max_poll_messages = 100
# A poll can carry topic publishes ("publish"), done before it looks into the mailbox: a client with a request budget
# sends its newest state and gets the others' in ONE request (e.g. a Roblox game syncing players many times a second)
max_poll_publishes = 10

# Commands: hosts without any request for this long are only used if no active host exists
host_inactive_seconds = 120

# Progress of long tasks (only if the caller accepted it): size, rate per task, how many wait per task (mode "all")
max_progress_kib = 4
max_progress_per_second = 5
max_progress_waiting_per_task = 50

# Message status (/message/status) is kept this long
message_status_minutes = 60
max_message_status_entries = 100_000

# Topics (publish/subscribe in realms)
max_topic_subscribers = 1000
max_topics_per_realm = 200

# Relaying direct messages over one other trusted server: "off" | "trusted"
relay_mode = "trusted"
# Accept direct messages that came over another server
accept_relayed = True

# Encrypted backup of everything in RAM at trusted servers: "peers" | "off"
backup_mode = "peers"
backup_interval_seconds = 30
# After a start, wait this long for trusted servers to look for an own backup
backup_restore_wait_seconds = 15
max_backup_mb = 50
# Backups of other servers we keep
stored_backup_hours = 24
max_stored_backups = 20
# On a normal stop: open requests (e.g. long polls) get this long, then the last backup is sent
shutdown_grace_seconds = 3

# Realm sync: servers with members keep a copy of the realm and compare versions this often
realm_sync_seconds = 15
# Changes within this time are sent together (e.g. many joins at once)
realm_push_delay_seconds = 0.2
# A copy that could not be compared for this long is shown as stale
realm_stale_seconds = 45

# BridgeAgent: "learn" (estimate + learn) | "frozen" (estimate, do not learn) | "off"
agent_mode = "learn"
# Way of direct messages to other servers: "direct" (as always) | "agent" (best way, around broken/slow lines)
routing = "direct"
# How often servers exchange their line tables
link_exchange_seconds = 15

# BridgeFriends: "open" (own, trusted and neutral servers) | "trusted" (own + trusted) | "local" (own server) | "off"
friends_mode = "open"
max_friends_per_client = 500
max_friend_invites_per_client = 20
# A code invitation (random 8 characters) lives this long by default; a name lives until it is deleted
friend_code_default_minutes = 60
# Wrong passwords per invitation: per asking client / per asking server (in friend_attempt_window_minutes),
# and in total per hour (then the invitation is locked for an hour)
friend_attempts_per_client = 5
friend_attempts_per_server = 20
friend_attempts_total_per_hour = 100
friend_attempt_window_minutes = 15
# Friend requests (/friends/add) per client and minute
friend_requests_per_minute = 10
# How long the status of the friends of one server is kept before it is asked again
friend_status_cache_seconds = 3
# Handshakes for friend connections with neutral servers (protection against abuse)
friend_link_handshakes_per_minute = 30
max_friend_links = 1000
# Friend connections to private / local addresses: None = only if this server itself runs on such an address
friends_allow_private_addresses = None

# Server to server communication
s2s_timeout_seconds = 5
# Keep True in production. Set to False only for local tests with self-signed certificates.
s2s_verify_tls = True
# endregion server limits
