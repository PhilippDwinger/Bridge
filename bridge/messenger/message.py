import base64
import datetime
import json
import zlib
from enum import StrEnum

from bridge import errors
from bridge.core import address, protocol
from bridge.core.jsoncheck import json_problem
from bridge.errors.exceptions import Exceptions
from bridge.messenger.mailbox import PoolName
from bridge.security.generator import generate_key
from bridge.security.hasher import sha256_hex
from bridge.transfer import chunking


class MessageMode(StrEnum):
    # Delivered in one piece and deleted as soon as it is polled. No hash, no retry. Small messages only.
    FAST = "fast"
    # Delivered in chunks. Only deleted after the recipient confirmed the SHA-256 hash of the complete message.
    SAFE = "safe"
    # Like safe, but the chunks carry the content compressed (zlib level 9 + Base64): much less data to transfer.
    # The hash is over the original JSON - after unpacking it is exactly the same.
    COMPRESSED = "compressed"
    # Like fast, but with its own lifetime (expires_in_seconds / expires_at, required). When the time is over the
    # message is deleted from the mailbox, even if nobody fetched it.
    TEMPORARY = "temporary"


# One piece: poll returns the content directly. Chunked: pending_id + chunks + hash + complete.
ONE_PIECE_MODES = (MessageMode.FAST, MessageMode.TEMPORARY)
CHUNKED_MODES = (MessageMode.SAFE, MessageMode.COMPRESSED)
ENCODING_ZLIB = "zlib+base64"
ENCODING_IDENTITY = "identity"


class ContentType(StrEnum):
    # Verified: only created by Bridge itself after a realm check (command call)
    TASK = "task"
    # Verified: only the host that received the task can answer it, and only to the caller
    RESPONSE = "response"
    # Verified: an intermediate state of a task from its host - only if the caller accepted progress
    PROGRESS = "progress"
    # Verified: reserved for the server itself
    INSTRUCTION = "instruction"
    # Verified: published to a topic of a realm by an allowed member, delivered to all subscribers
    EVENT = "event"
    # NOT verified: any client can send a direct message to any client. The receiver decides what to trust.
    DIRECT = "direct"
    # Verified: a message between two friends (BridgeFriends). Both servers checked the friendship, and that the sender
    # really is a client of the server that delivered it.
    FRIEND = "friend"


POOL_BY_CONTENT_TYPE = {
    ContentType.TASK: PoolName.TASK,
    ContentType.RESPONSE: PoolName.RESPONSE,
    ContentType.PROGRESS: PoolName.PROGRESS,
    ContentType.INSTRUCTION: PoolName.INSTRUCTION,
    ContentType.DIRECT: PoolName.DIRECT,
    ContentType.EVENT: PoolName.EVENT,
    ContentType.FRIEND: PoolName.FRIEND,
}

VERIFIED_CONTENT_TYPES = (ContentType.TASK, ContentType.RESPONSE, ContentType.PROGRESS, ContentType.INSTRUCTION,
                          ContentType.EVENT, ContentType.FRIEND)
MAX_RELAY_HOPS = 1

MAX_ID_LENGTH = 128


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


class Message:
    def __init__(
            self,
            sender_ip,
            recipient_ip,
            payload : str,
            content_type = ContentType.DIRECT,
            mode = MessageMode.SAFE,
            conversation_id = None,
            causation_id = None,
            message_id = None,
            created_at = None,
            expires_at = None,
            protocol_version = None,
            relayed_via = None,
            broadcast_id = None,
    ):
        # Use create_message() / message_from_dict() - they validate the input before calling this
        now = _now()
        self.message_id = message_id or generate_key(16)
        self.conversation_id = conversation_id or generate_key(16)
        self.causation_id = causation_id
        self.sender_ip = sender_ip
        self.recipient_ip = recipient_ip
        self.content_type = ContentType(content_type)
        self.mode = MessageMode(mode)
        # The content as JSON text. The hash and the chunks are built from this exact text.
        self.payload = payload
        self.size_bytes = len(payload.encode("utf-8"))
        self.sha256 = sha256_hex(payload)
        self.created_at = created_at or now
        self.expires_at = expires_at or now + datetime.timedelta(minutes=protocol.message_lifetime_minutes)
        self.protocol_version = protocol_version or protocol.current_protocol.version
        # Servers that passed this message on (only direct messages can be relayed)
        self.relayed_via = list(relayed_via or [])
        # Set when the message is one of the copies of a broadcast (all copies have the same broadcast_id)
        self.broadcast_id = broadcast_id
        self._chunks = None
        self._transport = None

    def __str__(self):
        return str(self.metadata())
    def __repr__(self):
        return str(self.metadata())

    @property
    def pool_name(self):
        return POOL_BY_CONTENT_TYPE[self.content_type]

    @property
    def verified(self):
        return self.content_type in VERIFIED_CONTENT_TYPES

    def is_expired(self):
        return _now() >= self.expires_at

    def get_content(self):
        return json.loads(self.payload)

    def transport(self):
        """(encoding, text) that goes over the wire. Compressed mode: zlib + Base64 if that is smaller."""
        if self._transport is None:
            self._transport = pack_payload(self.payload) if self.mode == MessageMode.COMPRESSED else (ENCODING_IDENTITY, self.payload)
        return self._transport

    def transport_size(self):
        """Bytes of what goes over the wire (UTF-8) - also for compressed data that did not get smaller."""
        encoding, text = self.transport()
        return len(text) if encoding == ENCODING_ZLIB else self.size_bytes

    def get_chunks(self):
        if self._chunks is None:
            self._chunks = chunking.split_text(self.transport()[1], protocol.current_protocol.chunk_size_kib * 1024)
        return self._chunks

    def metadata(self):
        data = {
            "message_id": self.message_id,
            "conversation_id": self.conversation_id,
            "causation_id": self.causation_id,
            "sender_ip": self.sender_ip,
            "recipient_ip": self.recipient_ip,
            "content_type": str(self.content_type),
            "verified": self.verified,
            "mode": str(self.mode),
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "protocol_version": self.protocol_version,
            "relayed_via": list(self.relayed_via),
        }
        if self.broadcast_id:
            data["broadcast_id"] = self.broadcast_id
        if self.mode in CHUNKED_MODES:
            data["chunk_count"] = len(self.get_chunks())
        if self.mode == MessageMode.COMPRESSED:
            data["encoding"] = self.transport()[0]
            data["transport_size_bytes"] = self.transport_size()
        return data

    def to_dict(self):
        # Full message incl. payload - used to forward a message to another Bridge server
        data = self.metadata()
        for key in ("chunk_count", "verified", "encoding", "transport_size_bytes"):
            data.pop(key, None)
        encoding, text = self.transport()
        if encoding == ENCODING_ZLIB:
            # Compressed messages also travel compressed between servers
            data["payload_zlib"] = text
        else:
            data["payload"] = self.payload
        return data


def pack_payload(payload):
    """(encoding, text) for compressed mode. Level 6: almost as small as 9, but many times faster on bad data.
    Big contents should be packed with asyncio.to_thread(pack_payload, ...) so the server does not stop meanwhile."""
    packed = base64.b64encode(zlib.compress(payload.encode("utf-8"), 6)).decode("ascii")
    if len(packed) < len(payload.encode("utf-8")):
        return ENCODING_ZLIB, packed
    # Tiny or random data does not get smaller - then it is sent as it is
    return ENCODING_IDENTITY, payload


# region validation helpers
def _parse_enum(enum_type, value, field_name):
    try:
        return enum_type(value)
    except ValueError:
        allowed = ", ".join(item.value for item in enum_type)
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'{field_name}' must be one of: {allowed} (got {value!r})")
        return None

def _valid_optional_id(value, field_name):
    if value is None:
        return True
    if isinstance(value, str) and 0 < len(value) <= MAX_ID_LENGTH:
        return True
    errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'{field_name}' must be a string with 1-{MAX_ID_LENGTH} characters")
    return False

def get_size_limit_bytes(mode):
    if mode in ONE_PIECE_MODES:
        return protocol.current_protocol.max_fast_message_kib * 1024
    if mode == MessageMode.COMPRESSED:
        # The original may be bigger - what counts for the transfer is checked after compressing
        return protocol.max_compressed_original_kib * 1024
    return protocol.current_protocol.max_safe_message_kib * 1024

def _check_transport(message):
    if message.mode == MessageMode.COMPRESSED:
        size = message.transport_size()
        limit = protocol.current_protocol.max_safe_message_kib * 1024
        if size > limit:
            errors.handle_error(Exceptions.MESSAGE_TOO_LARGE, f"Compressed still {size} bytes, limit {limit} bytes")
            return Exceptions.MESSAGE_TOO_LARGE
    return None

def check_lifetime(mode, expires_at, starts_at=None):
    """Own lifetime of a message: required for temporary, at most max_message_lifetime_minutes."""
    starts_at = starts_at or _now()
    if expires_at is None:
        if mode == MessageMode.TEMPORARY:
            errors.handle_error(Exceptions.ARGUMENT_ERROR, "Mode temporary needs expires_in_seconds or expires_at")
            errors.set_client_details(problems=["mode temporary needs 'expires_in_seconds' or 'expires_at'"])
            return Exceptions.ARGUMENT_ERROR
        return None
    if expires_at <= starts_at:
        late = (starts_at - expires_at).total_seconds()
        errors.handle_error(Exceptions.ALREADY_EXPIRED, f"expires {late:.1f} s before it would be sent")
        errors.set_client_details(problems=[f"the lifetime ends {late:.1f} s before the message would be sent"],
                                  expires_at=expires_at.isoformat(), send_at=starts_at.isoformat())
        return Exceptions.ALREADY_EXPIRED
    if expires_at - starts_at > datetime.timedelta(minutes=protocol.max_message_lifetime_minutes):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "Lifetime too long")
        errors.set_client_details(problems=[f"a message can live at most {protocol.max_message_lifetime_minutes} minutes"])
        return Exceptions.ARGUMENT_ERROR
    return None

def encode_content(content):
    problem = json_problem(content)
    if problem:
        # Too deep nesting would break the answer to the recipient later (and the message would be lost then)
        errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, f"Content: {problem}")
        errors.set_client_details(problems=[f"content: {problem}"])
        return Exceptions.CLIENT_PAYLOAD_ERROR
    try:
        # allow_nan=False: NaN / Infinity are not JSON - they would break the answer to the recipient later
        payload = json.dumps(content, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        payload.encode("utf-8")  # broken unicode (lone surrogates) would break it too
        return payload
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as error:
        errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, f"Content is not valid JSON: {error}")
        errors.set_client_details(problems=["content must be valid JSON (no NaN / Infinity, no broken unicode)"])
        return Exceptions.CLIENT_PAYLOAD_ERROR

def _check_common(sender_ip, recipient_ip, payload, mode, conversation_id, causation_id):
    if not address.is_valid_address(sender_ip):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Invalid sender IP: {sender_ip!r}")
        return Exceptions.ARGUMENT_ERROR
    if not address.is_valid_address(recipient_ip):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Invalid recipient IP: {recipient_ip!r}")
        return Exceptions.ARGUMENT_ERROR
    if not _valid_optional_id(conversation_id, "conversation_id") or not _valid_optional_id(causation_id, "causation_id"):
        return Exceptions.ARGUMENT_ERROR
    size_bytes = len(payload.encode("utf-8"))
    limit_bytes = get_size_limit_bytes(mode)
    if size_bytes > limit_bytes:
        errors.handle_error(
            Exceptions.MESSAGE_TOO_LARGE,
            f"{size_bytes} bytes, limit for mode '{mode}' is {limit_bytes} bytes"
        )
        return Exceptions.MESSAGE_TOO_LARGE
    return None
# endregion validation helpers


def create_message(sender_ip, recipient_ip, content, content_type=ContentType.DIRECT, mode=MessageMode.SAFE,
                   conversation_id=None, causation_id=None, expires_at=None, message_id=None, starts_at=None,
                   payload=None, transport=None):
    """starts_at: when the message will be sent (scheduled messages) - the lifetime is checked against it.
    payload / transport: already encoded / packed content (the same for every copy of a broadcast)."""
    content_type = _parse_enum(ContentType, content_type, "content_type")
    mode = _parse_enum(MessageMode, mode, "mode")
    if content_type is None or mode is None:
        return Exceptions.ARGUMENT_ERROR
    problem = check_lifetime(mode, expires_at, starts_at)
    if problem is not None:
        return problem
    if payload is None:
        payload = encode_content(content)
        if not isinstance(payload, str):
            return payload
    problem = _check_common(sender_ip, recipient_ip, payload, mode, conversation_id, causation_id)
    if problem is not None:
        return problem
    message = Message(
        sender_ip,
        recipient_ip,
        payload,
        content_type=content_type,
        mode=mode,
        conversation_id=conversation_id,
        causation_id=causation_id,
        expires_at=expires_at,
        message_id=message_id,
    )
    if transport is not None and mode == MessageMode.COMPRESSED:
        message._transport = transport
    problem = _check_transport(message)
    return problem if problem is not None else message


def _unpack(text):
    """Base64 + zlib -> text, with a limit so nobody can send a "zip bomb"."""
    try:
        packed = base64.b64decode(text, validate=True)
        inflater = zlib.decompressobj()
        limit = protocol.max_compressed_original_kib * 1024
        raw = inflater.decompress(packed, limit + 1)
        if len(raw) > limit or inflater.unconsumed_tail:
            return None
        return raw.decode("utf-8")
    except (ValueError, zlib.error, UnicodeDecodeError):
        return None


def message_from_dict(data):
    """Rebuilds a message that another Bridge server forwarded. Everything is checked again."""
    if not isinstance(data, dict):
        errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, "Forwarded message must be an object")
        return Exceptions.CLIENT_PAYLOAD_ERROR
    payload = data.get("payload")
    packed = None
    if payload is None and isinstance(data.get("payload_zlib"), str):
        packed = data["payload_zlib"]
        payload = _unpack(packed)
        if payload is None:
            errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, "Forwarded compressed payload is broken or too big")
            return Exceptions.CLIENT_PAYLOAD_ERROR
    if not isinstance(payload, str):
        errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, "Forwarded message has no payload")
        return Exceptions.CLIENT_PAYLOAD_ERROR
    content_type = _parse_enum(ContentType, data.get("content_type"), "content_type")
    mode = _parse_enum(MessageMode, data.get("mode"), "mode")
    if content_type is None or mode is None:
        return Exceptions.ARGUMENT_ERROR
    message_id = data.get("message_id")
    if message_id is None or not _valid_optional_id(message_id, "message_id"):
        return Exceptions.ARGUMENT_ERROR
    relayed_via = data.get("relayed_via") or []
    if (not isinstance(relayed_via, list) or len(relayed_via) > MAX_RELAY_HOPS
            or any(address.normalize_url(url) != url for url in relayed_via)):
        errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, "Invalid relayed_via")
        return Exceptions.CLIENT_PAYLOAD_ERROR
    problem = _check_common(
        data.get("sender_ip"), data.get("recipient_ip"), payload, mode,
        data.get("conversation_id"), data.get("causation_id"),
    )
    if problem is not None:
        return problem
    try:
        content_problem = json_problem(json.loads(payload))
        created_at = datetime.datetime.fromisoformat(data["created_at"])
        expires_at = datetime.datetime.fromisoformat(data["expires_at"])
    except (KeyError, TypeError, ValueError, RecursionError) as error:
        errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, f"Forwarded message is malformed: {type(error).__name__}")
        return Exceptions.CLIENT_PAYLOAD_ERROR
    if content_problem:
        errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, f"Forwarded message content: {content_problem}")
        return Exceptions.CLIENT_PAYLOAD_ERROR
    if created_at.tzinfo is None or expires_at.tzinfo is None:
        errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, "Forwarded message timestamps need a timezone")
        return Exceptions.CLIENT_PAYLOAD_ERROR
    # The other server cannot extend the lifetime beyond our own limit
    max_expires_at = _now() + datetime.timedelta(minutes=protocol.max_message_lifetime_minutes)
    expires_at = min(expires_at, max_expires_at)

    message = Message(
        data["sender_ip"],
        data["recipient_ip"],
        payload,
        content_type=content_type,
        mode=mode,
        conversation_id=data.get("conversation_id"),
        causation_id=data.get("causation_id"),
        message_id=message_id,
        created_at=created_at,
        expires_at=expires_at,
        protocol_version=str(data.get("protocol_version") or protocol.current_protocol.version),
        relayed_via=relayed_via,
        broadcast_id=data.get("broadcast_id") if _valid_optional_id(data.get("broadcast_id"), "broadcast_id") else None,
    )
    if data.get("sha256") != message.sha256:
        errors.handle_error(Exceptions.HASH_MISMATCH, "Forwarded message was changed on the way (hash differs)")
        return Exceptions.HASH_MISMATCH
    if mode == MessageMode.COMPRESSED:
        if packed is not None:
            # Keep what came packed - packing it again would cost time in the event loop
            message._transport = (ENCODING_ZLIB, packed)
        problem = _check_transport(message)
        if problem is not None:
            return problem
    if message.is_expired():
        errors.handle_error(Exceptions.MESSAGE_EXPIRED, "Forwarded message arrived expired")
        return Exceptions.MESSAGE_EXPIRED
    return message
