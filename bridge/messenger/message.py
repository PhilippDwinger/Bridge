import datetime
import json
from enum import StrEnum

from bridge import errors
from bridge.core import address, protocol
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


class ContentType(StrEnum):
    TASK = "task"
    RESPONSE = "response"
    # Reserved for the server itself - clients cannot send instructions
    INSTRUCTION = "instruction"


POOL_BY_CONTENT_TYPE = {
    ContentType.TASK: PoolName.TASK,
    ContentType.RESPONSE: PoolName.RESPONSE,
    ContentType.INSTRUCTION: PoolName.INSTRUCTION,
}

MAX_ID_LENGTH = 128


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


class Message:
    def __init__(
            self,
            sender_ip,
            recipient_ip,
            payload : str,
            content_type = ContentType.TASK,
            mode = MessageMode.SAFE,
            conversation_id = None,
            causation_id = None,
            message_id = None,
            created_at = None,
            expires_at = None,
            protocol_version = None,
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
        self._chunks = None

    def __str__(self):
        return str(self.metadata())
    def __repr__(self):
        return str(self.metadata())

    @property
    def pool_name(self):
        return POOL_BY_CONTENT_TYPE[self.content_type]

    def is_expired(self):
        return _now() >= self.expires_at

    def get_content(self):
        return json.loads(self.payload)

    def get_chunks(self):
        if self._chunks is None:
            self._chunks = chunking.split_text(self.payload, protocol.current_protocol.chunk_size_kib * 1024)
        return self._chunks

    def metadata(self):
        data = {
            "message_id": self.message_id,
            "conversation_id": self.conversation_id,
            "causation_id": self.causation_id,
            "sender_ip": self.sender_ip,
            "recipient_ip": self.recipient_ip,
            "content_type": str(self.content_type),
            "mode": str(self.mode),
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "protocol_version": self.protocol_version,
        }
        if self.mode == MessageMode.SAFE:
            data["chunk_count"] = len(self.get_chunks())
        return data

    def to_dict(self):
        # Full message incl. payload - used to forward a message to another Bridge server
        data = self.metadata()
        data.pop("chunk_count", None)
        data["payload"] = self.payload
        return data


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
    if mode == MessageMode.FAST:
        return protocol.current_protocol.max_fast_message_kib * 1024
    return protocol.current_protocol.max_safe_message_kib * 1024

def encode_content(content):
    try:
        return json.dumps(content, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError) as error:
        errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, f"Content is not JSON serializable: {error}")
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


def create_message(sender_ip, recipient_ip, content, content_type=ContentType.TASK, mode=MessageMode.SAFE,
                   conversation_id=None, causation_id=None):
    content_type = _parse_enum(ContentType, content_type, "content_type")
    mode = _parse_enum(MessageMode, mode, "mode")
    if content_type is None or mode is None:
        return Exceptions.ARGUMENT_ERROR
    payload = encode_content(content)
    if not isinstance(payload, str):
        return payload
    problem = _check_common(sender_ip, recipient_ip, payload, mode, conversation_id, causation_id)
    if problem is not None:
        return problem
    return Message(
        sender_ip,
        recipient_ip,
        payload,
        content_type=content_type,
        mode=mode,
        conversation_id=conversation_id,
        causation_id=causation_id,
    )


def message_from_dict(data):
    """Rebuilds a message that another Bridge server forwarded. Everything is checked again."""
    if not isinstance(data, dict):
        errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, "Forwarded message must be an object")
        return Exceptions.CLIENT_PAYLOAD_ERROR
    payload = data.get("payload")
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
    problem = _check_common(
        data.get("sender_ip"), data.get("recipient_ip"), payload, mode,
        data.get("conversation_id"), data.get("causation_id"),
    )
    if problem is not None:
        return problem
    try:
        json.loads(payload)
        created_at = datetime.datetime.fromisoformat(data["created_at"])
        expires_at = datetime.datetime.fromisoformat(data["expires_at"])
    except (KeyError, TypeError, ValueError) as error:
        errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, f"Forwarded message is malformed: {error}")
        return Exceptions.CLIENT_PAYLOAD_ERROR
    if created_at.tzinfo is None or expires_at.tzinfo is None:
        errors.handle_error(Exceptions.CLIENT_PAYLOAD_ERROR, "Forwarded message timestamps need a timezone")
        return Exceptions.CLIENT_PAYLOAD_ERROR
    # The other server cannot extend the lifetime beyond our own limit
    max_expires_at = _now() + datetime.timedelta(minutes=protocol.message_lifetime_minutes)
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
    )
    if data.get("sha256") != message.sha256:
        errors.handle_error(Exceptions.HASH_MISMATCH, "Forwarded message was changed on the way (hash differs)")
        return Exceptions.HASH_MISMATCH
    if message.is_expired():
        errors.handle_error(Exceptions.MESSAGE_EXPIRED, "Forwarded message arrived expired")
        return Exceptions.MESSAGE_EXPIRED
    return message
