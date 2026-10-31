from bridge import errors
from bridge.banker import mailbox_store
from bridge.core import clients
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.messenger import router
from bridge.messenger.message import POOL_BY_CONTENT_TYPE, ContentType, MessageMode, create_message
from bridge.security.hasher import secrets_equal

# Message flow for a recipient:
#   poll -> fast: content comes directly, message is deleted
#        -> safe: pending_id + metadata (sha256, chunk_count)
#              -> chunk(0..n-1) -> join -> SHA-256 -> complete(sha256) -> deleted
#              -> or cancel(pending_id) -> back into the mailbox
#              -> if neither happens, the pending message goes back automatically after Mailbox.PENDING_TIMEOUT_MINUTES


def _get_mailbox(client_key):
    mailbox = mailbox_store.get_mailbox(client_key)
    if mailbox is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND, "Client has no mailbox")
        return Exceptions.CLIENT_NOT_FOUND
    return mailbox


async def send_direct(client_key, recipient_ip, content, mode=MessageMode.SAFE, conversation_id=None, causation_id=None):
    """A direct message from one client to any other client (on any trusted server). Not verified."""
    sender_ip = clients.get_client_ip(client_key)
    if sender_ip is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND)
        return Exceptions.CLIENT_NOT_FOUND
    message = create_message(sender_ip, recipient_ip, content, ContentType.DIRECT, mode, conversation_id, causation_id)
    if is_exception(message):
        return message
    result = await router.deliver(message)
    if is_exception(result):
        return result
    return message


def parse_content_types(content_types):
    """Turns ["direct", "task", ...] from a client into pool names. None means all pools."""
    if content_types is None:
        return None
    if not isinstance(content_types, list) or not content_types:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "'content_types' must be a non-empty list")
        return Exceptions.ARGUMENT_ERROR
    pool_names = []
    for content_type in content_types:
        try:
            pool_names.append(POOL_BY_CONTENT_TYPE[ContentType(content_type)])
        except (ValueError, KeyError):
            allowed = ", ".join(item.value for item in ContentType)
            errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Unknown content type {content_type!r} (allowed: {allowed})")
            return Exceptions.ARGUMENT_ERROR
    return pool_names


def poll(client_key, content_types=None):
    mailbox = _get_mailbox(client_key)
    if is_exception(mailbox):
        return mailbox
    pool_names = parse_content_types(content_types)
    if is_exception(pool_names):
        return pool_names
    while True:
        message, pending_id = mailbox.poll_most_overdue(pool_names)
        if message is None:
            return {"message": None}
        if message.is_expired():
            mailbox.complete_pending_message(pending_id)
            errors.debug_print(f"Dropped expired message {message.message_id}")
            continue
        if message.mode == MessageMode.FAST:
            mailbox.complete_pending_message(pending_id)
            return {
                "mode": str(MessageMode.FAST),
                "message": message.metadata(),
                "content": message.get_content(),
            }
        return {
            "mode": str(MessageMode.SAFE),
            "pending_id": pending_id,
            "message": message.metadata(),
        }


def get_chunk(client_key, pending_id, chunk_index):
    mailbox = _get_mailbox(client_key)
    if is_exception(mailbox):
        return mailbox
    message = mailbox.get_pending_message(pending_id)
    if message is None:
        return Exceptions.KEY_ERROR
    chunks = message.get_chunks()
    if isinstance(chunk_index, bool) or not isinstance(chunk_index, int) or not 0 <= chunk_index < len(chunks):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"chunk_index must be between 0 and {len(chunks) - 1}")
        return Exceptions.ARGUMENT_ERROR
    return {
        "chunk_index": chunk_index,
        "chunk_count": len(chunks),
        "chunk": chunks[chunk_index],
    }


def complete(client_key, pending_id, sha256):
    mailbox = _get_mailbox(client_key)
    if is_exception(mailbox):
        return mailbox
    message = mailbox.get_pending_message(pending_id)
    if message is None:
        return Exceptions.KEY_ERROR
    if not isinstance(sha256, str) or not secrets_equal(sha256.lower(), message.sha256):
        errors.handle_error(Exceptions.HASH_MISMATCH, f"Message {message.message_id}")
        return Exceptions.HASH_MISMATCH
    mailbox.complete_pending_message(pending_id)
    return {"completed": True, "message_id": message.message_id}


def cancel(client_key, pending_id):
    mailbox = _get_mailbox(client_key)
    if is_exception(mailbox):
        return mailbox
    return mailbox.cancel_pending_message_with_pending_id(pending_id)
