import asyncio
import datetime
import math
import time

from bridge import errors
from bridge.banker import mailbox_store, schedule_store, status_store, trust_store
from bridge.core import address, clients, metrics, protocol
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.messenger import mailbox as mailbox_module, router
from bridge.messenger.message import ONE_PIECE_MODES, POOL_BY_CONTENT_TYPE, ContentType, MessageMode, create_message
from bridge.security.hasher import secrets_equal
from bridge.server import s2s_client, url_env
from bridge.subservices.bridge_agent import agent

# Message flow for a recipient (always started by the recipient - Bridge never pushes):
#   poll -> fast: content comes directly, message is deleted
#        -> safe: pending_id + metadata (sha256, chunk_count)
#              -> chunk(0..n-1) -> join -> SHA-256 -> complete(sha256) -> deleted
#              -> or cancel(pending_id) -> back into the mailbox
#              -> if neither happens, the pending message goes back automatically after Mailbox.PENDING_TIMEOUT_MINUTES
# Poll modes: wait_seconds = 0 answers at once; wait_seconds > 0 keeps the request open until something
# arrives or the time is over (long polling).


def _get_mailbox(client_key):
    mailbox = mailbox_store.get_mailbox(client_key)
    if mailbox is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND, "Client has no mailbox")
        return Exceptions.CLIENT_NOT_FOUND
    return mailbox


def check_wait_seconds(wait_seconds):
    if wait_seconds is None:
        return 0
    if (isinstance(wait_seconds, bool) or not isinstance(wait_seconds, (int, float)) or not math.isfinite(wait_seconds)
            or wait_seconds < 0):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "'wait_seconds' must be a number >= 0")
        return Exceptions.ARGUMENT_ERROR
    return min(float(wait_seconds), protocol.max_wait_seconds)


async def wait_for_signal(client_key, timeout):
    signal = mailbox_store.get_signal(client_key)
    try:
        await asyncio.wait_for(signal.wait(), timeout)
    except asyncio.TimeoutError:
        pass


async def send_direct(client_key, recipient_ip, content, mode=MessageMode.SAFE, conversation_id=None, causation_id=None,
                      expires_at=None):
    """A direct message from one client to any other client (on any trusted server). Not verified."""
    sender_ip = clients.get_client_ip(client_key)
    if sender_ip is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND)
        return Exceptions.CLIENT_NOT_FOUND
    message = create_message(sender_ip, recipient_ip, content, ContentType.DIRECT, mode, conversation_id, causation_id,
                             expires_at=expires_at)
    if is_exception(message):
        return message
    return await deliver_direct(message)


async def deliver_direct(message):
    """Delivers a direct message that was already created (also used for scheduled messages)."""
    recipient_ip = message.recipient_ip
    started = time.monotonic()
    result = await router.deliver(message)
    if is_exception(result):
        return result
    agent.delivered(router.route_of(recipient_ip, message.content_type), len(message.payload), time.monotonic() - started)
    status_store.remember_sent(message)
    return message


def _requeued(message):
    """A fetched message was not confirmed in time and waits again: status back to waiting, wake long polls."""
    from bridge.banker import ip_store
    status_store.set_status(message, status_store.WAITING)  # also updates the conversation stream (on_status)
    client_key = ip_store.get_client_key(message.recipient_ip)
    if client_key is not None:
        mailbox_store.notify(client_key)


mailbox_module.on_requeued.append(_requeued)


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


def remove_expired_messages():
    """The cleaner: deletes messages whose lifetime is over from every mailbox (also temporary ones)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    removed = 0
    for mailbox in list(mailbox_store.mailbox_storage.values()):
        for message in mailbox.remove_expired(now):
            status_store.set_status(message, status_store.EXPIRED)
            removed += 1
    if removed:
        metrics.count("messages expired", removed)
    return removed


async def run_cleaner():
    rounds = 0
    while True:
        await asyncio.sleep(1)
        rounds += 1
        try:
            removed = remove_expired_messages()
            if removed:
                errors.debug_print(f"Removed {removed} expired message(s)")
            if rounds % 60 == 0:
                from bridge.messenger import conversations
                from bridge.subservices.bridge_friends import service as friends
                conversations.forget_idle()
                friends.forget_gone()
        except Exception as error:
            errors.handle_error(Exceptions.FAILED, f"Message cleaner failed: {error!r}")


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
            status_store.set_status(message, status_store.EXPIRED)
            errors.debug_print(f"Dropped expired message {message.message_id}")
            continue
        agent.message_taken(clients.get_client_ip(client_key), message)
        if message.mode in ONE_PIECE_MODES:
            mailbox.complete_pending_message(pending_id)
            status_store.set_status(message, status_store.DELIVERED)
            return {
                "mode": str(message.mode),
                "message": message.metadata(),
                "content": message.get_content(),
            }
        status_store.set_status(message, status_store.TAKEN)
        # safe / compressed: fetch the chunks, (unpack,) check the hash, confirm
        return {
            "mode": str(message.mode),
            "pending_id": pending_id,
            "message": message.metadata(),
        }


def check_max_messages(max_messages):
    if max_messages is None:
        return None
    if isinstance(max_messages, bool) or not isinstance(max_messages, int) or not 1 <= max_messages <= protocol.max_poll_messages:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'max_messages' must be a whole number between 1 and {protocol.max_poll_messages}")
        return Exceptions.ARGUMENT_ERROR
    return max_messages


def _poll_more(client_key, content_types, first, max_messages):
    """Batch poll: after the first message, take more without waiting - one-piece messages only, a chunked one
    (safe / compressed) ends the batch, because the client has to fetch its chunks first."""
    items = [first]
    while len(items) < max_messages and "pending_id" not in items[-1]:
        result = poll(client_key, content_types)
        if is_exception(result) or result.get("message") is None:
            break
        items.append(result)
    return {"messages": items, "count": len(items)}


async def poll_wait(client_key, content_types=None, wait_seconds=0, max_messages=None):
    """Poll that can wait for a message (long polling). Still only an answer to the client's own request.
    With max_messages: answer {"messages": [...], "count"} - each item looks like a single poll answer."""
    wait_seconds = check_wait_seconds(wait_seconds)
    if is_exception(wait_seconds):
        return wait_seconds
    max_messages = check_max_messages(max_messages)
    if is_exception(max_messages):
        return max_messages
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait_seconds
    while True:
        # Reset the signal before looking, so nothing that arrives in between is missed
        mailbox_store.get_signal(client_key).clear()
        result = poll(client_key, content_types)
        if is_exception(result):
            return result
        if result.get("message") is not None:
            return result if max_messages is None else _poll_more(client_key, content_types, result, max_messages)
        remaining = deadline - loop.time()
        if remaining <= 0 or mailbox_store.closing:
            return result if max_messages is None else {"messages": [], "count": 0}
        await wait_for_signal(client_key, remaining)


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
    status_store.set_status(message, status_store.DELIVERED)
    return {"completed": True, "message_id": message.message_id}


def cancel(client_key, pending_id):
    mailbox = _get_mailbox(client_key)
    if is_exception(mailbox):
        return mailbox
    message = mailbox.get_pending_message(pending_id)
    result = mailbox.cancel_pending_message_with_pending_id(pending_id)
    if result is True and message is not None:
        status_store.set_status(message, status_store.WAITING)
        mailbox_store.notify(client_key)
    return result


# region message status
def get_local_status(message_id, sender_ip):
    status = status_store.get_status(message_id)
    if status is None or status["sender_ip"] != sender_ip:
        errors.handle_error(Exceptions.KEY_ERROR, "No status for this message")
        return Exceptions.KEY_ERROR
    return {
        "message_id": message_id,
        "recipient_ip": status["recipient_ip"],
        "state": status["state"],
        "updated_at": status["updated_at"].isoformat(),
    }


async def message_status(client_key, message_id):
    """Status of a message the client sent: waiting, taken, delivered or expired."""
    sender_ip = clients.get_client_ip(client_key)
    planned = schedule_store.get(message_id) if isinstance(message_id, str) else None
    if planned is not None and planned["client_key"] == client_key:
        return {"message_id": message_id, "recipient_ip": planned["message"].recipient_ip, "state": status_store.SCHEDULED,
                "send_at": planned["send_at"].isoformat(), "updated_at": None}
    sent = status_store.get_sent(message_id)
    if sent is None or sent["sender_ip"] != sender_ip:
        errors.handle_error(Exceptions.KEY_ERROR, "This client did not send a message with this id (or it is too old)")
        return Exceptions.KEY_ERROR
    recipient_server = address.server_of(sent["recipient_ip"])
    if recipient_server == url_env.base_root:
        return get_local_status(message_id, sender_ip)
    return await remote_status(recipient_server, message_id, sender_ip, sent["recipient_ip"],
                               sent.get("content_type"))


async def remote_status(recipient_server, message_id, sender_ip, recipient_ip, content_type=None):
    """Ask the recipient's server: over the trusted connection, or - for friend messages - the friend connection."""
    from bridge.subservices.bridge_friends import link as friend_link, service as friends
    if content_type == ContentType.FRIEND and not friend_link.trusted_connected(recipient_server):
        return await friends.remote_message_status(recipient_server, message_id, sender_ip)
    if not trust_store.is_trusted(recipient_server):
        # Relayed message to a server we do not trust - there is no way to ask it
        return {"message_id": message_id, "recipient_ip": recipient_ip, "state": "unknown (relayed)", "updated_at": None}
    return await s2s_client.message_status(recipient_server, message_id, sender_ip)

# endregion message status
