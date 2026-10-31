from bridge import errors
from bridge.banker import ip_store, mailbox_store, status_store, task_store, trust_store
from bridge.core import address, clients, protocol
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.messenger.message import ContentType
from bridge.server import s2s_client, url_env

# Pull only: delivering means putting the message into the recipient's mailbox on its home server.
# The recipient fetches it with its own request (/message/poll). Bridge never contacts a client.

# Relay route cache: server we do not trust -> trusted server that relayed to it successfully
_relay_routes = {}


def deliver_local(message):
    client_key = ip_store.get_client_key(message.recipient_ip)
    mailbox = mailbox_store.get_mailbox(client_key) if client_key else None
    if mailbox is None:
        errors.handle_error(Exceptions.RECIPIENT_NOT_FOUND, "Recipient IP is not registered on this server")
        return Exceptions.RECIPIENT_NOT_FOUND

    if message.content_type == ContentType.DIRECT and not clients.accepts_direct(client_key, message.sender_ip):
        errors.handle_error(Exceptions.RECIPIENT_REJECTED, "Direct message blocked by the recipient's settings")
        return Exceptions.RECIPIENT_REJECTED

    if message.content_type == ContentType.RESPONSE:
        # A response is only accepted for a task we sent for this client, from exactly that host, once
        outgoing = task_store.get_outgoing(message.causation_id)
        if (outgoing is None or outgoing["caller_ip"] != message.recipient_ip
                or outgoing["host_ip"] != message.sender_ip):
            errors.handle_error(Exceptions.TASK_NOT_FOUND, "Response without a matching open task was rejected")
            return Exceptions.TASK_NOT_FOUND

    result = mailbox.add_message(message, message.pool_name)
    if is_exception(result):
        return result

    if message.content_type == ContentType.TASK:
        # The host may answer this task exactly once
        task_store.add_incoming(message.message_id, message.sender_ip, message.recipient_ip, message.conversation_id)
    elif message.content_type == ContentType.RESPONSE:
        task_store.remove_outgoing(message.causation_id)
    status_store.set_status(message, status_store.WAITING)
    # Wakes up a poll of the recipient that is waiting - the recipient's own request returns with the message
    mailbox_store.notify(client_key)
    return result


async def _relay(message, recipient_server):
    """Direct message to a server we do not trust: ask our trusted servers to pass it on (one hop)."""
    connected = [server["url"] for server in trust_store.list_servers() if server["status"] == trust_store.STATUS_CONNECTED]
    cached = _relay_routes.get(recipient_server)
    candidates = ([cached] if cached in connected else []) + [url for url in connected if url != cached]
    last_error = Exceptions.SERVER_NOT_TRUSTED
    for relay_server in candidates:
        result = await s2s_client.relay_message(relay_server, message)
        if result is True:
            _relay_routes[recipient_server] = relay_server
            return True
        if result in (Exceptions.RECIPIENT_NOT_FOUND, Exceptions.RECIPIENT_REJECTED, Exceptions.MAILBOX_FULL):
            # The message reached the target server - no other route will do better
            _relay_routes[recipient_server] = relay_server
            return result
        last_error = result
    _relay_routes.pop(recipient_server, None)
    errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"No trusted server could relay to {recipient_server}")
    return last_error if is_exception(last_error) else Exceptions.SERVER_NOT_TRUSTED


async def deliver(message, from_server=None):
    """Delivers a message to its recipient - into a local mailbox or to the recipient's Bridge server.

    from_server is set when the message came from another Bridge server. Such messages are only passed on
    by relay_for_peer (direct messages, if relaying is on). Every hop is between two servers that trust each other.
    """
    if message.is_expired():
        errors.handle_error(Exceptions.MESSAGE_EXPIRED)
        return Exceptions.MESSAGE_EXPIRED
    recipient_server = address.server_of(message.recipient_ip)
    if recipient_server is None:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Invalid recipient IP: {message.recipient_ip!r}")
        return Exceptions.ARGUMENT_ERROR
    if recipient_server == url_env.base_root:
        return deliver_local(message)
    if from_server is not None:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{from_server} tried to relay a message to {recipient_server}")
        return Exceptions.NOT_ALLOWED
    if trust_store.is_trusted(recipient_server):
        return await s2s_client.send_message(recipient_server, message)
    if message.content_type == ContentType.DIRECT and not message.relayed_via:
        return await _relay(message, recipient_server)
    errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"{recipient_server} is not trusted")
    return Exceptions.SERVER_NOT_TRUSTED


async def relay_for_peer(message, peer_url):
    """We are the server in the middle: pass a direct message of a trusted server on to another trusted server."""
    if protocol.relay_mode != "trusted":
        errors.handle_error(Exceptions.NOT_ALLOWED, "Relaying is switched off on this server")
        return Exceptions.NOT_ALLOWED
    if message.content_type != ContentType.DIRECT or message.relayed_via:
        errors.handle_error(Exceptions.NOT_ALLOWED, "Only direct messages can be relayed, and only once")
        return Exceptions.NOT_ALLOWED
    if address.server_of(message.sender_ip) != peer_url:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} asked to relay a message of a foreign client")
        return Exceptions.NOT_ALLOWED
    target_server = address.server_of(message.recipient_ip)
    if target_server == url_env.base_root:
        return deliver_local(message)
    if target_server == peer_url or not trust_store.is_trusted(target_server):
        errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"Cannot relay to {target_server}")
        return Exceptions.SERVER_NOT_TRUSTED
    message.relayed_via = [url_env.base_root]
    return await s2s_client.send_message(target_server, message)
