import time

from bridge import errors
from bridge.banker import ip_store, mailbox_store, status_store, task_store, trust_store
from bridge.core import address, clients, protocol
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.messenger.message import ContentType
from bridge.server import s2s_client, url_env
from bridge.core import metrics
from bridge.messenger import conversations
from bridge.subservices.bridge_agent import agent
from bridge.subservices.bridge_express import types as express_types

# Pull only: delivering means putting the message into the recipient's mailbox on its home server.
# The recipient fetches it with its own request (/message/poll). Bridge never contacts a client.

# Relay route cache: server we do not trust -> trusted server that relayed to it successfully
_relay_routes = {}


def deliver_local(message):
    existing = status_store.get_status(message.message_id)
    if existing is not None and existing.get("recipient_ip") == message.recipient_ip and existing.get("sender_ip") == message.sender_ip:
        # The same message again (e.g. a second way after a timeout although the first one arrived) - only once
        return True
    client_key = ip_store.get_client_key(message.recipient_ip)
    mailbox = mailbox_store.get_mailbox(client_key) if client_key else None
    if mailbox is None:
        errors.handle_error(Exceptions.RECIPIENT_NOT_FOUND, "Recipient IP is not registered on this server")
        return Exceptions.RECIPIENT_NOT_FOUND

    if message.content_type == ContentType.DIRECT and not clients.accepts_direct(client_key, message.sender_ip):
        errors.handle_error(Exceptions.RECIPIENT_REJECTED, "Direct message blocked by the recipient's settings")
        return Exceptions.RECIPIENT_REJECTED
    if message.content_type == ContentType.FRIEND:
        # Only from an active friend (BridgeFriends) - checked here for local and for messages of other servers
        from bridge.subservices.bridge_friends import service as friends
        if not friends.accepts(message.recipient_ip, message.sender_ip):
            errors.handle_error(Exceptions.FRIEND_NOT_FOUND, "Friend message without an active friendship")
            return Exceptions.FRIEND_NOT_FOUND

    if message.content_type == ContentType.TASK and task_store.open_count(message.recipient_ip)[1] >= protocol.max_open_tasks_per_client:
        # The host has too many tasks it did not answer yet
        errors.handle_error(Exceptions.MAILBOX_FULL, "the host has too many open tasks")
        return Exceptions.MAILBOX_FULL

    outgoing = None
    if message.content_type in (ContentType.RESPONSE, ContentType.PROGRESS):
        # Responses and progress are only accepted for a task we sent for this client, from exactly that host
        outgoing = task_store.get_outgoing(message.causation_id)
        if (outgoing is None or outgoing["caller_ip"] != message.recipient_ip
                or outgoing["host_ip"] != message.sender_ip):
            errors.handle_error(Exceptions.TASK_NOT_FOUND, f"{message.content_type} without a matching open task was rejected")
            return Exceptions.TASK_NOT_FOUND

    # For the BridgeAgent: how many messages of the same kind wait before this one
    ahead = mailbox.waiting_count(message.pool_name)
    if message.content_type == ContentType.PROGRESS:
        progress_mode = outgoing.get("progress", "off")
        if progress_mode == "off":
            # The caller did not accept progress - it is simply dropped (not an error)
            return False
        keep = 1 if progress_mode == "latest" else protocol.max_progress_waiting_per_task
        result = mailbox.add_progress(message, keep)
        if not is_exception(result):
            content = message.get_content()
            outgoing["last_percent"] = content.get("percent") if isinstance(content, dict) else None
            outgoing["last_progress_at"] = time.time()
    else:
        result = mailbox.add_message(message, message.pool_name)
    if is_exception(result):
        return result
    agent.message_arrived(message, ahead)
    metrics.count(f"messages received {message.content_type}")
    metrics.count("bytes received", message.size_bytes)
    # Stream of the conversation (Wireshark-like): the message reached one of our clients
    conversations.record(message, "waiting")

    if message.content_type == ContentType.TASK:
        # The host may answer this task exactly once
        content = message.get_content()
        accepts_progress = isinstance(content, dict) and content.get("accepts_progress") is True
        task_store.add_incoming(message.message_id, message.sender_ip, message.recipient_ip, message.conversation_id,
                                accepts_progress)
        if isinstance(content, dict):
            agent.task_arrived(message.message_id, message.recipient_ip, content.get("realm_address"),
                               content.get("command_name"), ahead, len(message.payload))
        response_check = content.get("response_check") if isinstance(content, dict) else None
        if isinstance(response_check, dict) and response_check.get("validate") == "strict":
            # Signature with validate=strict: the response of the host must fit the return type.
            # The type is read again from its text (limited depth) - the tree of another server is not trusted.
            try:
                tree = express_types.parse_type(response_check.get("type"))
            except express_types.TypeError_:
                tree = None
            if tree is not None:
                task_store.incoming_tasks[message.message_id]["response_check"] = {
                    "type": express_types.to_text(tree), "tree": tree, "validate": "strict"}
    elif message.content_type == ContentType.RESPONSE:
        task_store.remove_outgoing(message.causation_id)
        agent.response_arrived(message.causation_id)
        if outgoing.get("progress") == "latest":
            # The answer is there - the last waiting progress is out of date
            mailbox.remove_progress(message.causation_id)
    status_store.set_status(message, status_store.WAITING)
    # Wakes up a poll of the recipient that is waiting - the recipient's own request returns with the message
    mailbox_store.notify(client_key)
    return result


def route_of(recipient_ip, content_type=None):
    """How a message gets to this recipient: "local", "remote:<server>", "relay" or - friend messages to a server we
    do not trust - "friend:<server>" (for the BridgeAgent and the conversations)."""
    server_url = address.server_of(recipient_ip)
    if server_url == url_env.base_root:
        return "local"
    if trust_store.is_trusted(server_url):
        return f"remote:{server_url}"
    if content_type == ContentType.FRIEND:
        return f"friend:{server_url}"
    return "relay"


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
    if from_server is None and address.is_local(message.sender_ip):
        # Stream of the conversation (Wireshark-like): our client sent this message
        conversations.record(message, "sent", "local" if recipient_server == url_env.base_root
                             else route_of(message.recipient_ip, message.content_type))
        started = time.monotonic()
        result = await _deliver(message, recipient_server, from_server)
        metrics.timing("deliver", time.monotonic() - started)
        if is_exception(result):
            conversations.update_state(message.message_id, message.conversation_id, "failed")
            metrics.count("messages failed")
        elif result is False:
            conversations.update_state(message.message_id, message.conversation_id, "dropped")
        else:
            metrics.count(f"messages sent {message.content_type}")
            metrics.count(f"messages mode {message.mode}")
            metrics.count("bytes sent", message.size_bytes)
            if getattr(message, "_route", None):
                conversations.set_route(message.message_id, message.conversation_id, message._route)
        return result
    return await _deliver(message, recipient_server, from_server)


async def _deliver(message, recipient_server, from_server):
    if recipient_server == url_env.base_root:
        return deliver_local(message)
    if from_server is not None:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{from_server} tried to relay a message to {recipient_server}")
        return Exceptions.NOT_ALLOWED
    if message.content_type == ContentType.FRIEND:
        # Friend messages go straight to the friend's server: trusted connection or friend connection (no relay)
        from bridge.subservices.bridge_friends import service as friends
        return await friends.deliver_remote(message, recipient_server)
    if (message.content_type == ContentType.DIRECT and not message.relayed_via
            and protocol.routing == "agent"):
        # The agent picks the best way (around broken or slow lines) and fails over to the next one
        from bridge.subservices.bridge_agent import routing
        result = await routing.deliver(message, recipient_server)
        if result is not None:
            return result
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
