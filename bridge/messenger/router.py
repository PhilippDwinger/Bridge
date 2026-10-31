from bridge import errors
from bridge.banker import ip_store, mailbox_store
from bridge.core import address
from bridge.errors.exceptions import Exceptions
from bridge.server import s2s_client, url_env


def deliver_local(message):
    client_key = ip_store.get_client_key(message.recipient_ip)
    mailbox = mailbox_store.get_mailbox(client_key) if client_key else None
    if mailbox is None:
        errors.handle_error(Exceptions.RECIPIENT_NOT_FOUND, "Recipient IP is not registered on this server")
        return Exceptions.RECIPIENT_NOT_FOUND
    return mailbox.add_message(message, message.pool_name)


async def deliver(message, from_server=None):
    """Delivers a message to its recipient - into a local mailbox or to the recipient's (trusted) Bridge server.

    from_server is set when the message came from another Bridge server. Such messages are never passed on
    to a third server (no relaying), so every hop is between two servers that trust each other.
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
    return await s2s_client.send_message(recipient_server, message)
