import asyncio
import json

from bridge import errors
from bridge.core import address, clients
from bridge.errors.exceptions import Exceptions, get_exception_id, is_exception
from bridge.messenger import router
from bridge.messenger.message import ContentType, MessageMode, create_message, encode_content, pack_payload
from bridge.realm import service as realm_service

# Publish/subscribe in realms:
#   subscribe   - the client wants the events of a topic (realm action, works across servers)
#   publish     - the realm says who is subscribed (and if the publisher may publish), then the publisher's
#                 home server puts one "event" message into the mailbox of every subscriber
#   subscribers - fetch events like any other message with /message/poll (content type "event")
# Event content: {"realm_address", "topic", "data"}


async def publish(client_key, realm_address, topic, data, mode=MessageMode.FAST, include_self=True):
    publisher_ip = clients.get_client_ip(client_key)
    if publisher_ip is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND)
        return Exceptions.CLIENT_NOT_FOUND
    subscribers = await realm_service.execute(publisher_ip, realm_address, "resolve_subscribers", {"topic": topic})
    if is_exception(subscribers):
        return subscribers
    if not isinstance(subscribers, list):
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, "Realm answered without a subscriber list")
        return Exceptions.REMOTE_SERVER_ERROR

    content = {"realm_address": realm_address, "topic": topic, "data": data}
    # Encoded (and packed) once for all subscribers
    payload = encode_content(content)
    if is_exception(payload):
        return payload
    transport = await asyncio.to_thread(pack_payload, payload) if mode == MessageMode.COMPRESSED else None

    async def deliver_to(subscriber_ip):
        message = create_message(publisher_ip, subscriber_ip, content, ContentType.EVENT, mode, payload=payload,
                                 transport=transport)
        if is_exception(message):
            return subscriber_ip, message
        return subscriber_ip, await router.deliver(message)

    # include_self=False: the publisher does not get its own event back (it is subscribed itself, e.g. every game
    # server of a Roblox game publishes its players and listens to the others)
    targets = [ip for ip in subscribers if isinstance(ip, str) and (include_self or ip != publisher_ip)]
    results = await asyncio.gather(*(deliver_to(ip) for ip in targets))
    failed = [{"client_ip": ip, "error": get_exception_id(result)} for ip, result in results if is_exception(result)]
    return {
        "topic": topic,
        "subscribers": len(results),
        "delivered": len(results) - len(failed),
        "failed": failed,
    }


async def verify_remote_event(message, peer_url):
    """An event from another server: check with the realm that the publisher may publish and we subscribed."""
    try:
        content = json.loads(message.payload)
        topic = content["topic"]
        realm_address = content["realm_address"]
    except (ValueError, TypeError, KeyError):
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} sent an event without topic data")
        return Exceptions.NOT_ALLOWED
    if not isinstance(topic, str) or not address.is_valid_address(realm_address):
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} sent an event with invalid topic data")
        return Exceptions.NOT_ALLOWED
    if address.server_of(realm_address) == peer_url:
        # The realm lives on the sending server - it already checked
        return True
    allowed = await realm_service.execute(message.sender_ip, realm_address, "verify_event",
                                          {"topic": topic, "subscriber_ip": message.recipient_ip})
    if allowed is not True:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} sent an event the realm does not allow")
        return Exceptions.NOT_ALLOWED
    return True
