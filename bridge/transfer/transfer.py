import datetime

from fastapi import HTTPException

from bridge.security.utils import get_free_key_in_dict
from bridge.security.utils import get_free_key_in_list
from bridge.transfer import protocol, chunk, universal

conversations = {}
active_message_ids = []

class Message:
    def __init__(
            self,
            sender_ip,
            recipient_ip,
            content,
            content_type,
            conversation_id = None,
            causation_id = None,
            origin_client_ip = None,
            origin_bridge_url = None,
            traffic_type = "direct",
            route_length = "unknown",
    ):
        from bridge import security
        if conversation_id is None:
            conversation_id = get_free_key_in_dict(conversations)
        message_id = get_free_key_in_list(active_message_ids)
        encoded_content = chunk.encode_direct(content)

        self.message_id = message_id
        self.origin_bridge_url = origin_bridge_url
        self.conversation_id = conversation_id
        self.causation_id = causation_id
        self.origin_client_ip = origin_client_ip
        self.sender_ip = sender_ip
        self.recipient_ip = recipient_ip
        self.content_type = content_type
        self.created_at = datetime.datetime.now(datetime.timezone.utc)
        self.protocol_version = protocol.get_current_version()
        self.traffic_type = traffic_type
        self.route_length = route_length

        default_lifetime_minutes = 5

        if traffic_type == "relayed":
            default_lifetime_minutes += 20

        if route_length == "long":
            default_lifetime_minutes *= 2
        elif route_length == "massive":
            default_lifetime_minutes *= 4

        self.expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            minutes=default_lifetime_minutes)

        content_chunks = chunk.chunk_string(encoded_content)

        self.content = content_chunks
        self.content_total_kib = chunk.get_size_string(encoded_content)
        self.content_total_chunks = len(content_chunks)
    def __str__(self) -> str:
        return str(self.__dict__)
    def __repr__(self) -> str:
        return str(self.__dict__)
universal.register_class("Message", Message)

def is_message_expired(message: Message):
    return message.expires_at < datetime.datetime.now(datetime.timezone.utc)

def create_message(
            sender_ip,
            target_recipient_ip,
            content,
            content_type,
            conversation_id = None,
            causation_id = None,
            origin_client_ip = None,
            origin_bridge_url = None,
            traffic_type = None,
            route_length = None,
    ):
    if (
            not sender_ip or
            not target_recipient_ip or
            not content or
            not content_type or
            not origin_bridge_url):
        raise HTTPException(status_code=400, detail="missing required fields")

    return Message(
        sender_ip,
        target_recipient_ip,
        content,
        content_type,
        conversation_id = conversation_id,
        causation_id = causation_id,
        origin_client_ip = origin_client_ip,
        origin_bridge_url = origin_bridge_url,
        traffic_type = traffic_type,
        route_length = route_length,
    )