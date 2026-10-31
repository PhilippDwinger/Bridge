from fastapi import APIRouter

from bridge.core import backup, protocol
from bridge.core.status import get_server_status
from bridge.realm import service as realm_service
from bridge.server import url_env

Router = APIRouter()

@Router.get("/server/status")
async def get_server_status_dict() -> dict:
    status_msg = "unknown"
    status = get_server_status()
    if status:
        status_msg = status
    return {
        "status": status_msg,
        # False while the server restores its backup after a start (client requests get 503 SERVER_STARTING)
        "ready": backup.is_ready(),
        "url": url_env.base_root,
        "protocol_version": protocol.current_protocol.version,
        "public_realm_address": realm_service.get_public_realm_address(),
        "limits": {
            "chunk_size_kib": protocol.current_protocol.chunk_size_kib,
            "max_fast_message_kib": protocol.current_protocol.max_fast_message_kib,
            "max_safe_message_kib": protocol.current_protocol.max_safe_message_kib,
        },
    }
