from fastapi import APIRouter
from bridge.core.status import get_server_status

Router = APIRouter()

@Router.get("/server/status")
def get_server_status_dict() -> dict:
    status_msg = "unknown"
    status = get_server_status()
    if status:
        status_msg = status
    return {"status": status_msg}