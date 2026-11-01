from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from bridge import errors
from bridge.core import timing
from bridge.errors.exceptions import Exceptions, get_exception_id, is_exception
from bridge.messenger import router as message_router, service as messenger_service
from bridge.messenger.message import ContentType, MessageMode, message_from_dict
from bridge.server import url_env
from bridge.server.routes._helpers import authenticate, check, get_field
from bridge.server.routes.messages import _times
from bridge.subservices.bridge_friends import doors, link, service as friends

# BridgeFriends: friendships between clients - also with clients of servers that do not trust this one.
Router = APIRouter(prefix="/friends")
# Only for other Bridge servers (trusted connection or friend connection, see bridge_friends/link.py)
S2SRouter = APIRouter(prefix="/s2s/friends")

MAX_STATUS_FRIENDS = 500


# region client endpoints
@Router.post("/invite")
async def invite(payload: dict):
    # A door other clients can use to become friends: "name" (memorable, password required, lives until deleted)
    # or without name a random code (expires, used once). accept: auto (default) | manual
    client_key = authenticate(payload)
    expires_at = check(timing.resolve(get_field(payload, "expires_in_seconds", (int, float), required=False),
                                      get_field(payload, "expires_at", str, required=False),
                                      get_field(payload, "timezone", str, required=False), "expires"))
    return check(await friends.create_invite(
        client_key,
        name=get_field(payload, "name", str, required=False),
        password=get_field(payload, "password", str, required=False),
        expires_at=expires_at,
        max_uses=get_field(payload, "max_uses", int, required=False),
        accept=get_field(payload, "accept", str, required=False, default="auto"),
        label=get_field(payload, "label", str, required=False),
    ))


@Router.post("/invites")
async def invites(payload: dict):
    client_key = authenticate(payload)
    return friends.list_invites(client_key)


@Router.post("/invite/delete")
async def invite_delete(payload: dict):
    client_key = authenticate(payload)
    return check(friends.delete_invite(client_key, get_field(payload, "invite_id", str)))


@Router.post("/add")
async def add(payload: dict):
    # address: "paddy-home@bridge.example.com" (or "K7M3XQ9P@...", or only the name for this server) + password
    client_key = authenticate(payload)
    return check(await friends.add_friend(
        client_key,
        get_field(payload, "address", str),
        get_field(payload, "password", str, required=False, default=""),
        label=get_field(payload, "label", str, required=False),
    ))


@Router.post("/requests")
async def open_requests(payload: dict):
    client_key = authenticate(payload)
    return friends.requests(client_key)


@Router.post("/answer")
async def answer(payload: dict):
    client_key = authenticate(payload)
    return check(await friends.answer_request(client_key, get_field(payload, "friend_ip", str),
                                              get_field(payload, "accept", bool)))


@Router.post("/list")
async def friend_list(payload: dict):
    client_key = authenticate(payload)
    return await friends.list_friends(client_key)


@Router.post("/info")
async def friend_info(payload: dict):
    client_key = authenticate(payload)
    return check(await friends.info(client_key, get_field(payload, "friend_ip", str)))


@Router.post("/remove")
async def remove(payload: dict):
    client_key = authenticate(payload)
    return check(await friends.remove_friend(client_key, get_field(payload, "friend_ip", str)))


@Router.post("/presence")
async def presence(payload: dict):
    # presence: available | busy | away | invisible (friends see "offline"), status_text: up to 100 characters
    client_key = authenticate(payload)
    return check(friends.set_presence(client_key, get_field(payload, "presence", str, required=False),
                                      get_field(payload, "status_text", str, required=False)))


@Router.post("/nickname")
async def nickname(payload: dict):
    client_key = authenticate(payload)
    return check(friends.set_nickname(client_key, get_field(payload, "friend_ip", str),
                                      get_field(payload, "nickname", str, required=False)))


def _content(payload):
    if "content" not in payload:
        get_field(payload, "content", object)  # reports the missing field
    return payload.get("content")


@Router.post("/send")
async def send(payload: dict):
    # A message to a friend (content type "friend", verified). Same modes and times as /message/send.
    client_key = authenticate(payload)
    return check(await friends.send(
        client_key,
        [get_field(payload, "friend_ip", str)],
        _content(payload),
        mode=get_field(payload, "mode", str, required=False, default=str(MessageMode.SAFE)),
        conversation_id=get_field(payload, "conversation_id", str, required=False),
        causation_id=get_field(payload, "causation_id", str, required=False),
        times=_times(payload),
    ))


@Router.post("/broadcast")
async def broadcast(payload: dict):
    # The same message to several friends - "friend_ips" or, without it, all active friends
    client_key = authenticate(payload)
    return check(await friends.send(
        client_key,
        get_field(payload, "friend_ips", list, required=False),
        _content(payload),
        mode=get_field(payload, "mode", str, required=False, default=str(MessageMode.SAFE)),
        conversation_id=get_field(payload, "conversation_id", str, required=False),
        causation_id=get_field(payload, "causation_id", str, required=False),
        times=_times(payload),
        broadcast=True,
    ))
# endregion client endpoints


# region server to server
def _ok(result=True):
    return {"ok": True, "result": result}

def _error(error, status_code=200):
    if not is_exception(error):
        error = Exceptions.UNKNOWN_ERROR
    content = {"ok": False, "error": get_exception_id(error), "message": error.default_message}
    details = errors.pop_client_details()
    if details:
        content["details"] = details
    return JSONResponse(status_code=status_code, content=content)

def _answer(result):
    return _error(result) if is_exception(result) else _ok(result)

def _peer(request):
    peer_url, problem = link.authenticate(request)
    if peer_url is None:
        return None, _error(problem, 403)
    return peer_url, None

def _belongs_to(ip, server_url):
    # Right server and a well-formed client id (no broken text that would break our answers later)
    return friends.valid_client_ip(ip, server_url)


def _source(request):
    return request.client.host if request.client else "unknown"


@S2SRouter.post("/link/hello")
async def link_hello(payload: dict, request: Request):
    result = await link.on_hello(payload, _source(request))
    return _error(result, 403) if is_exception(result) else _ok()


@S2SRouter.post("/link/deliver")
async def link_deliver(payload: dict, request: Request):
    result = await link.on_deliver(payload, _source(request))
    return _error(result, 403) if is_exception(result) else _ok()


@S2SRouter.post("/link/confirm")
async def link_confirm(payload: dict):
    if not link.on_confirm(payload):
        errors.handle_error(Exceptions.NOT_ALLOWED, "Unknown friend connection secret")
        return _error(Exceptions.NOT_ALLOWED, 403)
    return _ok()


@S2SRouter.post("/hello")
async def hello(payload: dict, request: Request):
    # A client of the other server wants to come in through one of our doors: challenge (nonce + salt)
    peer_url, failed = _peer(request)
    if failed:
        return failed
    requester_ip = payload.get("requester_ip")
    if not _belongs_to(requester_ip, peer_url):
        return _error(Exceptions.NOT_ALLOWED)
    return _answer(doors.start(payload.get("door"), peer_url, requester_ip))


@S2SRouter.post("/request")
async def request_friendship(payload: dict, request: Request):
    peer_url, failed = _peer(request)
    if failed:
        return failed
    requester_ip = payload.get("requester_ip")
    if not _belongs_to(requester_ip, peer_url):
        return _error(Exceptions.NOT_ALLOWED)
    return _answer(await friends.accept_request(payload.get("challenge_id"), payload.get("proof"), payload.get("client_nonce"),
                                                requester_ip, payload.get("requester_label"), peer_url))


@S2SRouter.post("/answer")
async def answer_from_peer(payload: dict, request: Request):
    # The owner of the door answered our client's request (manual accept)
    peer_url, failed = _peer(request)
    if failed:
        return failed
    inviter_ip, requester_ip = payload.get("inviter_ip"), payload.get("requester_ip")
    if not _belongs_to(inviter_ip, peer_url) or not _belongs_to(requester_ip, url_env.base_root):
        return _error(Exceptions.NOT_ALLOWED)
    return _answer(friends.apply_answer(requester_ip, inviter_ip, payload.get("friendship_id"), payload.get("accepted") is True))


@S2SRouter.post("/remove")
async def remove_from_peer(payload: dict, request: Request):
    peer_url, failed = _peer(request)
    if failed:
        return failed
    from_ip, to_ip = payload.get("from_ip"), payload.get("to_ip")
    if not _belongs_to(from_ip, peer_url) or not _belongs_to(to_ip, url_env.base_root):
        return _error(Exceptions.NOT_ALLOWED)
    return _answer(friends.apply_remove(to_ip, from_ip, payload.get("friendship_id")))


@S2SRouter.post("/status")
async def status(payload: dict, request: Request):
    # Status of our clients for one of their friends on the other server
    peer_url, failed = _peer(request)
    if failed:
        return failed
    asking_ip = payload.get("asking_ip")
    entries = payload.get("friends")
    if not _belongs_to(asking_ip, peer_url) or not isinstance(entries, list) or len(entries) > MAX_STATUS_FRIENDS:
        return _error(Exceptions.NOT_ALLOWED)
    result = {}
    for entry in entries:
        if not isinstance(entry, dict) or not _belongs_to(entry.get("friend_ip"), url_env.base_root):
            continue
        result[entry["friend_ip"]] = friends.local_status(entry["friend_ip"], asking_ip, entry.get("friendship_id"))
    return _ok(result)


@S2SRouter.post("/message")
async def message(payload: dict, request: Request):
    peer_url, failed = _peer(request)
    if failed:
        return failed
    received = message_from_dict(payload.get("message"))
    if is_exception(received):
        return _error(received)
    if (received.content_type != ContentType.FRIEND or received.relayed_via
            or not _belongs_to(received.recipient_ip, url_env.base_root)
            or not _belongs_to(received.sender_ip, peer_url)):
        # Only friend messages of the other server's own clients to our clients
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} sent an invalid friend message")
        return _error(Exceptions.NOT_ALLOWED)
    # deliver_local checks the friendship
    return _answer(message_router.deliver_local(received))


@S2SRouter.post("/message_status")
async def message_status(payload: dict, request: Request):
    peer_url, failed = _peer(request)
    if failed:
        return failed
    sender_ip = payload.get("sender_ip")
    if not _belongs_to(sender_ip, peer_url):
        return _error(Exceptions.NOT_ALLOWED)
    return _answer(messenger_service.get_local_status(payload.get("message_id"), sender_ip))
# endregion server to server
