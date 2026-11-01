from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from bridge import errors
from bridge.banker import backup_store, friend_store, trust_store
from bridge.core import address
from bridge.errors.exceptions import Exceptions, get_exception_id, is_exception
from bridge.messenger import router
from bridge.messenger.message import ContentType, message_from_dict
from bridge.core import backup, protocol
from bridge.messenger import service as messenger_service
from bridge.realm import commands, service as realm_service, sync as realm_sync, topics
from bridge.security.hasher import sha256_hex
from bridge.server import s2s_client, url_env
from bridge.subservices.bridge_agent import agent, routing, service as agent_service

# Endpoints only for other Bridge servers. Answers are always {"ok": true, "result": ...}
# or {"ok": false, "error": "<EXCEPTION_ID>"} so the calling server can map the error back.

Router = APIRouter(prefix="/s2s")

MAX_BUSY_IPS = 200


def _ok(result=True):
    return {"ok": True, "result": result}

def _error(error, status_code=200):
    if not is_exception(error):
        error = Exceptions.UNKNOWN_ERROR
    content = {
        "ok": False,
        "error": get_exception_id(error),
        "message": error.default_message,
    }
    details = errors.pop_client_details()
    if details:
        content["details"] = details
    return JSONResponse(status_code=status_code, content=content)

def _answer(result):
    return _error(result) if is_exception(result) else _ok(result)

def _authenticate_server(request):
    """Returns the URL of the calling trusted server or None."""
    from_url = address.normalize_url(request.headers.get(s2s_client.HEADER_FROM))
    token = request.headers.get(s2s_client.HEADER_TOKEN)
    if from_url is None or token is None or not trust_store.verify_token(from_url, token):
        errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"Rejected server request from {from_url!r}")
        return None
    return from_url

def _trusted_peer_from_body(payload):
    from_url = address.normalize_url(payload.get("from_url")) if isinstance(payload, dict) else None
    if from_url is None or not trust_store.is_trusted(from_url) or from_url == url_env.base_root:
        errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"Handshake from untrusted server {from_url!r}")
        return None
    return from_url


# region handshake (no token yet)
@Router.post("/handshake/hello")
async def handshake_hello(payload: dict):
    peer_url = _trusted_peer_from_body(payload)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    if not s2s_client.is_generator_for(peer_url):
        # The caller is the generator itself - it should deliver instead of saying hello
        return _error(Exceptions.ARGUMENT_ERROR)
    return _answer(await s2s_client.handshake(peer_url))


@Router.post("/handshake/deliver")
async def handshake_deliver(payload: dict):
    peer_url = _trusted_peer_from_body(payload)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    secret = payload.get("secret")
    if not isinstance(secret, str) or len(secret) < 32 or s2s_client.is_generator_for(peer_url):
        return _error(Exceptions.ARGUMENT_ERROR)
    # Call back the server at its registered URL - only the real server can confirm the secret
    try:
        status, data = await s2s_client._post(peer_url, "/s2s/handshake/confirm", {
            "from_url": url_env.base_root,
            "secret_sha256": sha256_hex(secret),
        })
    except Exception as error:
        errors.handle_error(Exceptions.REMOTE_SERVER_ERROR, f"Confirm callback to {peer_url} failed: {error!r}")
        return _error(Exceptions.REMOTE_SERVER_ERROR)
    if status != 200 or not isinstance(data, dict) or not data.get("ok"):
        errors.handle_error(Exceptions.SERVER_NOT_TRUSTED, f"{peer_url} did not confirm the handshake secret")
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    trust_store.set_connected(peer_url, secret)
    errors.debug_print(f"Connected with trusted server {peer_url}")
    s2s_client._after_connect(peer_url)
    return _ok()


@Router.post("/handshake/confirm")
async def handshake_confirm(payload: dict):
    peer_url = _trusted_peer_from_body(payload)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    if not s2s_client.confirm_secret_hash(peer_url, payload.get("secret_sha256")):
        errors.handle_error(Exceptions.NOT_ALLOWED, f"Unknown handshake secret for {peer_url}")
        return _error(Exceptions.NOT_ALLOWED, 403)
    return _ok()
# endregion handshake


# region authorized
@Router.post("/ping")
async def ping(request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    return _ok({"url": url_env.base_root})


@Router.post("/message")
async def receive_message(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    message = message_from_dict(payload.get("message"))
    if is_exception(message):
        return _error(message)
    if address.server_of(message.recipient_ip) != url_env.base_root:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} sent a message for a client of another server")
        return _error(Exceptions.NOT_ALLOWED)
    if message.relayed_via:
        # A direct message that the peer passed on for a third server. The sender must be a client of that third
        # server - never one of ours or of the relaying peer (otherwise the peer could fake our own clients).
        sender_server = address.server_of(message.sender_ip)
        if (not protocol.accept_relayed or message.content_type != ContentType.DIRECT
                or message.relayed_via != [peer_url] or sender_server in (url_env.base_root, peer_url, None)
                or friend_store.is_blocked(sender_server)):
            errors.handle_error(Exceptions.NOT_ALLOWED, f"Relayed message from {peer_url} rejected")
            return _error(Exceptions.NOT_ALLOWED)
    elif address.server_of(message.sender_ip) != peer_url:
        # Without relaying a server may only send messages of its own clients
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} sent a message with a foreign sender IP")
        return _error(Exceptions.NOT_ALLOWED)
    if message.content_type == ContentType.INSTRUCTION:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} tried to send an instruction")
        return _error(Exceptions.NOT_ALLOWED)
    if message.content_type == ContentType.FRIEND:
        # Friend messages only come over /s2s/friends/message (that checks the friendship and the block list)
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} sent a friend message to /s2s/message")
        return _error(Exceptions.NOT_ALLOWED)
    if message.content_type == ContentType.TASK:
        # Check the realm again instead of only trusting the other server
        verified = await commands.verify_remote_task(message, peer_url)
        if is_exception(verified):
            return _error(verified)
    if message.content_type == ContentType.EVENT:
        verified = await topics.verify_remote_event(message, peer_url)
        if is_exception(verified):
            return _error(verified)
    # Responses are checked in router.deliver_local against the task we sent
    return _answer(router.deliver_local(message))


@Router.post("/relay")
async def relay(payload: dict, request: Request):
    # The peer asks us to pass a direct message on to a server it does not trust (but we do)
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    message = message_from_dict(payload.get("message"))
    if is_exception(message):
        return _error(message)
    return _answer(await router.relay_for_peer(message, peer_url))


@Router.post("/status")
async def message_status(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    sender_ip = payload.get("sender_ip")
    if address.server_of(sender_ip) != peer_url:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} asked for a message of a foreign client")
        return _error(Exceptions.NOT_ALLOWED)
    return _answer(messenger_service.get_local_status(payload.get("message_id"), sender_ip))


@Router.post("/realm")
async def realm_action(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    caller_ip = payload.get("caller_ip")
    if address.server_of(caller_ip) != peer_url:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} acted for a client of another server")
        return _error(Exceptions.NOT_ALLOWED)
    return _answer(realm_service.execute_local(
        caller_ip, payload.get("realm_address"), payload.get("action"), payload.get("params"),
    ))


# region agent
@Router.post("/links")
async def links(request: Request):
    # Our lines to our partners - other servers use it to find ways around broken or slow lines
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    return _ok({"links": routing.link_table(), "relays": protocol.relay_mode == "trusted"})


@Router.post("/agent/hosts")
async def agent_hosts(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    if not agent.enabled():
        return _error(Exceptions.AGENT_OFF)
    hosts = payload.get("hosts")
    if not isinstance(hosts, list) or len(hosts) > agent_service.MAX_HOSTS:
        return _error(Exceptions.ARGUMENT_ERROR)
    return _ok(agent_service.local_host_reports([entry for entry in hosts if isinstance(entry, dict)]))


@Router.post("/agent/task")
async def agent_task(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    caller_ip = payload.get("caller_ip")
    if address.server_of(caller_ip) != peer_url:
        return _error(Exceptions.NOT_ALLOWED)
    if not agent.enabled():
        return _error(Exceptions.AGENT_OFF)
    return _ok(agent_service.local_task_status(payload.get("task_id"), caller_ip))


@Router.post("/agent/client")
async def agent_client(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    asking_ip = payload.get("asking_ip")
    if address.server_of(asking_ip) != peer_url:
        return _error(Exceptions.NOT_ALLOWED)
    if not agent.enabled():
        return _error(Exceptions.AGENT_OFF)
    return _ok(agent_service.local_client_info(payload.get("client_ip"), asking_ip))
# endregion agent


# region realm sync
MAX_SYNC_REALMS = 1000

@Router.post("/realm/push")
async def realm_push(payload: dict, request: Request):
    # The realm server tells us about a change in one of its realms
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    return _answer(realm_sync.apply_view(payload.get("view"), peer_url))


@Router.post("/realm/versions")
async def realm_versions(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    if not backup.is_ready():
        # While we restore our backup, "realm not found" would be wrong - ask again later
        return _error(Exceptions.SERVER_STARTING)
    realm_addresses = payload.get("realm_addresses")
    if not isinstance(realm_addresses, list) or len(realm_addresses) > MAX_SYNC_REALMS:
        return _error(Exceptions.ARGUMENT_ERROR)
    return _ok(realm_sync.versions_for([realm for realm in realm_addresses if isinstance(realm, str)], peer_url))


@Router.post("/realm/mirror")
async def realm_mirror(payload: dict, request: Request):
    # Only the part the asking server may know: its own members and what they may see
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    if not backup.is_ready():
        return _error(Exceptions.SERVER_STARTING)
    view = realm_sync.mirror_for(payload.get("realm_address"), peer_url)
    return _ok(view if view is not None else {"found": False})
# endregion realm sync


@Router.post("/realm/code")
async def realm_code_join(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    caller_ip = payload.get("caller_ip")
    if address.server_of(caller_ip) != peer_url:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} acted for a client of another server")
        return _error(Exceptions.NOT_ALLOWED)
    return _answer(realm_service.join_by_code_local(caller_ip, payload.get("code")))


@Router.post("/busy")
async def busy(payload: dict, request: Request):
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    client_ips = payload.get("client_ips")
    if not isinstance(client_ips, list) or len(client_ips) > MAX_BUSY_IPS:
        return _error(Exceptions.ARGUMENT_ERROR)
    return _ok(commands.get_local_busy_points([ip for ip in client_ips if isinstance(ip, str)]))
# endregion authorized


# region backup
@Router.post("/backup/store")
async def store_backup(payload: dict, request: Request):
    # Keep the encrypted backup of a trusted server. We cannot read it.
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    blob = payload.get("backup")
    if not isinstance(blob, dict) or blob.get("server_url") != peer_url or not isinstance(blob.get("data"), str):
        return _error(Exceptions.ARGUMENT_ERROR)
    size = backup.blob_size(blob)
    if size > protocol.max_backup_mb * 1024 * 1024:
        return _error(Exceptions.MESSAGE_TOO_LARGE)
    epoch = blob.get("epoch", 0)
    if not isinstance(epoch, int) or isinstance(epoch, bool):
        epoch = 0
    if not backup_store.store(peer_url, blob, size, epoch):
        return _error(Exceptions.SERVER_FULL)
    return _ok()


@Router.post("/backup/relay")
async def relay_backup(payload: dict, request: Request):
    # A trusted server hands us the backup of ANOTHER server to keep (resilience: A -> B, B relays A's backup to C).
    # We still cannot read it; we only keep the newest copy per owner. The owner gets it back via /backup/fetch.
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    blob = payload.get("backup")
    if not isinstance(blob, dict) or not isinstance(blob.get("data"), str):
        return _error(Exceptions.ARGUMENT_ERROR)
    owner_url = address.normalize_url(blob.get("server_url"))
    if owner_url is None or owner_url == url_env.base_root:
        # No valid owner, or it is our own backup - we never keep our own
        return _error(Exceptions.ARGUMENT_ERROR)
    epoch = blob.get("epoch", 0)
    if not isinstance(epoch, int) or isinstance(epoch, bool):
        return _error(Exceptions.ARGUMENT_ERROR)
    size = backup.blob_size(blob)
    if size > protocol.max_backup_mb * 1024 * 1024:
        return _error(Exceptions.MESSAGE_TOO_LARGE)
    if not backup_store.store(owner_url, blob, size, epoch):
        return _error(Exceptions.SERVER_FULL)
    return _ok()


@Router.post("/backup/fetch")
async def fetch_backup(request: Request):
    # A trusted server asks for its own backup (only its own - keyed by the caller's URL)
    peer_url = _authenticate_server(request)
    if peer_url is None:
        return _error(Exceptions.SERVER_NOT_TRUSTED, 403)
    return _ok(backup_store.fetch(peer_url))
# endregion backup
