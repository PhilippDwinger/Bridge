import asyncio
import datetime
import json
import random
import time

from bridge import errors
from bridge.banker import client_key_store, mailbox_store, status_store, task_store
from bridge.core import address, clients, protocol
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.messenger import router
from bridge.messenger import service as messenger_service
from bridge.messenger.message import ContentType, MessageMode, create_message, encode_content, get_size_limit_bytes
from bridge.realm import service as realm_service
from bridge.server import s2s_client, url_env
from bridge.subservices import bridge_express as express
from bridge.subservices.bridge_agent import agent
from bridge.subservices.bridge_express import types as _express_types  # noqa: F401 (express.types)
from bridge.transfer.lua import normalize_lua_hybrid_tables

# Calling a command:
#   1. find every host of the command in the realms the caller is member of (+ the public realm of its server)
#   2. pick a host (strategy "least_busy" or "random"; hosts that were active recently are preferred)
#   3. send the host a "task" message: {"command_name", "command_args", "realm_address"}
#   4. the host answers with respond(task_id) -> "response" message to the caller (causation_id = task id)
# Call modes: wait_seconds = 0 returns at once, the response comes into the mailbox.
#             wait_seconds > 0 keeps the call open and returns the response directly if it comes in time.
# Clients can never send task or response messages themselves. That is why they are "verified":
#   - a task only exists after the realm allowed the call
#   - a response is only accepted from the host that got the task, only to the caller, only once

# fastest: the host with the shortest estimated total time (BridgeAgent), least_busy if the agent is off
STRATEGIES = ("least_busy", "random", "fastest")
# What the caller accepts from the host while the task runs: nothing, only the newest state, or every state
PROGRESS_MODES = ("off", "latest", "all")


def _host_info(client_ip):
    """{"points", "active"} of one of our clients or None."""
    client_key = clients.get_client_key_from_ip(client_ip) if address.is_local(client_ip) else None
    mailbox = mailbox_store.get_mailbox(client_key) if client_key else None
    entry = client_key_store.get_client_entry(client_key) if client_key else None
    if mailbox is None or entry is None:
        return None
    inactive_since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=protocol.host_inactive_seconds)
    return {"points": mailbox.get_busy_points(), "active": entry["last_signal"] >= inactive_since}


def get_local_busy_points(client_ips):
    # Answer for other servers - only our own clients
    return {client_ip: _host_info(client_ip) for client_ip in client_ips}


async def get_busy_points(client_ips):
    """Returns {client_ip: {"points", "active"} or None if unknown/unreachable}."""
    result = {}
    by_server = {}
    for client_ip in client_ips:
        server_url = address.server_of(client_ip)
        if server_url is None:
            result[client_ip] = None
        elif server_url == url_env.base_root:
            result[client_ip] = _host_info(client_ip)
        else:
            by_server.setdefault(server_url, []).append(client_ip)
    for server_url, server_ips in by_server.items():
        remote = await s2s_client.busy_points(server_url, server_ips)
        for client_ip in server_ips:
            info = remote.get(client_ip) if isinstance(remote, dict) else None
            valid = (isinstance(info, dict) and isinstance(info.get("points"), int)
                     and not isinstance(info.get("points"), bool))
            result[client_ip] = {"points": info["points"], "active": bool(info.get("active"))} if valid else None
    return result


def _choose_host(host_infos, strategy):
    reachable = {ip: info for ip, info in host_infos.items() if info is not None}
    if not reachable:
        return None
    # Hosts that made a request recently are preferred - inactive ones only if nobody else is there
    active = {ip: info for ip, info in reachable.items() if info["active"]} or reachable
    if strategy == "random":
        return random.choice(list(active))
    lowest = min(info["points"] for info in active.values())
    # Least busy host wins, random between equally busy hosts (Bridge 2 picked the busiest one)
    return random.choice([ip for ip, info in active.items() if info["points"] == lowest])


async def find_candidates(client_key, caller_ip, command_name, realm_address=None):
    """({host_ip: realm it was found in}, {realm: signature of the command there}) or an exception."""
    if realm_address is not None:
        realm_addresses = [realm_address]
    else:
        realm_addresses = [realm_service.get_public_realm_address()] + clients.get_realm_memberships(client_key)
        realm_addresses = list(dict.fromkeys(a for a in realm_addresses if a))
    candidates = {}
    signatures = {}
    for current_realm in realm_addresses:
        resolved = await realm_service.execute(caller_ip, current_realm, "resolve_call", {"command_name": command_name})
        if is_exception(resolved):
            if realm_address is not None:
                return resolved
            continue
        if not isinstance(resolved, dict) or not isinstance(resolved.get("hosts"), list):
            continue
        signature = resolved.get("signature")
        if signature is not None and address.server_of(current_realm) != url_env.base_root:
            # From another server: build it again from its texts (never use its type trees as they came)
            signature = express.from_remote(signature)
        signatures[current_realm] = signature
        for host_ip in resolved["hosts"]:
            if isinstance(host_ip, str):
                candidates.setdefault(host_ip, current_realm)
    if not candidates:
        errors.handle_error(Exceptions.COMMAND_NOT_FOUND, f"'{command_name}'")
        return Exceptions.COMMAND_NOT_FOUND
    return candidates, signatures


async def call_command(client_key, command_name, command_args=None, realm_address=None, mode=MessageMode.SAFE,
                       strategy="least_busy", wait_seconds=0, progress="off"):
    caller_ip = clients.get_client_ip(client_key)
    if caller_ip is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND)
        return Exceptions.CLIENT_NOT_FOUND
    if not isinstance(command_name, str) or not command_name:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "'command_name' must be a non-empty string")
        return Exceptions.ARGUMENT_ERROR
    if strategy not in STRATEGIES:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'strategy' must be one of {', '.join(STRATEGIES)}")
        return Exceptions.ARGUMENT_ERROR
    wait_seconds = messenger_service.check_wait_seconds(wait_seconds)
    if is_exception(wait_seconds):
        return wait_seconds
    if progress not in PROGRESS_MODES:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'progress' must be one of {', '.join(PROGRESS_MODES)}")
        return Exceptions.ARGUMENT_ERROR
    # Size and shape of the arguments first - before anything expensive (type check, finding hosts)
    encoded = encode_content(command_args)
    if is_exception(encoded):
        return encoded
    try:
        size_limit = get_size_limit_bytes(MessageMode(mode))
    except ValueError:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"'mode' must be one of {', '.join(MessageMode)}")
        return Exceptions.ARGUMENT_ERROR
    if len(encoded.encode("utf-8")) > size_limit:
        errors.handle_error(Exceptions.MESSAGE_TOO_LARGE, f"'{command_name}': arguments too big")
        return Exceptions.MESSAGE_TOO_LARGE

    if task_store.open_count(caller_ip)[0] >= protocol.max_open_tasks_per_client:
        errors.handle_error(Exceptions.NOT_ALLOWED, "too many open calls")
        errors.set_client_details(problems=[f"at most {protocol.max_open_tasks_per_client} calls can wait for an answer"])
        return Exceptions.NOT_ALLOWED

    found = await find_candidates(client_key, caller_ip, command_name, realm_address)
    if is_exception(found):
        return found
    candidates, signatures = found

    host_infos = await get_busy_points(list(candidates))
    host_ip = None
    if strategy == "fastest":
        from bridge.subservices.bridge_agent import service as agent_service
        host_ip = await agent_service.fastest_host(caller_ip, command_name, candidates, host_infos, command_args)
    if host_ip is None:
        host_ip = _choose_host(host_infos, "least_busy" if strategy == "fastest" else strategy)
    if host_ip is None:
        errors.handle_error(Exceptions.COMMAND_NOT_FOUND, f"'{command_name}': no host is reachable right now")
        return Exceptions.COMMAND_NOT_FOUND

    command_args = normalize_lua_hybrid_tables(command_args)
    content = {
        "command_name": command_name,
        "command_args": command_args,
        "realm_address": candidates[host_ip],
        # The host knows if sending progress makes sense (otherwise Bridge drops it)
        "accepts_progress": progress != "off",
        "progress_mode": progress,
    }
    signature = signatures.get(candidates[host_ip])
    if isinstance(signature, dict) and signature.get("validate") in ("strict", "warn"):
        problems = express.check_args(command_args, signature)
        if problems and signature["validate"] == "strict":
            errors.handle_error(Exceptions.ARGS_INVALID, f"'{command_name}': {problems}")
            errors.set_client_details(problems=problems, signature=_public_signature(signature))
            return Exceptions.ARGS_INVALID
        if problems:
            content["validation_problems"] = problems
        # The host's server checks the response against the return type (strict)
        content["response_check"] = {"type": signature["returns"], "tree": signature["returns_tree"],
                                     "validate": signature["validate"]}
    message = create_message(caller_ip, host_ip, content, ContentType.TASK, mode)
    if is_exception(message):
        return message
    # Registered before sending - a fast host could answer before the send call returns
    task_store.add_outgoing(message.message_id, caller_ip, host_ip, progress)
    started = time.monotonic()
    result = await router.deliver(message)
    if is_exception(result):
        task_store.remove_outgoing(message.message_id)
        return result
    agent.call_sent(message.message_id, candidates[host_ip], command_name, host_ip, router.route_of(host_ip),
                    len(message.payload), time.monotonic() - started)
    status_store.remember_sent(message)
    answer = {
        "task_id": message.message_id,
        "message_id": message.message_id,
        "conversation_id": message.conversation_id,
        "host_ip": host_ip,
        "realm_address": candidates[host_ip],
        "progress": progress,
        "response": None,
    }
    if wait_seconds > 0:
        answer["response"] = await _wait_for_response(client_key, message.message_id, wait_seconds)
    return answer


async def _wait_for_response(client_key, task_id, wait_seconds):
    """Waits for the response of our task and takes it out of the mailbox. None if it did not come in time
    (it then stays in the mailbox as a normal response)."""
    mailbox = mailbox_store.get_mailbox(client_key)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait_seconds
    while mailbox is not None:
        mailbox_store.get_signal(client_key).clear()
        message = mailbox.take_response(task_id)
        if message is not None:
            status_store.set_status(message, status_store.DELIVERED)
            return {"message": message.metadata(), "content": message.get_content()}
        remaining = deadline - loop.time()
        if remaining <= 0 or mailbox_store.closing:
            return None
        await messenger_service.wait_for_signal(client_key, remaining)
    return None


async def respond(client_key, task_id, content, mode=MessageMode.SAFE):
    """The host answers a task. Only possible once, only by the host that received it."""
    host_ip = clients.get_client_ip(client_key)
    if host_ip is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND)
        return Exceptions.CLIENT_NOT_FOUND
    incoming = task_store.get_incoming(task_id)
    if incoming is None or incoming["host_ip"] != host_ip:
        errors.handle_error(Exceptions.TASK_NOT_FOUND, "Respond to an unknown task or a task of another host")
        return Exceptions.TASK_NOT_FOUND
    response_check = incoming.get("response_check")
    if isinstance(response_check, dict) and response_check.get("validate") == "strict":
        problems = express.types.check_value(content, response_check["tree"], "response")
        if problems:
            # The task stays open - the host can send a fitting response
            errors.handle_error(Exceptions.RESPONSE_INVALID, f"Task {task_id}: {problems}")
            errors.set_client_details(problems=problems, returns=response_check.get("type"))
            return Exceptions.RESPONSE_INVALID
    message = create_message(
        host_ip, incoming["caller_ip"], content, ContentType.RESPONSE, mode,
        conversation_id=incoming["conversation_id"], causation_id=task_id,
    )
    if is_exception(message):
        return message
    result = await router.deliver(message)
    if is_exception(result):
        return result
    status_store.remember_sent(message)
    task_store.remove_incoming(task_id)
    agent.task_answered(task_id)
    return {"message_id": message.message_id, "task_id": task_id}


def _public_signature(signature):
    """Signature without the trees (short, for error details)."""
    return {"params": [{"name": param["name"], "type": param["type"], "optional": param["optional"]}
                       for param in signature["params"]],
            "returns": signature["returns"], "validate": signature["validate"]}


async def send_progress(client_key, task_id, content=None, percent=None):
    """The host reports an intermediate state of a task. Only the host of the task, only to the caller,
    only until the response. If the caller did not accept progress, it is dropped: delivered is False."""
    host_ip = clients.get_client_ip(client_key)
    if host_ip is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND)
        return Exceptions.CLIENT_NOT_FOUND
    if percent is not None and (isinstance(percent, bool) or not isinstance(percent, (int, float)) or not 0 <= percent <= 100):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "'percent' must be a number from 0 to 100")
        return Exceptions.ARGUMENT_ERROR
    incoming = task_store.get_incoming(task_id)
    if incoming is None or incoming["host_ip"] != host_ip:
        errors.handle_error(Exceptions.TASK_NOT_FOUND, "Progress for an unknown task, a task of another host or an answered task")
        return Exceptions.TASK_NOT_FOUND
    if not incoming.get("accepts_progress"):
        return {"delivered": False, "reason": "caller_does_not_accept_progress"}
    now = time.time()
    if now - incoming["progress_window"] >= 1:
        incoming["progress_window"], incoming["progress_count"] = now, 0
    if incoming["progress_count"] >= protocol.max_progress_per_second:
        return {"delivered": False, "reason": "too_many_per_second"}
    incoming["progress_count"] += 1
    message = create_message(
        host_ip, incoming["caller_ip"], {"percent": percent, "content": content}, ContentType.PROGRESS, MessageMode.FAST,
        conversation_id=incoming["conversation_id"], causation_id=task_id,
    )
    if is_exception(message):
        return message
    if len(message.payload.encode("utf-8")) > protocol.max_progress_kib * 1024:
        errors.handle_error(Exceptions.MESSAGE_TOO_LARGE, f"Progress may have up to {protocol.max_progress_kib} KiB")
        return Exceptions.MESSAGE_TOO_LARGE
    result = await router.deliver(message)
    if is_exception(result):
        return result
    if result is False:
        return {"delivered": False, "reason": "caller_does_not_accept_progress"}
    return {"delivered": True, "message_id": message.message_id, "task_id": task_id}


async def verify_remote_task(message, peer_url):
    """A task that came from another server: check again that the realm allows this caller to use this host."""
    try:
        content = json.loads(message.payload)
        command_name = content["command_name"]
        realm_address = content["realm_address"]
    except (ValueError, TypeError, KeyError):
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} sent a task without command data")
        return Exceptions.NOT_ALLOWED
    if not isinstance(command_name, str) or not address.is_valid_address(realm_address):
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} sent a task with invalid command data")
        return Exceptions.NOT_ALLOWED
    if address.server_of(realm_address) == peer_url:
        # The realm lives on the sending server itself - it already checked it, asking it again proves nothing
        return True
    hosts = await realm_service.execute(message.sender_ip, realm_address, "resolve_hosts", {"command_name": command_name})
    if is_exception(hosts) or not isinstance(hosts, list) or message.recipient_ip not in hosts:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{peer_url} sent a task the realm does not allow")
        return Exceptions.NOT_ALLOWED
    return True
