import asyncio
import datetime
import json
import random

from bridge import errors
from bridge.banker import client_key_store, mailbox_store, status_store, task_store
from bridge.core import address, clients, protocol
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.messenger import router
from bridge.messenger import service as messenger_service
from bridge.messenger.message import ContentType, MessageMode, create_message
from bridge.realm import service as realm_service
from bridge.server import s2s_client, url_env
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

STRATEGIES = ("least_busy", "random")


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


async def call_command(client_key, command_name, command_args=None, realm_address=None, mode=MessageMode.SAFE,
                       strategy="least_busy", wait_seconds=0):
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

    if realm_address is not None:
        realm_addresses = [realm_address]
    else:
        realm_addresses = [realm_service.get_public_realm_address()] + clients.get_realm_memberships(client_key)
        realm_addresses = list(dict.fromkeys(a for a in realm_addresses if a))

    # host_ip -> realm the host was found in
    candidates = {}
    for current_realm in realm_addresses:
        hosts = await realm_service.execute(caller_ip, current_realm, "resolve_hosts", {"command_name": command_name})
        if is_exception(hosts):
            if realm_address is not None:
                return hosts
            continue
        if not isinstance(hosts, list):
            continue
        for host_ip in hosts:
            if isinstance(host_ip, str):
                candidates.setdefault(host_ip, current_realm)
    if not candidates:
        errors.handle_error(Exceptions.COMMAND_NOT_FOUND, f"'{command_name}'")
        return Exceptions.COMMAND_NOT_FOUND

    host_ip = _choose_host(await get_busy_points(list(candidates)), strategy)
    if host_ip is None:
        errors.handle_error(Exceptions.COMMAND_NOT_FOUND, f"'{command_name}': no host is reachable right now")
        return Exceptions.COMMAND_NOT_FOUND

    content = {
        "command_name": command_name,
        "command_args": normalize_lua_hybrid_tables(command_args),
        "realm_address": candidates[host_ip],
    }
    message = create_message(caller_ip, host_ip, content, ContentType.TASK, mode)
    if is_exception(message):
        return message
    # Registered before sending - a fast host could answer before the send call returns
    task_store.add_outgoing(message.message_id, caller_ip, host_ip)
    result = await router.deliver(message)
    if is_exception(result):
        task_store.remove_outgoing(message.message_id)
        return result
    status_store.remember_sent(message)
    answer = {
        "task_id": message.message_id,
        "message_id": message.message_id,
        "conversation_id": message.conversation_id,
        "host_ip": host_ip,
        "realm_address": candidates[host_ip],
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
        if remaining <= 0:
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
    return {"message_id": message.message_id, "task_id": task_id}


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
