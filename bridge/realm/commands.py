import random

from bridge import errors
from bridge.banker import mailbox_store
from bridge.core import address, clients
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.messenger import service as messenger_service
from bridge.messenger.message import ContentType, MessageMode
from bridge.realm import service as realm_service
from bridge.server import s2s_client, url_env
from bridge.transfer.lua import normalize_lua_hybrid_tables

# Calling a command:
#   1. find every host of the command in the realms the caller is member of (+ the public realm of its server)
#   2. pick the least busy host (busy points of its mailbox; hosts on other servers are asked via server to server)
#   3. send the host a "task" message: {"command_name", "command_args", "realm_address"}
#   4. the host answers with a normal "response" message (causation_id = message_id of the task)


async def get_busy_points(client_ips):
    """Returns {client_ip: busy points or None if unknown/unreachable}."""
    result = {}
    by_server = {}
    for client_ip in client_ips:
        server_url = address.server_of(client_ip)
        if server_url is None:
            result[client_ip] = None
        elif server_url == url_env.base_root:
            client_key = clients.get_client_key_from_ip(client_ip)
            mailbox = mailbox_store.get_mailbox(client_key) if client_key else None
            result[client_ip] = mailbox.get_busy_points() if mailbox else None
        else:
            by_server.setdefault(server_url, []).append(client_ip)
    for server_url, server_ips in by_server.items():
        remote_points = await s2s_client.busy_points(server_url, server_ips)
        for client_ip in server_ips:
            points = remote_points.get(client_ip) if isinstance(remote_points, dict) else None
            result[client_ip] = points if isinstance(points, int) and not isinstance(points, bool) else None
    return result


def get_local_busy_points(client_ips):
    # Answer for other servers - only our own clients
    result = {}
    for client_ip in client_ips:
        client_key = clients.get_client_key_from_ip(client_ip) if address.is_local(client_ip) else None
        mailbox = mailbox_store.get_mailbox(client_key) if client_key else None
        result[client_ip] = mailbox.get_busy_points() if mailbox else None
    return result


async def call_command(client_key, command_name, command_args=None, realm_address=None, mode=MessageMode.SAFE):
    caller_ip = clients.get_client_ip(client_key)
    if caller_ip is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND)
        return Exceptions.CLIENT_NOT_FOUND
    if not isinstance(command_name, str) or not command_name:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, "'command_name' must be a non-empty string")
        return Exceptions.ARGUMENT_ERROR

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

    busy_points = await get_busy_points(list(candidates))
    reachable = {host_ip: points for host_ip, points in busy_points.items() if points is not None}
    if not reachable:
        errors.handle_error(Exceptions.COMMAND_NOT_FOUND, f"'{command_name}': no host is reachable right now")
        return Exceptions.COMMAND_NOT_FOUND
    lowest = min(reachable.values())
    # Least busy host wins, random between equally busy hosts (Bridge 2 picked the busiest one)
    host_ip = random.choice([ip for ip, points in reachable.items() if points == lowest])

    content = {
        "command_name": command_name,
        "command_args": normalize_lua_hybrid_tables(command_args),
        "realm_address": candidates[host_ip],
    }
    message = await messenger_service.send(client_key, host_ip, content, ContentType.TASK, mode)
    if is_exception(message):
        return message
    return {
        "message_id": message.message_id,
        "conversation_id": message.conversation_id,
        "host_ip": host_ip,
        "realm_address": candidates[host_ip],
    }
