"""BridgeAgent answers for clients. Each server knows its own clients best, so the knowledge is combined:
the host's server knows its queue, how fast it takes tasks and how long it works; the caller's server knows the way
there (delivery, server to server). Clients still only ask their own server (pull only).
"""
import datetime
import json
import math
import time

from bridge import errors
from bridge.banker import client_key_store, mailbox_store, task_store
from bridge.core import address, clients, protocol
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.server import s2s_client, url_env
from bridge.subservices.bridge_agent import agent

MAX_HOSTS = 200


def _expired(task_id, entry):
    agent.task_expired(task_id, entry.get("host_ip"))

task_store.on_incoming_expired.append(_expired)


def _check_enabled():
    if not agent.enabled():
        errors.handle_error(Exceptions.AGENT_OFF)
        return Exceptions.AGENT_OFF
    return None

def _size(value):
    try:
        return len(json.dumps(value, separators=(",", ":")))
    except (TypeError, ValueError):
        return 0

def _estimate_part(value):
    """{"typical_s", "worst_s", ...} from another server - finite, not negative, or None."""
    if not isinstance(value, dict):
        return None
    numbers = []
    for key in ("typical_s", "worst_s"):
        number = value.get(key)
        if isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(number) or number < 0:
            return None
        numbers.append(min(float(number), 365 * 24 * 3600.0))
    based_on = value.get("based_on")
    return {"typical_s": numbers[0], "worst_s": numbers[1], "based_on": based_on if isinstance(based_on, str) and len(based_on) <= 32 else None}


def _plain(value, depth=0):
    """Any answer of another server, reduced to plain, safe JSON (short texts, finite numbers, small objects)."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value if math.isfinite(value) and abs(value) < 1e15 else None
    if isinstance(value, str):
        return value[:300] if not _broken_text(value) else None
    if isinstance(value, dict) and depth < 3:
        return {key[:64]: _plain(item, depth + 1) for key, item in list(value.items())[:40]
                if isinstance(key, str) and not _broken_text(key)}
    return None


def _broken_text(text):
    try:
        text.encode("utf-8")
        return False
    except UnicodeEncodeError:
        return True


def _clean_report(report):
    """A host report of another server: only the known fields, with checked types (it is shown to our clients and
    used to choose hosts)."""
    if not isinstance(report, dict):
        return None
    wait, processing = _estimate_part(report.get("wait")), _estimate_part(report.get("processing"))
    if wait is None or processing is None:
        return None
    queue = report.get("queue", 0)
    reliability = report.get("reliability", 1.0)
    return {
        "wait": wait,
        "processing": processing,
        "queue": queue if isinstance(queue, int) and not isinstance(queue, bool) and 0 <= queue <= 10 ** 6 else 0,
        "active": report.get("active") is not False,
        "reliability": (min(max(float(reliability), 0.0), 1.0) if isinstance(reliability, (int, float))
                        and not isinstance(reliability, bool) and math.isfinite(reliability) else 1.0),
    }


def _sum(*parts):
    return {"typical_s": round(sum(part["typical_s"] for part in parts), 4),
            "worst_s": round(sum(part["worst_s"] for part in parts), 4)}


# region host side (our own clients)
def _task_queue(mailbox):
    from bridge.messenger.mailbox import PoolName
    pending = sum(1 for entry in mailbox.pending_messages.values() if entry["pool_name"] == PoolName.TASK)
    return mailbox.waiting_count(PoolName.TASK) + pending

def local_host_reports(entries):
    """For hosts of this server: queue, how long until they take a task, how long they work on it."""
    from bridge.realm import commands
    reports = {}
    for entry in entries[:MAX_HOSTS]:
        host_ip = entry.get("host_ip")
        if not isinstance(host_ip, str) or address.server_of(host_ip) != url_env.base_root:
            continue
        info = commands._host_info(host_ip)
        client_key = clients.get_client_key_from_ip(host_ip)
        mailbox = mailbox_store.get_mailbox(client_key) if client_key else None
        if info is None or mailbox is None:
            reports[host_ip] = None
            continue
        queue = _task_queue(mailbox)
        reports[host_ip] = {
            "active": info["active"],
            "busy_points": info["points"],
            "queue": queue,
            "reliability": agent.host_reliability(host_ip),
            # The waiting time already includes the tasks ahead (learned with the queue length)
            "wait": agent.pickup_estimate(host_ip, queue),
            "processing": agent.process_estimate(entry.get("realm_address"), entry.get("command_name"), host_ip,
                                                 entry.get("size") or 0),
        }
    return reports

def local_task_status(task_id, caller_ip):
    """Where a task is right now - for the caller's server."""
    incoming = task_store.get_incoming(task_id)
    if incoming is None or incoming["caller_ip"] != caller_ip:
        return {"state": "answered_or_expired"}
    from bridge.realm import commands
    host_ip = incoming["host_ip"]
    client_key = clients.get_client_key_from_ip(host_ip)
    mailbox = mailbox_store.get_mailbox(client_key) if client_key else None
    info = commands._host_info(host_ip) or {"active": False}
    tracked = agent.host_tasks.get(task_id) or {}
    realm_address, command_name = tracked.get("realm"), tracked.get("command")
    state = {"state": "processing", "active": info["active"], "reliability": agent.host_reliability(host_ip)}
    if mailbox is not None:
        for index, message in enumerate(mailbox.task_pool):
            if message.message_id == task_id:
                state.update(state="waiting", position=index + 1, queue=len(mailbox.task_pool))
                break
        else:
            for entry in mailbox.pending_messages.values():
                if entry["message"].message_id == task_id:
                    since = datetime.datetime.now(datetime.timezone.utc) - entry["pending_since"]
                    state["processing_since_s"] = round(since.total_seconds(), 2)
                    break
    if state["state"] == "processing" and "processing_since_s" not in state and tracked.get("taken") is not None:
        state["processing_since_s"] = round(time.monotonic() - tracked["taken"], 2)
    state["processing"] = agent.process_estimate(realm_address, command_name, host_ip, 0)
    if state["state"] == "waiting":
        state["wait"] = agent.pickup_estimate(host_ip, state["position"] - 1)
    return state

def local_client_info(client_ip, asking_ip):
    """How quickly one of our clients takes messages - for a sender (only if it may send direct messages)."""
    client_key = clients.get_client_key_from_ip(client_ip)
    mailbox = mailbox_store.get_mailbox(client_key) if client_key else None
    entry = client_key_store.get_client_entry(client_key) if client_key else None
    if entry is None or mailbox is None:
        return {"known": False}
    if not clients.accepts_direct(client_key, asking_ip):
        # Who does not accept our messages does not tell us when it is online either
        return {"known": True, "accepts_direct": False}
    from bridge.messenger.mailbox import PoolName
    last_seen = (datetime.datetime.now(datetime.timezone.utc) - entry["last_signal"]).total_seconds()
    waiting = mailbox.waiting_count(PoolName.DIRECT)
    return {
        "known": True,
        "accepts_direct": True,
        "active": last_seen <= protocol.host_inactive_seconds,
        "last_seen_s": round(last_seen, 1),
        "waiting": waiting,
        "pickup": agent.pickup_estimate(client_ip, waiting),
    }
# endregion host side


# region caller side (combining)
async def host_reports(caller_ip, command_name, candidates, size_bytes):
    """{host_ip: report or None} with the whole estimated time (there, waiting, working, back)."""
    from bridge.messenger import router
    by_server = {}
    for host_ip, realm_address in candidates.items():
        by_server.setdefault(address.server_of(host_ip), []).append(
            {"host_ip": host_ip, "realm_address": realm_address, "command_name": command_name, "size": size_bytes})
    reports = {}
    for server_url, entries in by_server.items():
        if server_url == url_env.base_root:
            found = local_host_reports(entries)
        else:
            found = await s2s_client.agent_hosts(server_url, entries)
            if is_exception(found) or not isinstance(found, dict):
                found = {}
            found = {host_ip: _clean_report(report) for host_ip, report in found.items()}
        for entry in entries:
            host_ip = entry["host_ip"]
            report = found.get(host_ip)
            if not isinstance(report, dict) or not isinstance(report.get("wait"), dict) or not isinstance(report.get("processing"), dict):
                reports[host_ip] = None
                continue
            arrival = agent.deliver_estimate(router.route_of(host_ip), size_bytes)
            total = _sum(arrival, report["wait"], report["processing"], arrival)
            observed = agent.roundtrip_observed(entry["realm_address"], command_name, host_ip)
            if observed is not None and report.get("queue", 0) == 0:
                # Own experience with exactly this host beats the sum of the parts
                total = {"typical_s": observed["typical_s"], "worst_s": observed["worst_s"]}
            reports[host_ip] = dict(report, arrival=arrival, observed_roundtrip=observed, **total)
    return reports

def _score(report):
    """Lower is better: estimated time, a bit longer for unreliable and much longer for inactive hosts."""
    score = report["typical_s"] / max(report.get("reliability", 1.0), 0.1)
    return score if report.get("active", True) else score * 10

async def fastest_host(caller_ip, command_name, candidates, host_infos, command_args=None):
    """Used by strategy=fastest. None -> the caller falls back to least_busy."""
    if not agent.enabled():
        return None
    reachable = {ip: realm for ip, realm in candidates.items() if host_infos.get(ip) is not None}
    if not reachable:
        return None
    reports = await host_reports(caller_ip, command_name, reachable, _size(command_args))
    usable = [(ip, report) for ip, report in reports.items() if report is not None]
    if not usable:
        return None
    return min(usable, key=lambda item: _score(item[1]))[0]

async def estimate(client_key, command_name, realm_address=None, command_args=None):
    """Before a call: how long will it take, which host is best, which wait_seconds makes sense."""
    off = _check_enabled()
    if off:
        return off
    from bridge.realm import commands
    caller_ip = clients.get_client_ip(client_key)
    found = await commands.find_candidates(client_key, caller_ip, command_name, realm_address)
    if is_exception(found):
        return found
    candidates, _ = found
    reports = await host_reports(caller_ip, command_name, candidates, _size(command_args))
    hosts = [dict(report, host_ip=ip, realm_address=candidates[ip]) for ip, report in reports.items() if report]
    if not hosts:
        errors.handle_error(Exceptions.COMMAND_NOT_FOUND, f"'{command_name}': no host can be reached for an estimate")
        return Exceptions.COMMAND_NOT_FOUND
    hosts.sort(key=_score)
    best = hosts[0]
    wait_seconds = math.ceil(best["worst_s"]) if best["worst_s"] <= protocol.max_wait_seconds else None
    return {
        "command_name": command_name,
        "recommended_host": best["host_ip"],
        "typical_s": best["typical_s"],
        "worst_s": best["worst_s"],
        "recommended_wait_seconds": wait_seconds,
        "hint": None if wait_seconds is not None else
        f"Probably longer than {protocol.max_wait_seconds} s - call without waiting and poll the response later",
        "hosts": hosts,
    }

async def task_status(client_key, task_id):
    """How a called task is doing: waiting (position) / being processed (since, progress), rest time, risk."""
    off = _check_enabled()
    if off:
        return off
    from bridge.messenger import router
    caller_ip = clients.get_client_ip(client_key)
    outgoing = task_store.get_outgoing(task_id)
    if outgoing is None or outgoing["caller_ip"] != caller_ip:
        mailbox = mailbox_store.get_mailbox(client_key)
        if mailbox is not None and any(getattr(message, "causation_id", None) == task_id for message in mailbox.response_pool):
            return {"task_id": task_id, "state": "answered", "response_waiting": True}
        errors.handle_error(Exceptions.TASK_NOT_FOUND, "Unknown task, a task of another client, or the response was taken")
        return Exceptions.TASK_NOT_FOUND
    host_ip = outgoing["host_ip"]
    server_url = address.server_of(host_ip)
    if server_url == url_env.base_root:
        remote = local_task_status(task_id, caller_ip)
    else:
        remote = await s2s_client.agent_task(server_url, task_id, caller_ip)
        if is_exception(remote) or not isinstance(remote, dict):
            remote = {"state": "unknown", "reason": "the host's server cannot be reached"}
        else:
            remote = _plain(remote)
            for key in ("wait", "processing"):
                if key in remote:
                    remote[key] = _estimate_part(remote[key])
    elapsed = time.time() - outgoing.get("sent_at", time.time())
    percent = outgoing.get("last_percent")
    result = {"task_id": task_id, "host_ip": host_ip, "elapsed_s": round(elapsed, 2), "progress_percent": percent}
    result.update({key: value for key, value in remote.items() if key not in ("wait",)})
    back = agent.deliver_estimate(router.route_of(host_ip))
    processing = remote.get("processing")
    remaining = None
    if remote.get("state") == "waiting" and isinstance(processing, dict) and isinstance(remote.get("wait"), dict):
        remaining = _sum(remote["wait"], processing, back)
    elif remote.get("state") == "processing" and isinstance(processing, dict):
        since = remote.get("processing_since_s") or 0.0
        typical = max(processing["typical_s"] - since, 0.0)
        worst = max(processing["worst_s"] - since, typical)
        if isinstance(percent, (int, float)) and 3 <= percent < 100 and since > 0.2:
            # The host reports progress: the time so far tells how long the rest takes
            typical = since * (100 - percent) / percent
            worst = max(worst, typical * 1.5)
        remaining = _sum({"typical_s": typical, "worst_s": worst}, back)
    result["remaining"] = remaining
    time_left = protocol.command_response_minutes * 60 - elapsed
    if remote.get("state") in ("unknown", "answered_or_expired"):
        risk = "unknown"
    elif not remote.get("active", True) and remote.get("state") == "waiting":
        risk = "high"
    elif remaining is not None and remaining["worst_s"] > time_left:
        risk = "high"
    elif remote.get("reliability", 1.0) < 0.7:
        risk = "medium"
    else:
        risk = "low"
    result["risk_of_expiry"] = risk
    return result

async def message_info(client_key, recipient_ip):
    """Before/after a direct message: how fast does the recipient usually take messages?"""
    off = _check_enabled()
    if off:
        return off
    from bridge.messenger import router
    sender_ip = clients.get_client_ip(client_key)
    server_url = address.server_of(recipient_ip)
    if server_url is None:
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Invalid recipient IP: {recipient_ip!r}")
        return Exceptions.ARGUMENT_ERROR
    if server_url == url_env.base_root:
        info = local_client_info(recipient_ip, sender_ip)
    elif trust_ok(server_url):
        info = await s2s_client.agent_client(server_url, recipient_ip, sender_ip)
        if is_exception(info) or not isinstance(info, dict):
            info = {"known": None, "reason": "the recipient's server cannot be reached"}
        else:
            info = _plain(info)
            if "pickup" in info:
                info["pickup"] = _estimate_part(info["pickup"])
    else:
        info = {"known": None, "reason": "the recipient's server is not trusted by this server (relayed messages)"}
    arrival = agent.deliver_estimate(router.route_of(recipient_ip))
    result = {"recipient_ip": recipient_ip, "arrival": arrival, **info}
    if isinstance(info.get("pickup"), dict):
        result["until_taken"] = _sum(arrival, info["pickup"])
    return result

def trust_ok(server_url):
    from bridge.banker import trust_store
    return trust_store.is_trusted(server_url)
# endregion caller side
