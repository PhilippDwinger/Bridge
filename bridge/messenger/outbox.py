"""Everything a client sends as direct message: now or planned, to one or to many (broadcast), with a lifetime.

Times (see core/timing.py) are a timer in seconds or a point in time with timezone:
    send_in_seconds / send_at      when the message is sent (planned message)
    expires_in_seconds / expires_at  how long it lives - a timer counts from the real send time
If send_at is already over: if_past = "send" (default, sent at once + warning) or "reject" (400 SEND_TIME_PASSED).
Planned messages wait on the sender's server (part of the backup) and are sent by run_scheduler().
"""
import asyncio
import datetime
import math

from bridge import errors
from bridge.banker import client_key_store, schedule_store, status_store
from bridge.core import address, clients, metrics, protocol, timing
from bridge.errors.exceptions import Exceptions, get_exception_id, is_exception
from bridge.messenger import service
from bridge.messenger.message import ContentType, MessageMode, create_message, encode_content, pack_payload
from bridge.security.generator import generate_key

IF_PAST_MODES = ("send", "reject")


def _fail(error, problem, **details):
    errors.handle_error(error, problem)
    errors.set_client_details(problems=[problem], **details)
    return error


def plan_times(send_in_seconds=None, send_at=None, expires_in_seconds=None, expires_at=None, timezone_name=None,
               if_past="send"):
    """-> {"send_time" (None = now), "lifetime_seconds", "expires_at", "warnings"} or an exception."""
    if if_past not in IF_PAST_MODES:
        return _fail(Exceptions.ARGUMENT_ERROR, f"'if_past' must be one of {', '.join(IF_PAST_MODES)}")
    warnings = []
    now = timing.now()
    send_time = timing.resolve(send_in_seconds, send_at, timezone_name, "send")
    if is_exception(send_time):
        return send_time
    if send_time is not None and send_time <= now + datetime.timedelta(milliseconds=50):
        if send_at is not None and send_time < now - datetime.timedelta(seconds=1):
            late = (now - send_time).total_seconds()
            text = f"send_at ({timing.iso(send_time)}) was {late:.1f} s ago"
            if if_past == "reject":
                return _fail(Exceptions.SEND_TIME_PASSED, text, send_at=timing.iso(send_time), now=timing.iso(now))
            warnings.append(text + " - the message was sent right away")
        send_time = None
    if send_time is not None and send_time > now + datetime.timedelta(days=protocol.max_schedule_days):
        return _fail(Exceptions.ARGUMENT_ERROR, f"A message can be planned at most {protocol.max_schedule_days} days ahead")
    if expires_in_seconds is not None and expires_at is not None:
        return _fail(Exceptions.ARGUMENT_ERROR, "Use either 'expires_in_seconds' or 'expires_at', not both")
    lifetime_seconds = None
    absolute = None
    if expires_in_seconds is not None:
        if (isinstance(expires_in_seconds, bool) or not isinstance(expires_in_seconds, (int, float))
                or not math.isfinite(expires_in_seconds) or expires_in_seconds <= 0):
            return _fail(Exceptions.ARGUMENT_ERROR, "'expires_in_seconds' must be a number > 0")
        if expires_in_seconds > protocol.max_message_lifetime_minutes * 60:
            return _fail(Exceptions.ARGUMENT_ERROR, f"a message can live at most {protocol.max_message_lifetime_minutes} minutes")
        lifetime_seconds = float(expires_in_seconds)
    elif expires_at is not None:
        absolute = timing.parse_point(expires_at, timezone_name, "expires_at")
        if is_exception(absolute):
            return absolute
    start = send_time or now
    effective = start + datetime.timedelta(seconds=lifetime_seconds) if lifetime_seconds is not None else absolute
    return {"send_time": send_time, "start": start, "lifetime_seconds": lifetime_seconds, "expires_at": effective,
            "warnings": warnings}


def _schedule(client_key, message, times):
    if schedule_store.count_for(client_key) >= protocol.max_scheduled_per_client:
        errors.handle_error(Exceptions.TOO_MANY_SCHEDULED)
        return Exceptions.TOO_MANY_SCHEDULED
    # Byte budget: planned messages wait up to max_schedule_days in RAM
    if schedule_store.bytes_for(client_key) + message.size_bytes > protocol.max_scheduled_mb_per_client * 1024 * 1024:
        errors.handle_error(Exceptions.TOO_MANY_SCHEDULED, f"more than {protocol.max_scheduled_mb_per_client} MB planned")
        errors.set_client_details(problems=[f"a client can have at most {protocol.max_scheduled_mb_per_client} MB of planned messages"])
        return Exceptions.TOO_MANY_SCHEDULED
    if schedule_store.total_bytes() + message.size_bytes > protocol.max_scheduled_mb_total * 1024 * 1024:
        errors.handle_error(Exceptions.TOO_MANY_SCHEDULED, f"the server holds {protocol.max_scheduled_mb_total} MB of planned messages")
        errors.set_client_details(problems=["this server cannot hold more planned messages right now"])
        return Exceptions.TOO_MANY_SCHEDULED
    schedule_store.add(message.message_id, {
        "client_key": client_key,
        "send_at": times["send_time"],
        "message": message,
        "lifetime_seconds": times["lifetime_seconds"],
        "default_lifetime": times["expires_at"] is None,
        "created_at": timing.now(),
    })
    status_store.remember_scheduled(message)
    return True


def _answer(message, state, times, error=None):
    answer = {
        "message_id": message.message_id if message is not None else None,
        "conversation_id": message.conversation_id if message is not None else None,
        "state": state,
    }
    if message is not None:
        answer.update(mode=str(message.mode), size_bytes=message.size_bytes, sha256=message.sha256,
                      expires_at=None if state == "scheduled" and times["lifetime_seconds"] is None and times["expires_at"] is None
                      else timing.iso(message.expires_at))
        if message.mode == MessageMode.COMPRESSED:
            answer.update(encoding=message.transport()[0], transport_size_bytes=message.transport_size())
    if state == "scheduled":
        answer["scheduled_for"] = timing.iso(times["send_time"])
    if error is not None:
        answer["error"] = get_exception_id(error)
    return answer


async def send(client_key, recipients, content, mode=MessageMode.SAFE, conversation_id=None, causation_id=None,
               times=None, broadcast=False, content_type=ContentType.DIRECT):
    """Sends (or plans) a direct message to one recipient or - broadcast - to many.
    content_type FRIEND: a message between friends (BridgeFriends checks the friendship before)."""
    sender_ip = clients.get_client_ip(client_key)
    if sender_ip is None:
        errors.handle_error(Exceptions.CLIENT_NOT_FOUND)
        return Exceptions.CLIENT_NOT_FOUND
    times = times or plan_times()
    if is_exception(times):
        return times
    if broadcast:
        if isinstance(recipients, list) and all(isinstance(ip, str) for ip in recipients):
            recipients = list(dict.fromkeys(recipients))  # the same recipient only once
        if (not isinstance(recipients, list) or not recipients
                or len(recipients) > protocol.max_broadcast_recipients):
            return _fail(Exceptions.ARGUMENT_ERROR, f"'recipients' must be a list with 1-{protocol.max_broadcast_recipients} client IPs")
        invalid = [ip for ip in recipients if not address.is_valid_address(ip)]
        if invalid:
            return _fail(Exceptions.ARGUMENT_ERROR, f"invalid recipient IP(s): {invalid[:3]}")
        conversation_id = conversation_id or generate_key(16)
    broadcast_id = generate_key(16) if broadcast else None

    # Encoded (and packed) once for all recipients - packing runs in a thread, the server keeps working meanwhile
    payload = encode_content(content)
    if is_exception(payload):
        return payload
    transport = None
    if mode == MessageMode.COMPRESSED:
        transport = await asyncio.to_thread(pack_payload, payload)
    send_time = times["send_time"]
    expires_at = times["expires_at"]
    if mode == MessageMode.TEMPORARY and expires_at is None:
        # Also when planned: temporary always needs its own lifetime (the default would hide that)
        return _fail(Exceptions.ARGUMENT_ERROR, "mode temporary needs 'expires_in_seconds' or 'expires_at'")
    if send_time is not None and expires_at is None:
        # Default lifetime of a planned message: counted from its send time (recomputed when it is really sent)
        expires_at = send_time + datetime.timedelta(minutes=protocol.message_lifetime_minutes)
    messages = []
    for recipient_ip in recipients:
        message = create_message(sender_ip, recipient_ip, content, content_type, mode, conversation_id, causation_id,
                                 expires_at=expires_at, starts_at=times["start"], payload=payload, transport=transport)
        if is_exception(message):
            # The content is the same for everybody - if it does not fit, it fits for nobody
            return message
        message.broadcast_id = broadcast_id
        messages.append(message)

    if mode == MessageMode.COMPRESSED or mode == "compressed":
        for message in messages:
            metrics.count("compressed original bytes", message.size_bytes)
            metrics.count("compressed transport bytes", message.transport_size())
    if times["send_time"] is not None:
        results = []
        for message in messages:
            planned = _schedule(client_key, message, times)
            results.append(_answer(message, "scheduled", times, None if planned is True else planned))
        if not broadcast and results[0].get("error"):
            return Exceptions.TOO_MANY_SCHEDULED
    else:
        delivered = await asyncio.gather(*(service.deliver_direct(message) for message in messages))
        results = [_answer(message, "failed" if is_exception(result) else "sent", times,
                           result if is_exception(result) else None)
                   for message, result in zip(messages, delivered)]
        if not broadcast and is_exception(delivered[0]):
            return delivered[0]
    if not broadcast:
        return dict(results[0], warnings=times["warnings"])
    for result, message in zip(results, messages):
        result["recipient_ip"] = message.recipient_ip
    return {
        "broadcast_id": broadcast_id,
        "conversation_id": conversation_id,
        "sent": sum(1 for result in results if result["state"] == "sent"),
        "scheduled": sum(1 for result in results if result["state"] == "scheduled"),
        "failed": sum(1 for result in results if result.get("error")),
        "results": results,
        "warnings": times["warnings"],
    }


# region planned messages
def scheduled_of(client_key):
    """Planned messages of a client and the results of the ones already sent."""
    items = sorted(schedule_store.of_client(client_key), key=lambda item: item[1]["send_at"])
    return {
        "scheduled": [{
            "message_id": message_id,
            "recipient_ip": entry["message"].recipient_ip,
            "send_at": timing.iso(entry["send_at"]),
            "in_seconds": round((entry["send_at"] - timing.now()).total_seconds(), 1),
            "mode": str(entry["message"].mode),
            "size_bytes": entry["message"].size_bytes,
            "conversation_id": entry["message"].conversation_id,
            "broadcast_id": entry["message"].broadcast_id,
        } for message_id, entry in items],
        "recent_results": list(schedule_store.results.get(client_key, [])),
    }


def cancel(client_key, message_id):
    entry = schedule_store.get(message_id)
    if entry is None or entry["client_key"] != client_key:
        return _fail(Exceptions.KEY_ERROR, "No planned message with this id (already sent or cancelled?)")
    if entry.get("sending"):
        # It is on its way right now - "cancelled" would be a lie
        return _fail(Exceptions.NOT_ALLOWED, "the message is being sent right now - too late to cancel")
    schedule_store.remove(message_id)
    status_store.forget(message_id)
    return {"cancelled": True, "message_id": message_id}


async def send_due():
    """Sends every planned message whose time has come."""
    now = timing.now()
    # Still in the store while being sent: a stop in this moment keeps it in the last backup
    due = [(message_id, entry) for message_id, entry in schedule_store.due(now) if not entry.get("sending")]
    for message_id, entry in due:
        entry["sending"] = True
    if not due:
        return 0

    async def send_one(message_id, entry):
        message = entry["message"]
        if client_key_store.get_client_entry(entry["client_key"]) is None:
            # The sender does not exist anymore (removed) - its planned messages go with it
            schedule_store.remove(message_id)
            status_store.forget(message_id)
            return
        late = (now - entry["send_at"]).total_seconds()
        message.created_at = timing.now()
        if entry["lifetime_seconds"] is not None:
            message.expires_at = message.created_at + datetime.timedelta(seconds=entry["lifetime_seconds"])
        elif entry["default_lifetime"]:
            message.expires_at = message.created_at + datetime.timedelta(minutes=protocol.message_lifetime_minutes)
        result = {"message_id": message_id, "recipient_ip": message.recipient_ip, "sent_at": timing.iso(message.created_at),
                  "late_by_seconds": round(late, 2) if late > 2 else 0}
        try:
            if message.is_expired():
                result.update(state="expired", error="ALREADY_EXPIRED")
                status_store.set_status(message, status_store.EXPIRED)
            else:
                delivered = await service.deliver_direct(message)
                if is_exception(delivered):
                    result.update(state="failed", error=get_exception_id(delivered))
                    status_store.forget(message_id)
                else:
                    result["state"] = "sent"
                    metrics.count("scheduled sent")
                    if late > 2:
                        metrics.count("scheduled late")
        except Exception as error:
            result.update(state="failed", error="FAILED")
            errors.handle_error(Exceptions.FAILED, f"Planned message {message_id} could not be sent: {error!r}")
        schedule_store.remove(message_id)
        schedule_store.add_result(entry["client_key"], result)

    await asyncio.gather(*(send_one(message_id, entry) for message_id, entry in due))
    return len(due)


async def run_scheduler():
    while True:
        await asyncio.sleep(0.25)
        try:
            await send_due()
        except Exception as error:
            errors.handle_error(Exceptions.FAILED, f"Scheduler failed: {error!r}")
# endregion planned messages
