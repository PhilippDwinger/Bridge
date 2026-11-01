"""End-to-end test of the messaging features with two real Bridge servers A <-> B:
lifetime + mode temporary, mode compressed, planned messages (timezones), broadcast, conversations.

Run from the project folder:  python tests/e2e_messaging.py
"""
import base64
import datetime
import gzip
import hashlib
import json
import os
import zlib
import subprocess
import sys
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = {"A": 8181, "B": 8182}
URL = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
PASSWORD = {"A": "admin-A", "B": "admin-B"}
TRUSTS = {"A": ["B"], "B": ["A"]}
OVERRIDES = {"backup_restore_wait_seconds": 3, "backup_interval_seconds": 2}
SERVER_OVERRIDES = {}

results = {"ok": 0, "fail": 0}
processes = {}
logs = {}


def check(name, condition, info=None):
    if condition:
        results["ok"] += 1
        print(f"  OK    {name}")
    else:
        results["fail"] += 1
        print(f"  FAIL  {name}  {info if info is not None else ''}")


def post(server, path, body=None, timeout=40):
    try:
        response = httpx.post(URL[server] + path, json=body or {}, timeout=timeout)
    except httpx.HTTPError as error:
        return 0, {"error": repr(error)}
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, None


def register(server, name):
    status, data = post(server, "/client/register", {"name": name, "password": "pw-" + name})
    client_ip = data["client_ip"]
    status, data = post(server, "/client/login", {"client_ip": client_ip, "password": "pw-" + name})
    return client_ip, data["session_token"]


def start(name):
    overrides = dict(OVERRIDES, **SERVER_OVERRIDES.get(name, {}))
    env = dict(os.environ, PYTHONUNBUFFERED="1", BRIDGE_TEST_OVERRIDES=json.dumps(overrides), BRIDGE_STDIN_CONTROL="1")
    logs.setdefault(name, open(os.path.join(ROOT, "tests", f"messaging_{name}.log"), "a"))
    processes[name] = subprocess.Popen(
        [sys.executable, "tests/run_server.py", str(PORTS[name]), PASSWORD[name]] + [URL[other] for other in TRUSTS[name]],
        cwd=ROOT, stdin=subprocess.PIPE, stdout=logs[name], stderr=logs[name], env=env)
    for _ in range(300):
        try:
            response = httpx.get(URL[name] + "/server/status", timeout=1)
            if response.status_code == 200 and response.json().get("ready"):
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    return False


def stop(name, hard=False):
    process = processes[name]
    if hard:
        process.kill()
    else:
        process.stdin.close()
    process.wait(25)


def wait_connected(server, count, seconds=10):
    for _ in range(int(seconds * 5)):
        status, data = post(server, "/admin/trusted/list", {"password": PASSWORD[server]})
        if sum(1 for s in data["trusted_servers"] if s["status"] == "connected") >= count:
            return True
        time.sleep(0.2)
    return False


def wait_until(condition, seconds=5.0):
    """Polls condition() until it is true (returns True) or the time is over (False)."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.1)
    return condition()


def me(server, token):
    return post(server, "/client/me", {"session_token": token})[1]


def main():
    for name in PORTS:
        assert start(name), f"{name} did not start"
    try:
        check("A and B connected", wait_connected("A", 1) and wait_connected("B", 1))
        scenarios()
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.kill()
    print(f"\n{results['ok']} ok, {results['fail']} failed")
    sys.exit(1 if results["fail"] else 0)


def error_of(data):
    detail = (data or {}).get("detail") or {}
    return detail.get("error"), (detail.get("details") or {}).get("problems")


def receive(server, token, wait=0):
    """Takes the next message (fast/temporary in one piece, safe/compressed with chunks + hash)."""
    status, data = post(server, "/message/poll", {"session_token": token, "wait_seconds": wait})
    if not data.get("message"):
        return None, None
    if data["mode"] in ("fast", "temporary"):
        return data["message"], data["content"]
    meta, pending_id = data["message"], data["pending_id"]
    text = "".join(post(server, "/message/chunk", {"session_token": token, "pending_id": pending_id, "chunk_index": i})[1]["chunk"]
                   for i in range(meta["chunk_count"]))
    if meta.get("encoding") == "zlib+base64":
        text = zlib.decompress(base64.b64decode(text)).decode("utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    post(server, "/message/complete", {"session_token": token, "pending_id": pending_id, "sha256": digest})
    return meta, json.loads(text)


def status_of(server, token, message_id):
    return post(server, "/message/status", {"session_token": token, "message_id": message_id})[1].get("state")


def drain(server, token):
    while receive(server, token)[0] is not None:
        pass


def scenarios():
    a1, ta1 = register("A", "a1")
    a2, ta2 = register("A", "a2")
    b1, tb1 = register("B", "b1")
    b2, tb2 = register("B", "b2")

    print("Lifetime and mode temporary")
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "x", "mode": "temporary"})
    check("temporary without a lifetime -> 400", status == 400 and error_of(data)[0] == "ARGUMENT_ERROR", data)
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "gone soon", "mode": "temporary",
                                               "expires_in_seconds": 1.5})
    check("temporary with expires_in_seconds", status == 200 and data["mode"] == "temporary" and data["expires_at"], data)
    temporary_id = data["message_id"]
    time.sleep(2.6)
    status, mailbox = post("B", "/admin/mailbox", {"password": PASSWORD["B"], "client_ip": b1})
    check("after the lifetime it is deleted from the mailbox by itself (nobody polled)",
          all(not messages for messages in mailbox["pools"].values()), mailbox["pools"])
    check("... and the sender sees expired", status_of("A", ta1, temporary_id) == "expired")
    in_two_seconds = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=30)).astimezone(
        datetime.timezone(datetime.timedelta(hours=1))).isoformat()
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "lives 30 s", "mode": "safe",
                                               "expires_at": in_two_seconds})
    check("expires_at with offset (+01:00) works with safe too", status == 200 and data["expires_at"].endswith("+00:00"), data)
    meta, content = receive("B", tb1)
    check("... it arrives with that lifetime", content == "lives 30 s" and abs(datetime.datetime.fromisoformat(meta["expires_at"])
          - datetime.datetime.fromisoformat(in_two_seconds)).total_seconds() < 1, meta)
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": 1, "expires_at": "2026-01-01T10:00:00"})
    check("time without timezone -> 400 TIMEZONE_MISSING", status == 400 and error_of(data)[0] == "TIMEZONE_MISSING", data)
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": 1, "expires_at": "2020-01-01T10:00:00Z"})
    check("lifetime already over -> 400 ALREADY_EXPIRED", status == 400 and error_of(data)[0] == "ALREADY_EXPIRED", data)
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": 1, "expires_at": "2026-01-01T10:00:00",
                                               "timezone": "Mars/Olympus"})
    check("unknown timezone name -> 400 with a reason", status == 400 and "timezone" in (error_of(data)[1] or [""])[0].lower(), data)

    print("Mode compressed")
    big = {"text": "Grüße aus Bridge! " * 3000, "numbers": list(range(500))}
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": big, "mode": "compressed"})
    check("compressed: much smaller to transfer", status == 200 and data["encoding"] == "zlib+base64"
          and data["transport_size_bytes"] < data["size_bytes"] / 10, data)
    sha = data["sha256"]
    meta, content = receive("B", tb1)
    check("... arrives across servers exactly the same (hash of the original)", content == big and meta["sha256"] == sha
          and meta["mode"] == "compressed", meta)
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "hi", "mode": "compressed"})
    check("tiny content is not packed (identity)", data.get("encoding") == "identity", data)
    meta, content = receive("B", tb1)
    check("... and still arrives", content == "hi")
    huge = {"text": "a" * (3 * 1024 * 1024)}
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": huge, "mode": "compressed"})
    check("3 MiB original (safe would allow 1 MiB) fits compressed", status == 200 and data["size_bytes"] > 3 * 1024 * 1024, data)
    meta, content = receive("A", ta2)
    check("... and arrives complete", content == huge)

    print("HTTP compression for everybody")
    raw = json.dumps({"session_token": ta1, "recipient_ip": b1, "content": {"t": "x" * 6000}, "mode": "fast"}).encode()
    response = httpx.post(URL["A"] + "/message/send", content=gzip.compress(raw),
                          headers={"Content-Encoding": "gzip", "Content-Type": "application/json"})
    check("gzip compressed request is unpacked by Bridge", response.status_code == 200, response.text[:200])
    response = httpx.post(URL["B"] + "/message/poll", json={"session_token": tb1}, headers={"Accept-Encoding": "gzip"})
    check("big answers come gzip compressed (6 KB message went A -> B as gzip too)",
          response.headers.get("content-encoding") == "gzip" and response.json()["content"]["t"] == "x" * 6000,
          dict(response.headers))
    response = httpx.post(URL["A"] + "/message/send", content=b"not gzip", headers={"Content-Encoding": "gzip"})
    check("broken compressed body -> 400", response.status_code == 400, response.text[:200])

    print("Planned messages")
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "later", "mode": "fast",
                                               "send_in_seconds": 1.5})
    check("send_in_seconds -> scheduled", status == 200 and data["state"] == "scheduled" and data["scheduled_for"], data)
    planned_id = data["message_id"]
    check("status: scheduled", status_of("A", ta1, planned_id) == "scheduled")
    check("not there yet", receive("B", tb1)[0] is None)
    meta, content = receive("B", tb1, wait=4)
    check("arrives after the time", content == "later")
    status, data = post("A", "/message/scheduled", {"session_token": ta1})
    check("results of sent planned messages", any(r["message_id"] == planned_id and r["state"] == "sent" for r in data["recent_results"]), data)
    berlin_time = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=2)).astimezone(
        datetime.timezone(datetime.timedelta(hours=1))).replace(tzinfo=None)
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "at a time", "mode": "fast",
                                               "send_at": berlin_time.isoformat(), "timezone": "Europe/Berlin"})
    expected = berlin_time.replace(tzinfo=datetime.timezone(datetime.timedelta(hours=1)))
    check("send_at without offset + timezone Europe/Berlin (winter time = +01:00)", status == 200 and
          abs(datetime.datetime.fromisoformat(data["scheduled_for"]) - expected).total_seconds() < 0.01, data)
    meta, content = receive("B", tb1, wait=5)
    check("... arrives at that time", content == "at a time")
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "late", "mode": "fast",
                                               "send_at": "2026-01-01T09:00:00+01:00"})
    check("send_at already over -> sent right away with a warning", status == 200 and data["state"] == "sent"
          and data["warnings"] and "ago" in data["warnings"][0], data)
    receive("B", tb1)
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "late", "send_at": "2026-01-01T09:00:00Z",
                                               "if_past": "reject"})
    check("... or rejected with if_past = reject", status == 400 and error_of(data)[0] == "SEND_TIME_PASSED", data)
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "never", "send_in_seconds": 30})
    post("A", "/message/scheduled/cancel", {"session_token": ta1, "message_id": data["message_id"]})
    status, data = post("A", "/message/scheduled", {"session_token": ta1})
    check("cancel removes a planned message", data["scheduled"] == [], data)
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "lifetime from send", "mode": "temporary",
                                               "send_in_seconds": 1, "expires_in_seconds": 2})
    meta, content = receive("B", tb1, wait=4)
    check("planned + temporary: the lifetime counts from the real send time", content == "lifetime from send"
          and (datetime.datetime.fromisoformat(meta["expires_at"]) - datetime.datetime.fromisoformat(meta["created_at"])).total_seconds() > 1.9, meta)
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": 1, "send_in_seconds": 5,
                                               "expires_at": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=2)).isoformat()})
    check("lifetime ends before the planned send time -> 400 ALREADY_EXPIRED", status == 400 and error_of(data)[0] == "ALREADY_EXPIRED", data)

    print("Broadcast")
    status, data = post("A", "/message/broadcast", {"session_token": ta1, "recipients": [a2, b1, b2], "content": {"hello": "all"}, "mode": "fast"})
    check("broadcast to 3 clients on 2 servers", status == 200 and data["sent"] == 3 and data["failed"] == 0, data)
    broadcast_id, conversation_id = data["broadcast_id"], data["conversation_id"]
    got = [receive(server, token) for server, token in (("A", ta2), ("B", tb1), ("B", tb2))]
    check("everybody gets it, with the same broadcast_id and conversation_id",
          all(content == {"hello": "all"} and meta["broadcast_id"] == broadcast_id and meta["conversation_id"] == conversation_id
              for meta, content in got), got)
    status, data = post("A", "/message/broadcast", {"session_token": ta1, "recipients": [b1, "http://127.0.0.1:1<|BRIDGE_IP_SPLIT|>nobody"],
                                                    "content": 1, "mode": "fast"})
    check("one recipient fails -> the others still get it, result per recipient", status == 200 and data["sent"] == 1 and data["failed"] == 1, data)
    receive("B", tb1)
    status, data = post("A", "/message/broadcast", {"session_token": ta1, "recipients": [b1, b2], "content": "planned for all",
                                                    "mode": "fast", "send_in_seconds": 1})
    check("planned broadcast", status == 200 and data["scheduled"] == 2, data)
    first = receive("B", tb1, wait=4)[1]
    second = receive("B", tb2, wait=4)[1]
    check("... arrives at everybody", first == second == "planned for all")
    status, data = post("A", "/message/broadcast", {"session_token": ta1, "recipients": [b1] * 101, "content": 1})
    check("duplicates are removed (101 x the same = 1 recipient)", status == 200 and len(data["results"]) == 1, data.get("results"))
    drain("B", tb1)
    many = [f"http://127.0.0.1:1<|BRIDGE_IP_SPLIT|>x{i}" for i in range(101)]
    status, data = post("A", "/message/broadcast", {"session_token": ta1, "recipients": many, "content": 1})
    check("more than 100 recipients -> 400", status == 400, data)
    drain("B", tb2)
    drain("A", ta2)
    SCENARIO_STATE.update(a1=a1, ta1=ta1, a2=a2, ta2=ta2, b1=b1, tb1=tb1, b2=b2, tb2=tb2)
    conversation_scenarios()


SCENARIO_STATE = {}


def conversation_scenarios():
    globals().update(SCENARIO_STATE)
    print("Conversations (like 'Follow stream' in Wireshark)")
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "ping", "mode": "fast",
                                               "conversation_id": "chat-1"})
    receive("B", tb1)
    post("B", "/message/send", {"session_token": tb1, "recipient_ip": a1, "content": "pong", "mode": "safe", "conversation_id": "chat-1"})
    receive("A", ta1)
    status, data = post("A", "/conversation/stream", {"session_token": ta1, "conversation_id": "chat-1"})
    entries = data.get("entries", [])
    check("a1 sees both directions in order (seq 1, 2)", [(e["seq"], e["from"] == a1, e["to"] == b1) for e in entries][:1] == [(1, True, True)]
          and len(entries) == 2 and entries[1]["from"] == b1, entries)
    check("... with states: delivered (asked from B like an ACK), taken after x s, route",
          all(e["state"] == "delivered" and e["taken_after_s"] is not None for e in entries) and entries[0]["route"].startswith("remote:"), entries)
    check("... and stats (messages, bytes, types)", data["stats"]["messages"] == 2 and data["stats"]["by_type"] == {"direct": 2}, data.get("stats"))
    check("no contents without record = full", all("content" not in e for e in entries))
    status, data = post("B", "/conversation/stream", {"session_token": tb1, "conversation_id": "chat-1"})
    check("b1's server has its own stream of the same conversation", status == 200 and len(data["entries"]) == 2, data)
    status, data = post("A", "/conversation/stream", {"session_token": ta2, "conversation_id": "chat-1"})
    check("a2 (not part of it) cannot read it -> 400", status == 400, data)

    status, data = post("A", "/conversation/start", {"session_token": ta1, "title": "Raid", "record": "full", "participants": [a2, b1]})
    raid = data["conversation_id"]
    check("start a group conversation with record = full", status == 200 and data["group"] and data["record"] == "full", data)
    post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": {"go": True}, "mode": "fast", "conversation_id": raid})
    status, data = post("A", "/conversation/stream", {"session_token": ta2, "conversation_id": raid})
    check("group: a2 sees the message a1 sent to b1, with content", status == 200 and data["entries"][0]["content"] == {"go": True}, data)
    last = data["last_seq"]
    import threading
    threading.Timer(0.6, lambda: post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": "live",
                                                              "mode": "fast", "conversation_id": raid})).start()
    started = time.time()
    status, data = post("A", "/conversation/stream", {"session_token": ta2, "conversation_id": raid, "after_seq": last, "wait_seconds": 5})
    check("follow live: waits for the next entry (after_seq + wait_seconds)", data["entries"] and data["entries"][0]["content"] == "live"
          and time.time() - started < 3, (data.get("entries"), time.time() - started))
    receive("A", ta2)
    receive("B", tb1)

    status, data = post("A", "/command/call", {"session_token": ta1, "command_name": "nothing-here", "realm_address": None})
    check("unknown command -> 404 (no stream entry)", status == 404)
    status, data = post("A", "/conversation/list", {"session_token": ta1})
    ids = [c["conversation_id"] for c in data["conversations"]]
    check("list: a1's conversations, newest first", ids[:1] == [raid] and "chat-1" in ids, ids)
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": "http://127.0.0.1:1<|BRIDGE_IP_SPLIT|>x",
                                               "content": 1, "mode": "fast", "conversation_id": "chat-2"})
    status, data = post("A", "/conversation/stream", {"session_token": ta1, "conversation_id": "chat-2"})
    check("a message that could not be delivered shows as failed", data.get("entries") and data["entries"][0]["state"] == "failed", data)
    post("A", "/conversation/close", {"session_token": ta1, "conversation_id": raid})
    post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": 1, "mode": "fast", "conversation_id": raid})
    status, data = post("A", "/conversation/stream", {"session_token": ta1, "conversation_id": raid})
    check("closed: nothing new is recorded", data["closed"] and data["stats"]["messages"] == 2, data.get("stats"))
    receive("B", tb1)
    post("A", "/admin/settings", {"password": PASSWORD["A"], "conversation_mode": "off"})
    post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": 1, "mode": "fast", "conversation_id": "chat-3"})
    status, data = post("A", "/conversation/stream", {"session_token": ta1, "conversation_id": "chat-3"})
    check("conversation_mode off: nothing is recorded", status == 400, data)
    post("A", "/admin/settings", {"password": PASSWORD["A"], "conversation_mode": "all"})
    receive("A", ta2)


if __name__ == "__main__":
    main()
