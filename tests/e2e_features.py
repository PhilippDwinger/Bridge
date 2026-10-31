"""End-to-end test of the newer features with three real Bridge servers:  A <-> B <-> C  (A and C do not trust each other)

Run from the project folder:  python tests/e2e_features.py
Needs: fastapi, uvicorn, argon2-cffi, httpx, cryptography
"""
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = {"A": 8111, "B": 8112, "C": 8113}
URL = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
PASSWORD = {"A": "admin-A", "B": "admin-B", "C": "admin-C"}
TRUSTS = {"A": ["B"], "B": ["A", "C"], "C": ["B"]}
OVERRIDES = {"backup_interval_seconds": 2, "host_inactive_seconds": 3, "backup_restore_wait_seconds": 5}

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
    response = httpx.post(URL[server] + path, json=body or {}, timeout=timeout)
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, None


def error_id(data):
    detail = (data or {}).get("detail")
    return detail.get("error") if isinstance(detail, dict) else None


def register(server, name, identity_secret=None):
    body = {"name": name, "password": "pw-" + name}
    if identity_secret:
        body["identity_secret"] = identity_secret
    status, data = post(server, "/client/register", body)
    client_ip = data["client_ip"]
    status, data = post(server, "/client/login", {"client_ip": client_ip, "password": "pw-" + name})
    return client_ip, data["session_token"]


def receive(server, token, wait=0, content_types=None):
    body = {"session_token": token, "wait_seconds": wait}
    if content_types:
        body["content_types"] = content_types
    status, data = post(server, "/message/poll", body)
    if data.get("message") is None:
        return None, None
    return finish(server, token, data)


def finish(server, token, data):
    if data["mode"] == "fast":
        return data["message"], data["content"]
    meta, pending_id = data["message"], data["pending_id"]
    chunks = [post(server, "/message/chunk", {"session_token": token, "pending_id": pending_id, "chunk_index": i})[1]["chunk"]
              for i in range(meta["chunk_count"])]
    payload = "".join(chunks)
    post(server, "/message/complete", {"session_token": token, "pending_id": pending_id,
                                       "sha256": hashlib.sha256(payload.encode()).hexdigest()})
    return meta, json.loads(payload)


def start(name):
    env = dict(os.environ, PYTHONUNBUFFERED="1", BRIDGE_TEST_OVERRIDES=json.dumps(OVERRIDES))
    logs.setdefault(name, open(os.path.join(ROOT, "tests", f"features_{name}.log"), "a"))
    processes[name] = subprocess.Popen(
        [sys.executable, "tests/run_server.py", str(PORTS[name]), PASSWORD[name]] + [URL[other] for other in TRUSTS[name]],
        cwd=ROOT, stdout=logs[name], stderr=logs[name], env=env)
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
        process.send_signal(signal.SIGINT)  # like Ctrl+C - the server makes a last backup
    process.wait(15)


def wait_connected(server, count, seconds=10):
    for _ in range(int(seconds * 5)):
        status, data = post(server, "/admin/trusted/list", {"password": PASSWORD[server]})
        if sum(1 for s in data["trusted_servers"] if s["status"] == "connected") >= count:
            return True
        time.sleep(0.2)
    return False


def main():
    for name in PORTS:
        assert start(name), f"{name} did not start"
    try:
        check("A, B, C connected (A-B, B-C)", wait_connected("A", 1) and wait_connected("B", 2) and wait_connected("C", 1))
        scenarios()
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.kill()
    print(f"\n{results['ok']} ok, {results['fail']} failed")
    sys.exit(1 if results["fail"] else 0)


def scenarios():
    a1, ta1 = register("A", "a1", identity_secret="a1-secret-" + "x" * 30)
    a2, ta2 = register("A", "a2")
    b1, tb1 = register("B", "b1")
    c1, tc1 = register("C", "c1")

    print("Long polling (the client asks and waits - Bridge never pushes)")
    started = time.time()
    meta, content = receive("A", ta2, wait=1.5)
    check("empty mailbox: poll waits about wait_seconds", meta is None and 1.3 < time.time() - started < 3)
    threading.Timer(0.7, lambda: post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": "late", "mode": "fast"})).start()
    started = time.time()
    meta, content = receive("A", ta2, wait=10)
    check("message arriving during the wait returns at once", content == "late" and time.time() - started < 3, time.time() - started)

    print("Stable identity")
    status, data = post("A", "/client/register", {"name": "a1", "password": "x", "identity_secret": "a1-secret-" + "x" * 30})
    check("same identity_secret while registered -> 409", status == 409, data)
    status, data = post("A", "/client/register", {"name": "short", "password": "x", "identity_secret": "too-short"})
    check("identity_secret too short -> 400", status == 400, data)

    print("Direct message settings")
    post("A", "/client/direct", {"session_token": ta2, "mode": "nobody"})
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": 1})
    check("mode nobody -> 403 RECIPIENT_REJECTED", status == 403 and error_id(data) == "RECIPIENT_REJECTED", data)
    post("A", "/client/direct", {"session_token": ta2, "mode": "allowlist", "allow": [URL["B"]]})
    status, _ = post("B", "/message/send", {"session_token": tb1, "recipient_ip": a2, "content": "from B", "mode": "fast"})
    status2, _ = post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": 1})
    check("allowlist with a whole server URL: B allowed, A not", status == 200 and status2 == 403)
    post("A", "/client/direct", {"session_token": ta2, "mode": "everyone", "block": [b1]})
    status, _ = post("B", "/message/send", {"session_token": tb1, "recipient_ip": a2, "content": 1})
    check("block list beats everyone", status == 403)
    post("A", "/client/direct", {"session_token": ta2, "mode": "everyone", "block": []})
    receive("A", ta2)

    print("Message status")
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": {"x": 1}, "mode": "safe"})
    message_id = data["message_id"]
    check("status waiting", post("A", "/message/status", {"session_token": ta1, "message_id": message_id})[1]["state"] == "waiting")
    status, polled = post("B", "/message/poll", {"session_token": tb1})
    check("status taken (safe, not confirmed)", post("A", "/message/status", {"session_token": ta1, "message_id": message_id})[1]["state"] == "taken")
    finish("B", tb1, polled)
    check("status delivered (across servers)", post("A", "/message/status", {"session_token": ta1, "message_id": message_id})[1]["state"] == "delivered")
    status, data = post("B", "/message/status", {"session_token": tb1, "message_id": message_id})
    check("only the sender may ask -> 400", status == 400, data)

    print("Commands: catalog, wait for the answer, active hosts")
    public_b = httpx.get(URL["B"] + "/realm/public").json()["realm_address"]
    post("B", "/realm/command/create", {"session_token": tb1, "realm_address": public_b, "command_name": "double", "description": "doubles a number"})
    status, data = post("A", "/realm/commands", {"session_token": ta1, "realm_address": public_b})
    check("command catalog with description", data["commands"].get("double", {}).get("descriptions") == ["doubles a number"], data)

    stop_host = threading.Event()

    def host_b1():
        while not stop_host.is_set():
            status, data = post("B", "/message/poll", {"session_token": tb1, "wait_seconds": 1, "content_types": ["task"]})
            if data and data.get("message"):
                task = data["content"] if data["mode"] == "fast" else None
                if task is None:
                    continue
                post("B", "/command/respond", {"session_token": tb1, "task_id": data["message"]["message_id"],
                                               "content": task["command_args"] * 2, "mode": "fast"})

    worker = threading.Thread(target=host_b1, daemon=True)
    worker.start()
    status, data = post("A", "/command/call", {"session_token": ta1, "command_name": "double", "command_args": 21,
                                               "realm_address": public_b, "mode": "fast", "wait_seconds": 10})
    check("call with wait_seconds returns the response directly", status == 200 and data["response"] and data["response"]["content"] == 42, data)
    status, data = post("A", "/command/call", {"session_token": ta1, "command_name": "double", "command_args": 1,
                                               "realm_address": public_b, "mode": "fast", "strategy": "random"})
    check("strategy random works, response goes to the mailbox", status == 200 and data["response"] is None, data)
    meta, content = receive("A", ta1, wait=5, content_types=["response"])
    check("... and arrives there", content == 2, content)
    stop_host.set()
    worker.join(3)

    b2, tb2 = register("B", "b2")
    post("B", "/realm/command/create", {"session_token": tb2, "realm_address": public_b, "command_name": "work"})
    post("B", "/realm/command/create", {"session_token": tb1, "realm_address": public_b, "command_name": "work"})
    post("A", "/command/call", {"session_token": ta1, "command_name": "work", "realm_address": public_b, "mode": "fast"})
    time.sleep(3.5)  # both hosts are inactive now (test setting: 3 seconds)
    post("B", "/client/me", {"session_token": tb1})  # b1 shows a sign of life
    busy_host = None
    for _ in range(3):
        status, data = post("A", "/command/call", {"session_token": ta1, "command_name": "work", "realm_address": public_b, "mode": "fast"})
        busy_host = data["host_ip"]
        if busy_host != b1:
            break
    check("active host is preferred over an idle one", busy_host == b1, busy_host)
    for token in (tb1, tb2):
        while receive("B", token)[0]:
            pass

    print("Topics (publish/subscribe across servers)")
    post("A", "/realm/topic/subscribe", {"session_token": ta1, "realm_address": public_b, "topic": "news"})
    post("C", "/realm/topic/subscribe", {"session_token": tc1, "realm_address": public_b, "topic": "news"})
    status, data = post("B", "/realm/topic/publish", {"session_token": tb1, "realm_address": public_b, "topic": "news", "content": {"headline": "Bridge"}})
    check("publish reaches 2 subscribers on 2 servers", status == 200 and data["delivered"] == 2 and not data["failed"], data)
    meta, content = receive("A", ta1, content_types=["event"])
    check("event on A: verified, topic and data", meta and meta["content_type"] == "event" and meta["verified"] and content["data"] == {"headline": "Bridge"}, content)
    meta, content = receive("C", tc1, content_types=["event"])
    check("event on C", content and content["topic"] == "news")
    status, data = post("A", "/realm/create", {"session_token": ta1, "realm_type": "private", "realm_name": "P"})
    private = data["realm_address"]
    post("A", "/realm/role/create", {"session_token": ta1, "realm_address": private, "role_name": "listener"})
    key = post("A", "/realm/key/create", {"session_token": ta1, "realm_address": private, "roles": ["listener"]})[1]["access_key"]
    post("B", "/realm/join", {"session_token": tb1, "realm_address": private, "access_key": key})
    post("B", "/realm/topic/subscribe", {"session_token": tb1, "realm_address": private, "topic": "secret"})
    status, data = post("B", "/realm/topic/publish", {"session_token": tb1, "realm_address": private, "topic": "secret", "content": 1})
    check("private realm: member without can_publish may not publish -> 403", status == 403, data)
    status, data = post("A", "/realm/topic/publish", {"session_token": ta1, "realm_address": private, "topic": "secret", "content": 1})
    check("owner may publish", status == 200 and data["delivered"] == 1, data)
    receive("B", tb1)

    print("Relaying A -> B -> C (A does not trust C)")
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": c1, "content": "hi C", "mode": "fast"})
    check("direct message A -> C goes over B", status == 200, data)
    meta, content = receive("C", tc1)
    check("C gets it with relayed_via = [B]", content == "hi C" and meta["relayed_via"] == [URL["B"]] and meta["sender_ip"] == a1, meta)
    status, data = post("A", "/message/status", {"session_token": ta1, "message_id": data["message_id"]})
    check("status of a relayed message is unknown", data["state"].startswith("unknown"), data)
    status, data = post("A", "/command/call", {"session_token": ta1, "command_name": "x", "realm_address": URL["C"] + "<|BRIDGE_IP_SPLIT|>abc"})
    check("verified things are not relayed (realm on C) -> 403", status == 403, data)
    post("C", "/admin/settings", {"password": PASSWORD["C"], "accept_relayed": False})
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": c1, "content": 1})
    check("C does not accept relayed messages -> rejected", status == 403, data)
    post("C", "/admin/settings", {"password": PASSWORD["C"], "accept_relayed": True})
    post("B", "/admin/settings", {"password": PASSWORD["B"], "relay_mode": "off"})
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": c1, "content": 1})
    check("B relay_mode off -> no route", status == 403, data)
    post("B", "/admin/settings", {"password": PASSWORD["B"], "relay_mode": "trusted"})

    print("Encrypted backup at trusted servers")
    post("A", "/message/send", {"session_token": ta2, "recipient_ip": a1, "content": {"keep": "me"}, "mode": "safe"})
    status, data = post("A", "/admin/backup/now", {"password": PASSWORD["A"]})
    check("backup sent to B", status == 200 and URL["B"] in data["sent_to"], data)
    status, data = post("B", "/admin/backup/status", {"password": PASSWORD["B"]})
    stored = [entry for entry in data["stored_for_other_servers"] if entry["server_url"] == URL["A"]]
    check("B keeps A's backup", len(stored) == 1, data)
    status, data = post("B", "/s2s/backup/fetch", {})
    check("nobody can fetch it without the server token", status == 403)

    stop("A")  # normal shutdown -> last backup
    check("A is back", start("A"))
    restored = None
    for _ in range(40):
        status, data = post("A", "/admin/backup/status", {"password": PASSWORD["A"]})
        if data.get("restore_done"):
            restored = data.get("last_restore")
            break
        time.sleep(0.5)
    check("A restored itself from B", restored and restored.get("restored") is True, restored)
    status, data = post("A", "/client/me", {"session_token": ta1})
    check("old session of a1 still works after the restart", status == 200 and data["client_ip"] == a1, data)
    meta, content = receive("A", ta1)
    check("unread message survived the restart", content == {"keep": "me"}, content)
    status, data = post("A", "/realm/info", {"session_token": ta1, "realm_address": private})
    check("realm survived the restart", status == 200 and data["is_owner"], data)

    time.sleep(3)  # periodic backup (test setting: every 2 seconds)
    post("A", "/message/send", {"session_token": ta2, "recipient_ip": a1, "content": "after crash", "mode": "fast"})
    time.sleep(3)
    stop("A", hard=True)  # crash - no last backup
    start("A")
    for _ in range(40):
        status, data = post("A", "/admin/backup/status", {"password": PASSWORD["A"]})
        if data.get("restore_done"):
            break
        time.sleep(0.5)
    meta, content = receive("A", ta1)
    check("after a crash the periodic backup restores the data", content == "after crash", content)
    status, data = post("A", "/client/register", {"name": "a1", "password": "x", "identity_secret": "a1-secret-" + "x" * 30})
    check("stable identity is back too (still registered -> 409)", status == 409, data)


if __name__ == "__main__":
    main()
