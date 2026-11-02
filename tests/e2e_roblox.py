"""End-to-end test of what the Roblox extension needs from Bridge, with two real Bridge servers A <-> B:
batch poll (max_messages), client self delete (/client/delete), limits in /server/status, topics over two servers.

Run from the project folder:  python tests/e2e_roblox.py
"""
import json
import os
import subprocess
import sys
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = {"A": 8191, "B": 8192}
URL = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
PASSWORD = {"A": "admin-A", "B": "admin-B"}
TRUSTS = {"A": ["B"], "B": ["A"]}
OVERRIDES = {"backup_restore_wait_seconds": 3, "backup_interval_seconds": 2}

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


def error_of(data):
    detail = (data or {}).get("detail") or {}
    return detail.get("error")


def register(server, name):
    status, data = post(server, "/client/register", {"name": name, "password": "pw-" + name})
    client_ip = data["client_ip"]
    status, data = post(server, "/client/login", {"client_ip": client_ip, "password": "pw-" + name})
    return client_ip, data["session_token"]


def start(name):
    env = dict(os.environ, PYTHONUNBUFFERED="1", BRIDGE_TEST_OVERRIDES=json.dumps(OVERRIDES), BRIDGE_STDIN_CONTROL="1")
    logs.setdefault(name, open(os.path.join(ROOT, "tests", f"roblox_{name}.log"), "a"))
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


def wait_connected(server, count, seconds=10):
    for _ in range(int(seconds * 5)):
        status, data = post(server, "/admin/trusted/list", {"password": PASSWORD[server]})
        if sum(1 for s in data["trusted_servers"] if s["status"] == "connected") >= count:
            return True
        time.sleep(0.2)
    return False


def scenarios():
    status = httpx.get(URL["A"] + "/server/status").json()
    limits = status.get("limits", {})
    check("status: limits for clients (max_poll_messages, max_wait_seconds, session_lifetime_minutes)",
          limits.get("max_poll_messages") == 100 and limits.get("max_wait_seconds") == 25
          and limits.get("session_lifetime_minutes") == 60, limits)

    a1, ta1 = register("A", "a1")
    b1, tb1 = register("B", "b1")
    realm = status["public_realm_address"]

    # region batch poll
    for index in range(5):
        post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": {"n": index}, "mode": "fast"})
    time.sleep(0.5)
    code, data = post("B", "/message/poll", {"session_token": tb1, "max_messages": 3})
    check("batch poll: max_messages=3 gives 3 messages", code == 200 and data.get("count") == 3
          and [item["content"]["n"] for item in data["messages"]] == [0, 1, 2], data)
    code, data = post("B", "/message/poll", {"session_token": tb1, "max_messages": 50})
    check("batch poll: the rest (2), in order", code == 200 and [item["content"]["n"] for item in data["messages"]] == [3, 4], data)
    code, data = post("B", "/message/poll", {"session_token": tb1, "max_messages": 50})
    check("batch poll: empty mailbox -> messages [] (count 0)", code == 200 and data == {"messages": [], "count": 0}, data)
    code, data = post("B", "/message/poll", {"session_token": tb1})
    check("poll without max_messages stays as before ({message: null})", code == 200 and data.get("message") is None, data)

    started = time.time()
    import threading
    threading.Timer(0.7, lambda: post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1,
                                                              "content": "late", "mode": "fast"})).start()
    code, data = post("B", "/message/poll", {"session_token": tb1, "max_messages": 10, "wait_seconds": 5})
    check("batch poll waits (long polling) and answers as soon as something arrives",
          code == 200 and data.get("count") == 1 and data["messages"][0]["content"] == "late"
          and 0.5 < time.time() - started < 4, (data, time.time() - started))

    post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "f1", "mode": "fast"})
    post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": {"big": "x" * 100}, "mode": "safe"})
    post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": "f2", "mode": "fast"})
    time.sleep(0.5)
    code, data = post("B", "/message/poll", {"session_token": tb1, "max_messages": 10})
    items = data.get("messages") or []
    check("batch poll: a safe message ends the batch (pending_id, chunks fetched afterwards)",
          len(items) == 2 and items[0].get("content") == "f1" and "pending_id" in items[1], data)
    if len(items) == 2 and "pending_id" in items[1]:
        meta = items[1]["message"]
        chunk = post("B", "/message/chunk", {"session_token": tb1, "pending_id": items[1]["pending_id"], "chunk_index": 0})[1]
        code, done = post("B", "/message/complete", {"session_token": tb1, "pending_id": items[1]["pending_id"],
                                                     "sha256": meta["sha256"]})
        check("the safe message from the batch can be completed", code == 200 and json.loads(chunk["chunk"]) == {"big": "x" * 100}, done)
    code, data = post("B", "/message/poll", {"session_token": tb1, "max_messages": 10})
    check("batch poll: the message after the safe one comes next", [i.get("content") for i in data.get("messages", [])] == ["f2"], data)

    for bad in (0, 101, True, "5", 2.5):
        code, data = post("B", "/message/poll", {"session_token": tb1, "max_messages": bad})
        if code != 400:
            break
    check("batch poll: max_messages outside 1..100 / not a whole number -> 400", code == 400, (bad, code, data))
    # endregion

    # region topics over two servers + batch
    code, data = post("B", "/realm/topic/subscribe", {"session_token": tb1, "realm_address": realm, "topic": "players"})
    check("b1 (server B) subscribes a topic in the public realm of A", code == 200, data)
    code, data = post("A", "/realm/topic/subscribe", {"session_token": ta1, "realm_address": realm, "topic": "players"})
    for index in range(20):
        post("A", "/realm/topic/publish", {"session_token": ta1, "realm_address": realm, "topic": "players",
                                           "content": {"tick": index}})
    time.sleep(0.8)
    code, data = post("B", "/message/poll", {"session_token": tb1, "max_messages": 100, "content_types": ["event"]})
    ticks = [item["content"]["data"]["tick"] for item in data.get("messages", [])]
    check("20 events of A arrive on B in ONE poll request", ticks == list(range(20)), data.get("count"))
    code, data = post("A", "/message/poll", {"session_token": ta1, "max_messages": 100})
    check("the publisher gets its own events too (default include_self=true)", data.get("count") == 20, data.get("count"))
    code, data = post("A", "/realm/topic/publish", {"session_token": ta1, "realm_address": realm, "topic": "players",
                                                    "content": {"tick": 50}, "include_self": False})
    check("include_self=false: publish goes to the others only", code == 200 and data.get("subscribers") == 1, data)
    time.sleep(0.5)
    code, own = post("A", "/message/poll", {"session_token": ta1, "max_messages": 100})
    code, other = post("B", "/message/poll", {"session_token": tb1, "max_messages": 100})
    check("include_self=false: A gets nothing back, B gets the event",
          own.get("count") == 0 and [i["content"]["data"]["tick"] for i in other.get("messages", [])] == [50], (own, other))
    # endregion

    # region delete
    code, data = post("B", "/client/delete", {"session_token": tb1, "password": "wrong"})
    check("delete with wrong password -> 401 INVALID_CREDENTIALS", code == 401 and error_of(data) == "INVALID_CREDENTIALS", data)
    code, data = post("B", "/client/delete", {"session_token": tb1})
    check("delete without password -> 400", code == 400, data)
    code, data = post("B", "/client/delete", {"session_token": tb1, "password": "pw-b1"})
    check("delete with password -> deleted", code == 200 and data == {"deleted": True}, data)
    code, data = post("B", "/client/me", {"session_token": tb1})
    check("after delete the session is gone", code == 401 and error_of(data) == "SESSION_INVALID", data)
    code, data = post("B", "/client/login", {"client_ip": b1, "password": "pw-b1"})
    check("after delete the login fails", code == 401, data)
    time.sleep(1.0)
    code, data = post("A", "/realm/topic/publish", {"session_token": ta1, "realm_address": realm, "topic": "players",
                                                    "content": {"tick": 99}})
    check("after delete b1 is no longer a subscriber (only a1 left)", code == 200 and data.get("subscribers") == 1, data)
    # endregion


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


if __name__ == "__main__":
    main()
