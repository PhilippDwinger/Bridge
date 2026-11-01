"""End-to-end test of the hardening (found by a code review): bad inputs, limits, planned messages over a restart,
backup that is too big. Two real Bridge servers A <-> B.

Run from the project folder:  python tests/e2e_hardening.py
"""
import base64
import json
import os
import subprocess
import sys
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = {"A": 8211, "B": 8212}
URL = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
PASSWORD = {"A": "admin-A", "B": "admin-B"}
TRUSTS = {"A": ["B"], "B": ["A"]}
OVERRIDES = {"backup_restore_wait_seconds": 3, "backup_interval_seconds": 2, "message_lifetime_minutes": 0.05,
             "max_conversations_per_client": 5, "max_backup_mb": 1, "max_mailbox_mb_per_sender": 16}
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
    logs.setdefault(name, open(os.path.join(ROOT, "tests", f"hardening_{name}.log"), "a"))
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


def raw(server, path, text):
    response = httpx.post(URL[server] + path, content=text.encode("utf-8"), headers={"Content-Type": "application/json"}, timeout=60)
    return response.status_code, response.text


def scenarios():
    a1, ta1 = register("A", "a1")
    a2, ta2 = register("A", "a2")
    public_a = httpx.get(URL["A"] + "/realm/public").json()["realm_address"]

    print("Bad inputs give 400, never 500")
    status, text = raw("A", "/message/send", json.dumps({"session_token": ta1, "recipient_ip": a2, "mode": "fast"})[:-1] + ', "content": {"x": NaN}}')
    check("NaN in the content -> 400", status == 400, text[:200])
    status, text = raw("A", "/message/poll", json.dumps({"session_token": ta1})[:-1] + ', "wait_seconds": NaN}')
    check("NaN as wait_seconds -> 400 (no endless poll)", status == 400, text[:200])
    status, text = raw("A", "/realm/command/create", json.dumps({"session_token": ta1, "realm_address": public_a})[:-1] + ', "command_name": "\\ud800"}')
    check("broken unicode in a command name -> 400", status == 400, text[:200])
    status, text = raw("A", "/message/send", json.dumps({"session_token": ta1, "recipient_ip": a2, "mode": "fast"})[:-1] + ', "content": "\\udc00"}')
    check("broken unicode in the content -> 400", status == 400, text[:200])
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": 1, "send_at": "9999-12-31T23:59:59-01:00"})
    check("time far out of range -> 400", status == 400, data)
    post("A", "/realm/command/create", {"session_token": ta1, "realm_address": public_a, "command_name": "echo"})
    status, data = post("A", "/command/call", {"session_token": ta2, "command_name": "echo", "realm_address": public_a,
                                               "command_args": {"9" * 5000: 1, "x": 2}, "mode": "fast"})
    check("an argument key with 5000 digits -> no 500", status == 200, data)
    status, text = raw("A", "/message/send", "x" * (20 * 1024 * 1024))
    check("a 20 MB plain body -> 413 before it is read", status == 413, text[:200])
    for path in ("/random/one", "/random/two", "/x/y/z"):
        httpx.post(URL["A"] + path, json={})
    status, data = post("A", "/admin/analysis", {"password": PASSWORD["A"]})
    check("unknown paths are counted as 'other' (no new counters)", "http other" in data["counters"]
          and not any("random" in name for name in data["counters"]), [name for name in data["counters"] if name.startswith("http")])

    print("Limits")
    big = {"text": "a" * (8 * 1024 * 1024 - 20)}
    answers = [post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": big, "mode": "compressed",
                                           "expires_in_seconds": 600}) for _ in range(3)]
    check("byte budget: one sender can put at most 16 MB into a mailbox (also compressed)",
          [status for status, _ in answers] == [200, 200, 507] or (answers[0][0] == 200 and answers[2][0] >= 400), [s for s, _ in answers])
    while post("A", "/message/poll", {"session_token": ta2})[1].get("message"):
        pass
    results = [post("A", "/realm/command/create", {"session_token": ta1, "realm_address": public_a, "command_name": f"c{i}"})[0]
               for i in range(51)]
    # "echo" from above is the 50th command of a1
    check("a client can host at most 50 commands per realm", results[:49].count(200) == 49 and min(results[49:]) >= 400, results[-3:])
    for i in range(7):
        post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": i, "mode": "fast", "conversation_id": f"conv-{i}"})
    status, data = post("A", "/conversation/list", {"session_token": ta1})
    own = [c["conversation_id"] for c in data["conversations"] if c["created_by_me"]]
    check("a client keeps at most 5 own conversations (test setting) - its oldest go",
          own == ["conv-6", "conv-5", "conv-4", "conv-3", "conv-2"], [(c["conversation_id"], c["created_by_me"]) for c in data["conversations"]])
    while post("A", "/message/poll", {"session_token": ta2})[1].get("message"):
        pass

    print("Planned message over a restart (default lifetime 3 s in this test)")
    # 20 s: enough time for the restart also when the machine is busy (e.g. all tests at once)
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": "after restart", "mode": "fast",
                                               "send_in_seconds": 20})
    planned = data["message_id"]
    time.sleep(2.5)  # periodic backup at B
    stop("A")
    check("A is back", start("A"))
    status, data = post("A", "/message/status", {"session_token": ta1, "message_id": planned})
    check("the planned message survived the restart", data.get("state") == "scheduled", data)
    deadline = time.time() + 25
    content = None
    while time.time() < deadline and content is None:
        status, data = post("A", "/message/poll", {"session_token": ta2, "wait_seconds": 2})
        content = data.get("content")
    check("... and arrives at its time (not dropped as expired)", content == "after restart", content)

    print("Backup too big")
    random_text = base64.b64encode(os.urandom(600 * 1024)).decode()
    for _ in range(3):
        post("A", "/message/send", {"session_token": ta1, "recipient_ip": a1, "content": random_text, "mode": "safe",
                                    "expires_in_seconds": 600})
    status, data = post("A", "/admin/backup/now", {"password": PASSWORD["A"]})
    status, backup_state = post("A", "/admin/backup/status", {"password": PASSWORD["A"]})
    check("over the limit: still a backup - without the mailbox contents", URL["B"] in (data.get("sent_to") or [])
          and backup_state.get("without_messages") is True, (data, backup_state.get("without_messages")))


if __name__ == "__main__":
    main()
