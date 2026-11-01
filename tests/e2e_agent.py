"""End-to-end test of the BridgeAgent with two real Bridge servers A <-> B and simulated hosts on B.

Run from the project folder:  python tests/e2e_agent.py
"""
import json
import os
import threading
import subprocess
import sys
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = {"A": 8171, "B": 8172}
URL = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
PASSWORD = {"A": "admin-A", "B": "admin-B"}
TRUSTS = {"A": ["B"], "B": ["A"]}
OVERRIDES = {"backup_restore_wait_seconds": 3, "backup_interval_seconds": 2}
# Tasks on B expire after 6 seconds, so a host that never answers shows up quickly
SERVER_OVERRIDES = {"B": {"command_response_minutes": 0.1}}

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
    logs.setdefault(name, open(os.path.join(ROOT, "tests", f"agent_{name}.log"), "a"))
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


class Host(threading.Thread):
    """A simulated host: takes its tasks and answers after `delay` seconds (pause() stops taking tasks)."""

    def __init__(self, server, token, delay):
        super().__init__(daemon=True)
        self.server, self.token, self.delay = server, token, delay
        self.running = threading.Event()
        self.running.set()
        self.stopped = False

    def run(self):
        while not self.stopped:
            if not self.running.is_set():
                time.sleep(0.05)
                continue
            status, data = post(self.server, "/message/poll", {"session_token": self.token, "content_types": ["task"],
                                                               "wait_seconds": 1})
            if not data or not data.get("message"):
                continue
            time.sleep(self.delay)
            post(self.server, "/command/respond", {"session_token": self.token, "task_id": data["message"]["message_id"],
                                                   "content": "ok", "mode": "fast"})


def scenarios():
    a1, ta1 = register("A", "a1")
    b1, tb1 = register("B", "b1")
    b2, tb2 = register("B", "b2")
    b3, tb3 = register("B", "b3")
    public_b = httpx.get(URL["B"] + "/realm/public").json()["realm_address"]
    for token in (tb1, tb2):
        post("B", "/realm/command/create", {"session_token": token, "realm_address": public_b, "command_name": "work"})
    post("B", "/realm/command/create", {"session_token": tb3, "realm_address": public_b, "command_name": "lazy"})
    fast_host, slow_host = Host("B", tb1, 0.2), Host("B", tb2, 0.9)
    fast_host.start()
    slow_host.start()

    print("Estimate before anything was learned")
    status, data = post("A", "/agent/estimate", {"session_token": ta1, "command_name": "work", "realm_address": public_b})
    check("estimate answers for both hosts", status == 200 and len(data.get("hosts", [])) == 2, data)
    check("... based on the baseline / general experience", all(h["processing"]["based_on"] in ("baseline", "general") for h in data.get("hosts", [])), data)
    check("... with a recommended wait_seconds", isinstance(data.get("recommended_wait_seconds"), int), data)

    print("Learning from calls")
    counts = {b1: 0, b2: 0}
    for _ in range(60):
        # random strategy until both hosts have enough tasks (does not depend on luck)
        data = post("A", "/command/call", {"session_token": ta1, "command_name": "work", "realm_address": public_b,
                                           "mode": "fast", "strategy": "random", "wait_seconds": 5})[1]
        counts[data.get("host_ip")] = counts.get(data.get("host_ip"), 0) + 1
        if counts[b1] >= 6 and counts[b2] >= 6:
            break
    status, data = post("A", "/agent/estimate", {"session_token": ta1, "command_name": "work", "realm_address": public_b})
    hosts = {h["host_ip"]: h for h in data.get("hosts", [])}
    fast, slow = hosts.get(b1, {}), hosts.get(b2, {})
    check("processing time learned per host (own model)", fast.get("processing", {}).get("based_on") == "own"
          and slow.get("processing", {}).get("based_on") == "own", data)
    check("fast host ~0.2 s, slow host ~0.9 s", 0.1 < fast["processing"]["typical_s"] < 0.45 and 0.5 < slow["processing"]["typical_s"] < 1.8,
          (fast.get("processing"), slow.get("processing")))
    check("the fast host is recommended", data.get("recommended_host") == b1, data.get("recommended_host"))
    check("worst case is above typical", fast["worst_s"] >= fast["typical_s"], fast)
    picked = [post("A", "/command/call", {"session_token": ta1, "command_name": "work", "realm_address": public_b, "mode": "fast",
                                          "strategy": "fastest", "wait_seconds": 5})[1]["host_ip"] for _ in range(4)]
    check("strategy fastest takes the fast host", picked.count(b1) >= 3, picked)

    print("Status of a running task")
    fast_host.running.clear()
    slow_host.running.clear()
    time.sleep(1.2)  # both hosts are out of their last poll
    first = post("A", "/command/call", {"session_token": ta1, "command_name": "work", "realm_address": public_b, "mode": "safe",
                                        "strategy": "least_busy", "progress": "latest"})[1]
    second = post("A", "/command/call", {"session_token": ta1, "command_name": "work", "realm_address": public_b, "mode": "safe",
                                         "strategy": "random"})[1]
    host_token = {b1: tb1, b2: tb2}
    status, data = post("A", "/agent/task", {"session_token": ta1, "task_id": first["task_id"]})
    check("task waits in the host's mailbox, with position", status == 200 and data.get("state") == "waiting" and data.get("position", 0) >= 1, data)
    check("... with remaining time and risk", isinstance(data.get("remaining"), dict) and data.get("risk_of_expiry") in ("low", "medium"), data)
    token = host_token[first["host_ip"]]
    status, polled = post("B", "/message/poll", {"session_token": token, "content_types": ["task"]})
    while polled.get("message") and polled["message"]["message_id"] != first["task_id"]:
        post("B", "/message/cancel", {"session_token": token, "pending_id": polled["pending_id"]})
        status, polled = post("B", "/message/poll", {"session_token": token, "content_types": ["task"]})
    time.sleep(0.5)
    status, data = post("A", "/agent/task", {"session_token": ta1, "task_id": first["task_id"]})
    check("host took it (safe, not confirmed) -> processing, with since", data.get("state") == "processing"
          and data.get("processing_since_s", 0) >= 0.4, data)
    post("B", "/command/progress", {"session_token": token, "task_id": first["task_id"], "percent": 50})
    time.sleep(0.2)
    status, data = post("A", "/agent/task", {"session_token": ta1, "task_id": first["task_id"]})
    check("progress 50 % -> remaining about the time so far", data.get("progress_percent") == 50
          and 0.3 < data["remaining"]["typical_s"] < 2.0, data)
    post("B", "/command/respond", {"session_token": token, "task_id": first["task_id"], "content": "ok", "mode": "fast"})
    post("B", "/message/cancel", {"session_token": token, "pending_id": polled["pending_id"]})
    time.sleep(0.3)
    status, data = post("A", "/agent/task", {"session_token": ta1, "task_id": first["task_id"]})
    check("after the response: answered", data.get("state") == "answered", data)
    fast_host.running.set()
    slow_host.running.set()
    status, data = post("A", "/agent/task", {"session_token": tb1, "task_id": second["task_id"]})
    check("another client cannot ask for my task", status in (401, 404), data)

    print("Recipient info for direct messages")
    status, data = post("A", "/agent/message", {"session_token": ta1, "recipient_ip": b1})
    check("b1 is known and active, with the time until it takes a message", status == 200 and data.get("known") is True
          and data.get("active") is True and isinstance(data.get("until_taken"), dict), data)
    post("B", "/client/direct", {"session_token": tb3, "mode": "nobody"})
    status, data = post("A", "/agent/message", {"session_token": ta1, "recipient_ip": b3})
    check("who accepts no direct messages tells nothing about itself", data.get("accepts_direct") is False and "last_seen_s" not in data, data)

    print("Reliability")
    for _ in range(2):
        post("A", "/command/call", {"session_token": ta1, "command_name": "lazy", "realm_address": public_b, "mode": "fast"})
    time.sleep(6.5)  # tasks on B expire after 6 seconds (test setting)
    post("A", "/command/call", {"session_token": ta1, "command_name": "work", "realm_address": public_b, "mode": "fast", "wait_seconds": 5})
    status, data = post("B", "/admin/agent", {"password": PASSWORD["B"]})
    unreliable = {entry["host_ip"]: entry["reliability"] for entry in data.get("unreliable_hosts", [])}
    check("a host that never answers becomes unreliable", b3 in unreliable and unreliable[b3] < 0.8, data.get("unreliable_hosts"))

    print("Admin, modes and backup")
    status, data = post("A", "/admin/agent", {"password": PASSWORD["A"]})
    check("admin status: models, accuracy, load profile", status == 200 and data["models"].get("deliver", {}).get("samples", 0) > 0
          and "within_worst_case" in data["accuracy"]["deliver"] and len(data["load_profile_utc"]) == 24, data)
    status, exported = post("B", "/admin/agent", {"password": PASSWORD["B"], "action": "export"})
    check("export has the format of baseline.json", exported.get("format") == 1 and set(exported.get("kinds", {})) ==
          {"deliver", "s2s", "pickup", "process", "roundtrip"}, list(exported))
    post("A", "/admin/settings", {"password": PASSWORD["A"], "agent_mode": "frozen"})
    before = post("A", "/admin/agent", {"password": PASSWORD["A"]})[1]["models"]["deliver"]["samples"]
    post("A", "/message/send", {"session_token": ta1, "recipient_ip": b1, "content": 1, "mode": "fast"})
    after = post("A", "/admin/agent", {"password": PASSWORD["A"]})[1]["models"]["deliver"]["samples"]
    check("frozen: estimates still work, but nothing is learned", after == before
          and post("A", "/agent/estimate", {"session_token": ta1, "command_name": "work", "realm_address": public_b})[0] == 200)
    post("A", "/admin/settings", {"password": PASSWORD["A"], "agent_mode": "off"})
    status, data = post("A", "/agent/estimate", {"session_token": ta1, "command_name": "work", "realm_address": public_b})
    check("off -> 503 AGENT_OFF", status == 503 and data["detail"]["error"] == "AGENT_OFF", data)
    post("A", "/admin/settings", {"password": PASSWORD["A"], "agent_mode": "learn"})
    models_before = post("B", "/admin/agent", {"password": PASSWORD["B"]})[1]["models"]
    fast_host.stopped = slow_host.stopped = True
    time.sleep(1.5)
    stop("B")  # normal stop -> last backup at A (includes what the agent learned)
    check("B is back", start("B"))
    models_after = post("B", "/admin/agent", {"password": PASSWORD["B"]})[1]["models"]
    check("what the agent learned survived the restart (backup at A)",
          models_after.get("process", {}).get("samples", 0) >= models_before.get("process", {}).get("samples", 0) > 0,
          (models_before.get("process"), models_after.get("process")))
    status, data = post("B", "/admin/agent", {"password": PASSWORD["B"], "action": "reset"})
    check("reset: only the general models from the baseline are left",
          status == 200 and all(entry["models"] == 1 for entry in data["status"]["models"].values()), data.get("status", {}).get("models"))


if __name__ == "__main__":
    main()
