"""End-to-end test of the BridgeAgent routing and the analysis with three real Bridge servers that all trust each
other (A, B, C). The line A -> C is made broken / slow on purpose (test fault file), so the agent has to find the way
over B.

Run from the project folder:  python tests/e2e_routing.py
"""
import json
import os
import subprocess
import sys
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = {"A": 8201, "B": 8202, "C": 8203}
URL = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
PASSWORD = {"A": "admin-A", "B": "admin-B", "C": "admin-C"}
TRUSTS = {"A": ["B", "C"], "B": ["A", "C"], "C": ["A", "B"]}
OVERRIDES = {"link_exchange_seconds": 1, "backup_restore_wait_seconds": 3, "s2s_timeout_seconds": 3}
SERVER_OVERRIDES = {}
FAULTS = os.path.join(ROOT, "tests", "routing_faults.json")

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
    if name == "A":
        env["BRIDGE_TEST_LINK_FAULTS_FILE"] = FAULTS
    logs.setdefault(name, open(os.path.join(ROOT, "tests", f"routing_{name}.log"), "a"))
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
        check("A, B, C all connected", wait_connected("A", 2) and wait_connected("B", 2) and wait_connected("C", 2))
        scenarios()
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.kill()
    print(f"\n{results['ok']} ok, {results['fail']} failed")
    sys.exit(1 if results["fail"] else 0)


def faults(value):
    with open(FAULTS, "w", encoding="utf-8") as file:
        json.dump(value, file)


def receive(server, token, wait=3):
    status, data = post(server, "/message/poll", {"session_token": token, "wait_seconds": wait})
    return data.get("message"), data.get("content")


def routes(server="A"):
    return post(server, "/admin/routes", {"password": PASSWORD[server]})[1]


def scenarios():
    faults({})
    a1, ta1 = register("A", "a1")
    c1, tc1 = register("C", "c1")
    time.sleep(1.5)  # line tables are exchanged every second (test setting)

    print("Everything fine: direct")
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": c1, "content": 1, "mode": "fast"})
    meta, content = receive("C", tc1)
    check("A -> C direct", status == 200 and meta and meta["relayed_via"] == [], meta)
    data = routes()
    check("/admin/routes: lines, partner tables and best ways", data["links"].get(URL["C"], {}).get("connected")
          and URL["B"] in data["partner_tables"] and data["best_ways"].get(URL["C"]), data)

    print("Line A -> C broken, routing = direct (as before)")
    faults({URL["C"]: {"fail": True}})
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": c1, "content": "lost", "mode": "fast"})
    check("the message does not arrive", status >= 400, data)

    print("Line A -> C broken, routing = agent")
    post("A", "/admin/settings", {"password": PASSWORD["A"], "routing": "agent"})
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": c1, "content": "around", "mode": "fast",
                                               "conversation_id": "way"})
    meta, content = receive("C", tc1)
    check("the agent finds the way over B", status == 200 and content == "around" and meta["relayed_via"] == [URL["B"]], (data, meta))
    time.sleep(1.5)
    data = routes()
    best = data["best_ways"].get(URL["C"], [{}])[0]
    check("after the failures the best way to C is over B", best.get("way") == f"over {URL['B']}", data["best_ways"].get(URL["C"]))
    check("... the line shows the failures", data["links"][URL["C"]]["fails_in_row"] >= 3, data["links"].get(URL["C"]))
    started = time.time()
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": c1, "content": "fast now", "mode": "fast"})
    meta, content = receive("C", tc1)
    check("next messages go over B at once (no waiting for the broken line)", content == "fast now" and time.time() - started < 1.5,
          time.time() - started)
    status, data = post("A", "/conversation/stream", {"session_token": ta1, "conversation_id": "way"})
    check("the conversation stream shows the way over B", data.get("entries") and data["entries"][0]["route"] == f"relay:{URL['B']}",
          data.get("entries"))
    status, data = post("A", "/message/status", {"session_token": ta1, "message_id": data["entries"][0]["message_id"]})

    print("Line A -> C works again")
    faults({})
    time.sleep(2.5)  # the line table exchange uses the line again -> it is healthy
    data = routes()
    check("the direct way is the best again", data["best_ways"].get(URL["C"], [{}])[0].get("way") == "direct", data["best_ways"].get(URL["C"]))
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": c1, "content": "direct again", "mode": "fast"})
    meta, content = receive("C", tc1)
    check("... and is used", content == "direct again" and meta["relayed_via"] == [], meta)

    print("Line A -> C very slow")
    faults({URL["C"]: {"delay": 0.6}})
    time.sleep(4)  # a few slow line table requests -> the agent learns the latency
    data = routes()
    check("a very slow line: the way over B is better", data["best_ways"].get(URL["C"], [{}])[0].get("way") == f"over {URL['B']}",
          (data["links"].get(URL["C"]), data["best_ways"].get(URL["C"])))
    started = time.time()
    post("A", "/message/send", {"session_token": ta1, "recipient_ip": c1, "content": "quick", "mode": "fast"})
    meta, content = receive("C", tc1)
    check("... the message is quick over B", content == "quick" and meta["relayed_via"] == [URL["B"]] and time.time() - started < 0.6,
          (meta, time.time() - started))
    faults({})

    print("Analysis")
    status, data = post("A", "/admin/analysis", {"password": PASSWORD["A"]})
    counters = data.get("counters", {})
    check("counters for the last minute / hour / since start", counters.get("messages sent direct", {}).get("total", 0) >= 4
          and "last_minute" in counters.get("messages sent direct", {}), counters.get("messages sent direct"))
    # Failover: the first message after breaking the line tries direct first. If the machine is busy, the line table
    # exchange (every second) may have seen the broken line 3 times already - then even the first message goes over
    # B at once (right too), and there is no failover to count.
    relays = counters.get("routes relay", {}).get("total", 0)
    check("ways used: relay and failover are counted", relays >= 2
          and (counters.get("routes failover", {}).get("total", 0) >= 1 or relays >= 3),
          {k: v for k, v in counters.items() if k.startswith("routes")})
    check("timings with p50 / p90 (delivery, HTTP per endpoint)", data["timings"].get("deliver", {}).get("p90_s") is not None
          and "http /message/send" in data["timings"], list(data.get("timings", {})))
    check("lines, mailboxes, errors in the report", URL["C"] in data.get("links", {}) and "biggest_mailboxes" in data and "errors" in data)
    status, data = post("C", "/admin/analysis", {"password": PASSWORD["C"]})
    check("C counted the received messages", data["counters"].get("messages received direct", {}).get("total", 0) >= 5,
          data["counters"].get("messages received direct"))


if __name__ == "__main__":
    main()
