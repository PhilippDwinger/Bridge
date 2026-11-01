"""End-to-end test of the realm sync with three real Bridge servers:  A <-> B <-> C

Realms on A and C, the member b1 lives on B. B keeps a synced copy of the realms.
C sends no pushes in this test, so only the regular version check can bring its changes to B.

Run from the project folder:  python tests/e2e_realm_sync.py
"""
import json
import os
import subprocess
import sys
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = {"A": 8151, "B": 8152, "C": 8153}
URL = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
PASSWORD = {"A": "admin-A", "B": "admin-B", "C": "admin-C"}
TRUSTS = {"A": ["B"], "B": ["A", "C"], "C": ["B"]}
OVERRIDES = {"realm_sync_seconds": 1, "realm_stale_seconds": 3, "backup_interval_seconds": 2,
             "backup_restore_wait_seconds": 4}
# C never pushes (the push waits "forever") - its changes only arrive with the regular sync
SERVER_OVERRIDES = {"C": {"realm_push_delay_seconds": 9999}}

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
    logs.setdefault(name, open(os.path.join(ROOT, "tests", f"sync_{name}.log"), "a"))
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
        check("A, B, C connected (A-B, B-C)", wait_connected("A", 1) and wait_connected("B", 2) and wait_connected("C", 1))
        scenarios()
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.kill()
    print(f"\n{results['ok']} ok, {results['fail']} failed")
    sys.exit(1 if results["fail"] else 0)


def scenarios():
    a1, ta1 = register("A", "a1")
    a2, ta2 = register("A", "a2")
    b1, tb1 = register("B", "b1")
    c1, tc1 = register("C", "c1")

    print("Copy of a realm on the member's server (push)")
    status, data = post("A", "/realm/create", {"session_token": ta1, "realm_type": "private", "realm_name": "Guild"})
    guild = data["realm_address"]
    post("A", "/realm/role/create", {"session_token": ta1, "realm_address": guild, "role_name": "caller"})
    code = post("A", "/realm/code/create", {"session_token": ta1, "realm_address": guild, "roles": ["caller"]})[1]["code"]
    status, data = post("B", "/realm/join", {"session_token": tb1, "code": code, "server_url": URL["A"]})
    check("b1 (on B) joins the private realm on A", status == 200, data)
    check("B has a copy: name, type and version in /client/me",
          wait_until(lambda: me("B", tb1)["realm_details"].get(guild, {}).get("name") == "Guild")
          and me("B", tb1)["realm_details"][guild]["realm_type"] == "private", me("B", tb1)["realm_details"].get(guild))
    post("A", "/realm/command/create", {"session_token": ta1, "realm_address": guild, "command_name": "secret",
                                        "allowed_roles": ["caller"], "description": "only for callers"})
    check("new command reaches the copy at once",
          wait_until(lambda: "secret" in post("B", "/realm/commands", {"session_token": tb1, "realm_address": guild})[1]["commands"]))
    status, data = post("B", "/realm/commands", {"session_token": tb1, "realm_address": guild})
    check("catalog comes from the copy (no request to A)", data.get("source") == "mirror" and data.get("stale") is False, data)
    post("A", "/realm/role/set", {"session_token": ta1, "realm_address": guild, "member_ip": b1, "roles": []})
    check("role taken away -> command gone from b1's catalog",
          wait_until(lambda: "secret" not in post("B", "/realm/commands", {"session_token": tb1, "realm_address": guild})[1]["commands"]))
    status, data = post("B", "/realm/info", {"session_token": tb1, "realm_address": guild})
    check("info still comes from A while it is online", status == 200 and not data.get("from_mirror"), data)

    print("Kick across servers")
    post("A", "/realm/kick", {"session_token": ta1, "realm_address": guild, "member_ip": b1})
    check("kick on A -> b1 is no member anymore on B",
          wait_until(lambda: guild not in me("B", tb1)["realms"], 2), me("B", tb1)["realms"])
    status, data = post("B", "/realm/commands", {"session_token": tb1, "realm_address": guild})
    check("... and gets no catalog anymore -> 403", status == 403, data)

    print("Kick on the same server")
    code = post("A", "/realm/code/create", {"session_token": ta1, "realm_address": guild})[1]["code"]
    post("A", "/realm/join", {"session_token": ta2, "code": code})
    check("a2 joined", guild in me("A", ta2)["realms"])
    post("A", "/realm/kick", {"session_token": ta1, "realm_address": guild, "member_ip": a2})
    check("kick -> a2's own list is updated too", guild not in me("A", ta2)["realms"], me("A", ta2)["realms"])

    print("Regular version check (C sends no pushes)")
    status, data = post("C", "/realm/create", {"session_token": tc1, "realm_type": "protected", "realm_name": "Club",
                                               "access_key": "club-key"})
    club = data["realm_address"]
    status, data = post("B", "/realm/join", {"session_token": tb1, "realm_address": club, "access_key": "club-key"})
    check("b1 joins the protected realm on C", status == 200 and club in me("B", tb1)["realms"], data)
    check("copy of C's realm arrives with the regular sync",
          wait_until(lambda: me("B", tb1)["realm_details"].get(club, {}).get("name") == "Club", 4))
    post("C", "/realm/kick", {"session_token": tc1, "realm_address": club, "member_ip": b1})
    # C sends no push (test setting), so only the regular sync of B can bring the kick
    check("kick on C arrives with the regular sync",
          wait_until(lambda: club not in me("B", tb1)["realms"], 4), me("B", tb1)["realms"])

    print("Topics make members too")
    public_a = httpx.get(URL["A"] + "/realm/public").json()["realm_address"]
    post("B", "/realm/topic/subscribe", {"session_token": tb1, "realm_address": public_a, "topic": "news"})
    check("b1 subscribes in A's public realm -> it is in b1's realms",
          wait_until(lambda: public_a in me("B", tb1)["realms"], 2), me("B", tb1)["realms"])
    check("... and B has a copy of it",
          wait_until(lambda: me("B", tb1)["realm_details"].get(public_a, {}).get("realm_type") == "public", 2))

    print("Realm server offline -> copy is stale but readable")
    code = post("A", "/realm/code/create", {"session_token": ta1, "realm_address": guild, "roles": ["caller"]})[1]["code"]
    post("B", "/realm/join", {"session_token": tb1, "code": code, "server_url": URL["A"]})
    wait_until(lambda: me("B", tb1)["realm_details"].get(guild, {}).get("name") == "Guild", 3)
    time.sleep(2.5)  # periodic backup of A at B (test setting: every 2 seconds)
    stop("A", hard=True)
    check("after the stale time the copy is marked stale",
          wait_until(lambda: me("B", tb1)["realm_details"].get(guild, {}).get("stale") is True, 6),
          me("B", tb1)["realm_details"].get(guild))
    status, data = post("B", "/realm/info", {"session_token": tb1, "realm_address": guild})
    check("/realm/info answers from the copy", status == 200 and data.get("from_mirror") and data.get("stale"), data)
    status, data = post("B", "/realm/commands", {"session_token": tb1, "realm_address": guild})
    check("catalog from the copy, marked stale", status == 200 and data.get("source") == "mirror" and data.get("stale"), data)
    check("membership is kept while A is away", guild in me("B", tb1)["realms"])

    print("Realm server back")
    check("A is back", start("A"))
    check("copy is up to date again",
          wait_until(lambda: me("B", tb1)["realm_details"].get(guild, {}).get("stale") is False, 8),
          me("B", tb1)["realm_details"].get(guild))
    status, data = post("B", "/realm/info", {"session_token": tb1, "realm_address": guild})
    check("info comes from A again", status == 200 and not data.get("from_mirror"), data)
    status, data = post("B", "/admin/status", {"password": PASSWORD["B"]})
    check("admin status shows the realm sync", data.get("realm_sync", {}).get("mirrors", 0) >= 1, data.get("realm_sync"))


if __name__ == "__main__":
    main()
