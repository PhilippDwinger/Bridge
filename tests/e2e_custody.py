"""End-to-end test of the resilient backup custody chain (A -> B -> C and back to A).

Shows: A backs up to B only (A is not connected to C yet). B relays A's backup on to C. Then B is closed and A is
restarted - A gets its data back from C, although it never backed up to C directly.

Trust (who each server trusts at start):
  A -> B, C      B -> A, C      C -> B      (C does NOT trust A yet, so A connects only to B at first)

Run from the project folder:  python tests/e2e_custody.py
"""
import json
import os
import subprocess
import sys
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = {"A": 8501, "B": 8502, "C": 8503}
URL = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
PASSWORD = {"A": "admin-A", "B": "admin-B", "C": "admin-C"}
TRUSTS = {"A": ["B", "C"], "B": ["A", "C"], "C": ["B"]}
OVERRIDES = {"backup_interval_seconds": 2, "backup_restore_wait_seconds": 4}

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
    env = dict(os.environ, PYTHONUNBUFFERED="1", BRIDGE_TEST_OVERRIDES=json.dumps(OVERRIDES), BRIDGE_STDIN_CONTROL="1")
    logs.setdefault(name, open(os.path.join(ROOT, "tests", f"custody_{name}.log"), "a"))
    processes[name] = subprocess.Popen(
        [sys.executable, "tests/run_server.py", str(PORTS[name]), PASSWORD[name]] + [URL[o] for o in TRUSTS[name]],
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


def stop(name):
    process = processes[name]
    process.stdin.close()
    process.wait(25)


def holds_backup_of(custodian, owner_server):
    """True if `custodian` currently keeps a backup of `owner_server`."""
    status, data = post(custodian, "/admin/backup/status", {"password": PASSWORD[custodian]})
    if not isinstance(data, dict):
        return False
    kept = {entry["server_url"] for entry in data.get("stored_for_other_servers", [])}
    return URL[owner_server] in kept


def wait_until(condition, seconds=8.0):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(0.2)
    return condition()


def connected_to(server, other, seconds=8.0):
    def ok():
        status, data = post(server, "/admin/trusted/list", {"password": PASSWORD[server]})
        if not isinstance(data, dict):
            return False
        return any(s["url"] == URL[other] and s["status"] == "connected" for s in data.get("trusted_servers", []))
    return wait_until(ok, seconds)


def main():
    for name in ("B", "C"):          # the two keepers first
        assert start(name), f"{name} did not start"
    assert start("A"), "A did not start"
    try:
        check("A is connected to B", connected_to("A", "B"))
        check("A is NOT connected to C yet (C does not trust A)", not connected_to("A", "C", seconds=2))

        keep_ip, _ = register("A", "keep")
        check("B keeps A's backup (direct)", wait_until(lambda: holds_backup_of("B", "A")))
        check("C keeps A's backup (relayed through B)", wait_until(lambda: holds_backup_of("C", "A"), seconds=12))

        # Now let C trust A, so A can later ask C for its backup
        post("C", "/admin/trusted/add", {"password": PASSWORD["C"], "url": URL["A"]})
        post("C", "/admin/trusted/connect", {"password": PASSWORD["C"], "url": URL["A"]})
        check("A connects to C after C trusts it", connected_to("A", "C"))

        stop("B")                    # the server A backed up to is gone
        time.sleep(1)
        check("A restarts", (stop("A"), start("A"))[1])
        # A is fresh and only C is left - it must get its data back from C
        got = wait_until(lambda: post("A", "/client/login", {"client_ip": keep_ip, "password": "pw-keep"})[0] == 200, 12)
        check("A got its client back from C (A -> B -> C -> A)", got)
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.kill()
    print(f"\n{results['ok']} ok, {results['fail']} failed")
    sys.exit(1 if results["fail"] else 0)


if __name__ == "__main__":
    main()
