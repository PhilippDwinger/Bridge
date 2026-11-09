"""Regression test for the bug hunt of 01.11.2026 (56 findings): every fixed bug that can be checked from outside.
Three servers: A and B trust each other, C is neutral.

Run from the project folder:  python tests/e2e_bugfixes.py
"""
import base64
import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
import time
import zlib

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = {"A": 8231, "B": 8232, "C": 8233}
URL = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
PASSWORD = {"A": "admin-A", "B": "admin-B", "C": "admin-C"}
TRUSTS = {"A": ["B"], "B": ["A"], "C": []}
OVERRIDES = {"backup_restore_wait_seconds": 3, "s2s_timeout_seconds": 3, "backup_interval_seconds": 2,
             "friend_status_cache_seconds": 0, "friend_requests_per_minute": 100, "max_scheduled_mb_per_client": 1}
SERVER_OVERRIDES = {}
FAULTS = os.path.join(ROOT, "tests", "bugfix_faults.json")

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
    if name == "C":
        env["BRIDGE_TEST_LINK_FAULTS_FILE"] = FAULTS
    logs.setdefault(name, open(os.path.join(ROOT, "tests", f"bugfix_{name}.log"), "a"))
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
        check("A and B connected (C trusts nobody)", wait_connected("A", 1) and wait_connected("B", 1))
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


def detail(data):
    return (data or {}).get("detail") or {}


def receive(server, token, types=None, wait=3):
    """Next message (also safe / compressed: chunks, unpack, hash, complete) -> (meta, content) or (None, None)."""
    body = {"session_token": token, "wait_seconds": wait}
    if types:
        body["content_types"] = types
    status, data = post(server, "/message/poll", body)
    meta = data.get("message")
    if meta is None:
        return None, None
    if "pending_id" not in data:
        return meta, data["content"]
    chunks = [post(server, "/message/chunk", {"session_token": token, "pending_id": data["pending_id"], "chunk_index": index})[1]["chunk"]
              for index in range(meta["chunk_count"])]
    text = "".join(chunks)
    if meta.get("encoding") == "zlib+base64":
        text = zlib.decompress(base64.b64decode(text)).decode("utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    post(server, "/message/complete", {"session_token": token, "pending_id": data["pending_id"], "sha256": digest})
    return meta, json.loads(text)


def drain(server, token, types=None):
    while receive(server, token, types, wait=0)[0] is not None:
        pass


def friends_of(server, token):
    status, data = post(server, "/friends/list", {"session_token": token})
    return {friend["friend_ip"]: friend for friend in data["friends"]}


def instruction(server, token, kind, wait=3):
    deadline = time.time() + wait
    while time.time() < deadline:
        meta, content = receive(server, token, ["instruction"], wait=1)
        if meta is not None and content.get("instruction") == kind:
            return meta, content
    return None, None


def raw(server, path, text):
    response = httpx.post(URL[server] + path, content=text.encode("utf-8"), headers={"Content-Type": "application/json"}, timeout=60)
    return response.status_code, response.text


def scenarios():
    faults({})
    a1, ta1 = register("A", "a1")
    a2, ta2 = register("A", "a2")
    b1, tb1 = register("B", "b1")
    c1, tc1 = register("C", "c1")
    public_a = httpx.get(URL["A"] + "/realm/public").json()["realm_address"]

    print("Messages")
    deep = "[" * 3000 + "]" * 3000
    status, text = raw("A", "/message/send", json.dumps({"session_token": ta1, "recipient_ip": a2, "mode": "fast"})[:-1] + f', "content": {deep}}}')
    meta, content = receive("A", ta2, wait=0)
    check("3000 times nested content -> 400, nothing lost on poll", status == 400 and meta is None, text[:150])
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": 1, "expires_in_seconds": 1e12})
    check("expires_in_seconds 1e12 -> 400 (no 500)", status == 400, data)
    status, text = raw("A", "/message/poll", json.dumps({"session_token": ta1})[:-1] + ', "wait_seconds": ' + "9" * 400 + "}")
    check("wait_seconds with 400 digits -> 400", status == 400, text[:150])
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": 1, "mode": "temporary",
                                               "send_in_seconds": 30})
    check("temporary + planned without lifetime -> 400", status == 400, data)
    big = "x" * 700_000
    first = post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": big, "send_in_seconds": 600})[0]
    second = post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": big, "send_in_seconds": 600})[0]
    check("byte budget for planned messages (test: 1 MB per client)", first == 200 and second >= 400, (first, second))
    status, data = post("A", "/message/send", {"session_token": ta1, "recipient_ip": a2, "content": 1,
                                               "send_at": "2027-03-28T02:30:00", "timezone": "Europe/Berlin"})
    check("a time that does not exist (summer time) -> 400", status == 400, data)

    print("Logins and admin")
    # On C: the lock is right, but it locks the admin of that server for some minutes (A and B are needed later)
    with concurrent.futures.ThreadPoolExecutor(30) as pool:
        statuses = list(pool.map(lambda _: post("C", "/admin/status", {"password": "wrong"})[0], range(30)))
    check("30 parallel wrong admin passwords -> the lock still works", statuses.count(429) >= 20, sorted(set(statuses)))
    b_other, _ = register("B", "b-other")
    for i in range(4):
        post("B", "/client/login", {"client_ip": b1, "password": "wrong"})
    own = post("B", "/client/login", {"client_ip": b_other, "password": "pw-b-other"})[0]
    fifth = post("B", "/client/login", {"client_ip": b1, "password": "wrong"})[0]
    status, data = post("B", "/client/login", {"client_ip": b1, "password": "pw-b1"})
    check("logging into an own account between guesses does not reset the lock", own == 200 and fifth == 401 and status == 429,
          (own, fifth, status))
    tokens = [post("A", "/client/login", {"client_ip": a2, "password": "pw-a2"})[1]["session_token"] for _ in range(22)]
    status, data = post("A", "/client/me", {"session_token": tokens[0]})
    check("at most 20 sessions per client - the oldest goes", status == 401 and post("A", "/client/me", {"session_token": tokens[-1]})[0] == 200,
          status)
    ta2 = tokens[-1]

    print("Realms")
    status, data = post("A", "/realm/create", {"session_token": ta1, "realm_type": "private", "realm_name": "Geheim"})
    secret_realm = data["realm_address"]
    status, data = post("A", "/realm/code/create", {"session_token": ta1, "realm_address": secret_realm, "preferred_code": "QWERTZ23"})
    status, own = post("A", "/realm/create", {"session_token": ta2, "realm_type": "protected", "realm_name": "Probe"})
    answers = [post("A", "/realm/code/create", {"session_token": ta2, "realm_address": own["realm_address"], "preferred_code": "QWERTZ23"})[0]
               for _ in range(6)]
    check("preferred_code that is taken counts like a wrong code (then 429)", answers[0] == 409 and answers[-1] == 429, answers)
    status, data = post("A", "/realm/code/create", {"session_token": ta1, "realm_address": secret_realm, "expires_in_minutes": 0.0001})
    check("codes live at least one minute", status == 400, data)
    status, data = post("A", "/realm/code/create", {"session_token": ta1, "realm_address": secret_realm, "max_uses": 5})
    code = data.get("code") if isinstance(data, dict) else None
    post("A", "/realm/role/create", {"session_token": ta1, "realm_address": secret_realm, "role_name": "worker", "can_host_commands": True})
    status, data = post("B", "/realm/join", {"session_token": tb1, "code": code, "server_url": URL["A"]})
    post("A", "/realm/role/set", {"session_token": ta1, "realm_address": secret_realm, "member_ip": b1, "roles": ["worker"]})
    status, data = post("B", "/realm/command/create", {"session_token": tb1, "realm_address": secret_realm, "command_name": "job"})
    hosted = status == 200
    post("A", "/realm/role/set", {"session_token": ta1, "realm_address": secret_realm, "member_ip": b1, "roles": []})
    status, catalog = post("A", "/realm/commands", {"session_token": ta1, "realm_address": secret_realm})
    status_call, data = post("A", "/command/call", {"session_token": ta1, "command_name": "job", "realm_address": secret_realm})
    check("role taken away -> the hosted command is gone (catalog, calls)", hosted and "job" not in (catalog or {}) and status_call == 404,
          (hosted, catalog, status_call))
    c_join, tc_join = register("A", "joiner")
    results = []
    for i in range(4):
        results.append(post("A", "/realm/join", {"session_token": tc_join, "code": f"ZZZZZZ{i}{i}"})[0])
    post("A", "/realm/join", {"session_token": tc_join, "realm_address": public_a})
    results.append(post("A", "/realm/join", {"session_token": tc_join, "code": "ZZZZZZ99"})[0])
    results.append(post("A", "/realm/join", {"session_token": tc_join, "code": "ZZZZZZ88"})[0])
    check("joining the public realm does not reset the counter of wrong codes", results[-1] == 429, results)

    print("BridgeExpress")
    union = " | ".join(f'list<number | "{i}">' for i in range(20))
    post("A", "/realm/command/create", {"session_token": ta2, "realm_address": public_a, "command_name": "slow",
                                        "signature": {"params": [{"name": "a", "type": union}], "returns": "any"}})
    started = time.time()
    status, data = post("A", "/command/call", {"session_token": ta1, "command_name": "slow", "realm_address": public_a,
                                               "command_args": {"a": [1] * 300000 + ["z"]}})
    check("huge argument with a long union type: answered fast (budget), refused", status == 400 and time.time() - started < 5,
          (status, round(time.time() - started, 2)))

    print("BridgeFriends")
    post("A", "/friends/invite", {"session_token": ta1, "name": "alpha-home", "password": "geheim-123"})
    status, data = post("C", "/friends/add", {"session_token": tc1, "address": f"alpha-home@{URL['A']}", "password": "geheim-123"})
    check("friends A <-> C (neutral)", status == 200 and data["state"] == "active", data)
    response = httpx.post(URL["A"] + "/s2s/friends/link/hello", json={"from_url": URL["C"]})
    status, data = post("C", "/friends/send", {"session_token": tc1, "friend_ip": a1, "content": "noch da", "mode": "fast"})
    meta, content = receive("A", ta1, ["friend"])
    check("a fake hello does not cut the friend connection", status == 200 and content == "noch da", (response.text[:100], data))
    real = [post("C", "/friends/add", {"session_token": tc1, "address": f"alpha-home@{URL['A']}", "password": f"falsch-{i}"})[0] for i in range(6)]
    fake = [post("C", "/friends/add", {"session_token": tc1, "address": f"gibts-nicht@{URL['A']}", "password": f"falsch-{i}"})[0] for i in range(6)]
    check("lock after wrong passwords looks the same for unknown names", real == fake and real[-1] == 429, (real, fake))
    a2c, ta2c = register("A", "a-code")
    status, door = post("A", "/friends/invite", {"session_token": ta2c, "name": "sandra22", "password": "passwort-1"})
    check("names that look like a code are allowed", status == 200, door)
    # Another server under a path on C's host and port is ANOTHER server (several servers per host:port) - no block
    status, data = post("A", "/admin/blocked/add", {"password": PASSWORD["A"], "url": URL["C"] + "/irgendwas/"})
    friend = {f["friend_ip"]: f for f in post("A", "/friends/list", {"session_token": ta1})[1]["friends"]}.get(c1, {})
    check("blocking another server on C's host (other path) does not block C", status == 200 and friend.get("via") != "blocked", (data, friend.get("via")))
    post("A", "/admin/blocked/remove", {"password": PASSWORD["A"], "url": URL["C"] + "/irgendwas/"})
    # Another spelling of C itself (Bridge route at the end, upper case, trailing /) blocks C
    status, data = post("A", "/admin/blocked/add", {"password": PASSWORD["A"], "url": URL["C"] + "/ADMIN/"})
    friend = {f["friend_ip"]: f for f in post("A", "/friends/list", {"session_token": ta1})[1]["friends"]}.get(c1, {})
    check("blocking another spelling of C's URL blocks C", status == 200 and friend.get("via") == "blocked", (data, friend.get("via")))
    post("A", "/admin/blocked/remove", {"password": PASSWORD["A"], "url": URL["C"] + "/"})
    status, data = post("A", "/friends/add", {"session_token": ta1, "address": "x@https://zzä..example.com", "password": ""})
    check("a broken server URL -> 400, no 500", status == 400, data)

    print("Restart of A: friendships survive the restore window")
    time.sleep(2.5)  # periodic backup at B
    stop("A")
    overrides = dict(OVERRIDES)
    env = dict(os.environ, PYTHONUNBUFFERED="1", BRIDGE_TEST_OVERRIDES=json.dumps(overrides), BRIDGE_STDIN_CONTROL="1")
    processes["A"] = subprocess.Popen([sys.executable, "tests/run_server.py", str(PORTS["A"]), PASSWORD["A"]] + [URL[o] for o in TRUSTS["A"]],
                                      cwd=ROOT, stdin=subprocess.PIPE, stdout=logs["A"], stderr=logs["A"], env=env)
    seen = []
    deadline = time.time() + 8
    while time.time() < deadline:
        status, data = post("C", "/friends/list", {"session_token": tc1})
        seen.append(len(data.get("friends", [])) if isinstance(data, dict) else -1)
        time.sleep(0.2)
    for _ in range(100):
        try:
            if httpx.get(URL["A"] + "/server/status", timeout=1).json().get("ready"):
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    status, data = post("C", "/friends/list", {"session_token": tc1})
    status_a, data_a = post("A", "/friends/list", {"session_token": ta1})
    check("C kept the friendship while A was restoring (and A has it again)", min(seen) == 1
          and any(f["friend_ip"] == a1 for f in data.get("friends", []))
          and any(f["friend_ip"] == c1 for f in data_a.get("friends", [])), (seen[:10], data_a))

    print("Backup bigger than the normal request limit (17 MiB)")
    filler, tf = register("A", "filler")
    senders = [register("A", f"s{i}") for i in range(2)]
    for ip, token in senders:
        for i in range(12):
            post("A", "/message/send", {"session_token": token, "recipient_ip": filler, "mode": "safe", "expires_in_seconds": 600,
                                        "content": base64.b64encode(os.urandom(700_000)).decode()})
    status, data = post("A", "/admin/backup/now", {"password": PASSWORD["A"]})
    status, state = post("A", "/admin/backup/status", {"password": PASSWORD["A"]})
    check("a ~22 MB backup is stored at B (with the messages)", URL["B"] in (data.get("sent_to") or [])
          and not state.get("without_messages") and (data.get("size_bytes") or 0) > 17 * 1024 * 1024, (data, state.get("last_error")))


if __name__ == "__main__":
    main()
