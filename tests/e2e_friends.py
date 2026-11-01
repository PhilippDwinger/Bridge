"""End-to-end test of BridgeFriends with three real Bridge servers: A and B trust each other, C trusts nobody and
nobody trusts C ("neutral"). Paddy's case: a client at home (on A) and one on the school PC (on C) become friends with
a name + password and talk to each other - without the servers trusting each other.

Run from the project folder:  python tests/e2e_friends.py
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import zlib

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = {"A": 8221, "B": 8222, "C": 8223}
URL = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
PASSWORD = {"A": "admin-A", "B": "admin-B", "C": "admin-C"}
TRUSTS = {"A": ["B"], "B": ["A"], "C": []}
OVERRIDES = {"backup_restore_wait_seconds": 3, "s2s_timeout_seconds": 3, "backup_interval_seconds": 2,
             "friend_status_cache_seconds": 0, "friend_requests_per_minute": 100, "host_inactive_seconds": 2}
SERVER_OVERRIDES = {}
FAULTS = os.path.join(ROOT, "tests", "friends_faults.json")

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
    logs.setdefault(name, open(os.path.join(ROOT, "tests", f"friends_{name}.log"), "a"))
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


def scenarios():
    faults({})
    a1, ta1 = register("A", "Paddy-Home")
    a2, ta2 = register("A", "a2")
    b1, tb1 = register("B", "b1")
    c1, tc1 = register("C", "School-PC")
    c2, tc2 = register("C", "c2")
    home = f"paddy-home@{URL['A']}"

    print("At home: a friend name with a password")
    status, door = post("A", "/friends/invite", {"session_token": ta1, "name": "paddy-home", "password": "sonnenblume",
                                                 "label": "Paddy zuhause"})
    check("invitation with a name: address name@server, lives until deleted", status == 200 and door["address"] == home
          and door["expires_at"] is None and door["max_uses"] is None and door["has_password"], door)
    status, data = post("A", "/friends/invite", {"session_token": ta2, "name": "Paddy-Home", "password": "xxxxxxxx"})
    check("the name is taken (big/small letters do not matter)", status == 409, data)
    status, data = post("A", "/friends/invite", {"session_token": ta2, "name": "kurz", "password": "123"})
    check("a name needs a password with at least 6 characters", status == 400, data)

    print("At school (server C - A and C do not trust each other)")
    status, wrong = post("C", "/friends/add", {"session_token": tc1, "address": home, "password": "falsch!!"})
    check("wrong password -> FRIEND_INVITE_INVALID", status == 403 and detail(wrong).get("error") == "FRIEND_INVITE_INVALID", wrong)
    status, unknown = post("C", "/friends/add", {"session_token": tc1, "address": f"gibtsnicht@{URL['A']}", "password": "sonnenblume"})
    check("an unknown name gives exactly the same answer (nobody can list the names)",
          status == 403 and detail(unknown).get("error") == detail(wrong).get("error")
          and detail(unknown).get("message") == detail(wrong).get("message"), (wrong, unknown))
    status, school = post("C", "/friends/add", {"session_token": tc1, "address": home, "password": "sonnenblume", "label": "Schul-PC"})
    check("right password -> friends at once (accept auto), over a neutral server", status == 200 and school["state"] == "active"
          and school["via"] == "neutral" and school["label"] == "Paddy zuhause", school)
    friends = friends_of("A", ta1)
    check("the home client has the school client as friend", friends.get(c1, {}).get("state") == "active"
          and friends[c1]["label"] == "Schul-PC", friends)
    check("both see the same safety code", friends.get(c1, {}).get("safety_code") == school.get("safety_code")
          and len(school.get("safety_code", "")) == 14, (friends.get(c1, {}).get("safety_code"), school.get("safety_code")))
    meta, content = instruction("A", ta1, "friend_added")
    check("the home client got the instruction friend_added (verified, from its server)", meta is not None
          and meta["verified"] and content["friend_ip"] == c1 and content["via"] == "neutral", content)
    status, data = post("A", "/admin/trusted/list", {"password": PASSWORD["A"]})
    status, overview = post("A", "/admin/friends", {"password": PASSWORD["A"]})
    check("A and C have a friend connection, but still no trust", URL["C"] not in [s["url"] for s in data["trusted_servers"]]
          and URL["C"] in overview["friend_connections"], (data, overview))
    status, data = post("C", "/friends/add", {"session_token": tc1, "address": home, "password": "sonnenblume"})
    check("adding again -> the same friendship (already)", status == 200 and data["already"] and data["safety_code"] == school["safety_code"], data)

    print("Friend messages")
    for mode in ("fast", "safe", "compressed", "temporary"):
        body = {"session_token": tc1, "friend_ip": a1, "content": {"mode": mode, "text": "hallo " * (800 if mode == "compressed" else 3)},
                "mode": mode}
        if mode == "temporary":
            body["expires_in_seconds"] = 60
        status, sent = post("C", "/friends/send", body)
        meta, content = receive("A", ta1, ["friend"])
        check(f"school -> home ({mode}): type friend, verified, sender = school client", status == 200 and meta is not None
              and meta["content_type"] == "friend" and meta["verified"] and meta["sender_ip"] == c1 and content["mode"] == mode,
              (sent, meta))
    status, sent = post("A", "/friends/send", {"session_token": ta1, "friend_ip": c1, "content": "Antwort", "mode": "fast"})
    meta, content = receive("C", tc1, ["friend"])
    check("home -> school", content == "Antwort" and meta["sender_ip"] == a1, meta)
    status, data = post("A", "/message/status", {"session_token": ta1, "message_id": sent.get("message_id")})
    check("message status over the friend connection: delivered", data.get("state") == "delivered", data)
    status, data = post("C", "/message/send", {"session_token": tc1, "recipient_ip": a1, "content": "direct", "mode": "fast"})
    check("a normal direct message still needs trust - only friends can talk", status >= 400, data)
    status, data = post("C", "/friends/send", {"session_token": tc2, "friend_ip": a1, "content": "hi", "mode": "fast"})
    check("no friend -> FRIEND_NOT_FOUND", status == 404 and detail(data).get("error") == "FRIEND_NOT_FOUND", data)
    status, data = post("C", "/friends/send", {"session_token": tc1, "friend_ip": a1, "content": "später", "mode": "fast",
                                               "send_in_seconds": 1, "conversation_id": "friend-conv"})
    meta, content = receive("A", ta1, ["friend"], wait=4)
    check("planned friend message arrives", data.get("state") == "scheduled" and content == "später", (data, content))
    status, data = post("C", "/conversation/stream", {"session_token": tc1, "conversation_id": "friend-conv"})
    entries = data.get("entries") or [{}]
    check("conversation stream: type friend, way friend:<server>, state from the friend's server",
          entries[0].get("type") == "friend" and entries[0].get("route") == f"friend:{URL['A']}"
          and entries[0].get("state") in ("taken", "delivered"), entries)

    print("Faking")
    fake_message = {"message_id": "f" * 32, "conversation_id": "x" * 32, "causation_id": None, "sender_ip": c1, "recipient_ip": a1,
                    "content_type": "friend", "mode": "fast", "size_bytes": 2, "sha256": "", "created_at": "2026-01-01T00:00:00+00:00",
                    "expires_at": "2099-01-01T00:00:00+00:00", "protocol_version": "3.0", "relayed_via": [], "payload": "\"x\""}
    response = httpx.post(URL["A"] + "/s2s/friends/message", json={"message": fake_message}, headers={"X-Bridge-From": URL["C"]})
    check("friend message without token -> 403", response.status_code == 403, response.text[:200])
    response = httpx.post(URL["A"] + "/s2s/friends/message", json={"message": fake_message},
                          headers={"X-Bridge-From": URL["C"], "X-Bridge-Friend-Token": "a" * 64})
    check("friend message with a guessed token -> 403", response.status_code == 403, response.text[:200])
    secret = "b" * 64
    response = httpx.post(URL["A"] + "/s2s/friends/link/deliver", json={"from_url": URL["C"], "secret": secret})
    # A is the generator for C (smaller URL), so C's deliver is wrong anyway - and the confirm callback would fail too
    response2 = httpx.post(URL["C"] + "/s2s/friends/link/deliver", json={"from_url": URL["A"], "secret": secret})
    check("a fake friend connection is rejected (the callback to the real server fails)",
          response.status_code == 403 and response2.status_code == 403, (response.text[:150], response2.text[:150]))
    response = httpx.post(URL["C"] + "/s2s/friends/status", json={"asking_ip": a1, "friends": [{"friend_ip": c1}]},
                          headers={"X-Bridge-From": URL["A"], "X-Bridge-Friend-Token": secret})
    check("... and its secret is no token", response.status_code == 403, response.text[:150])
    meta, content = receive("A", ta1, ["friend"], wait=0)
    check("nothing faked arrived", meta is None, meta)
    status, data = post("B", "/message/send", {"session_token": tb1, "recipient_ip": a1, "content": "x", "mode": "fast",
                                               "content_type": "friend"})
    check("a client cannot send content_type friend over /message/send", status == 403, data)

    print("Code + manual accept")
    status, code = post("A", "/friends/invite", {"session_token": ta2, "accept": "manual", "label": "a2"})
    check("code invitation: 8 characters, expires, used once", status == 200 and len(code["code"]) == 8 and code["expires_at"]
          and code["max_uses"] == 1 and not code["has_password"], code)
    typed = code["code"][:4].lower() + "-" + code["code"][4:].lower()
    status, pending = post("C", "/friends/add", {"session_token": tc2, "address": f"{typed}@{URL['A'].replace('http://', 'http://')}"})
    check("code typed with '-' and small letters -> request waits (manual)", status == 200 and pending["state"] == "pending_out", pending)
    meta, content = instruction("A", ta2, "friend_request")
    check("the door owner got friend_request", content is not None and content["friend_ip"] == c2, content)
    status, data = post("C", "/friends/send", {"session_token": tc2, "friend_ip": a2, "content": "zu früh", "mode": "fast"})
    check("no messages before the answer", status == 404, data)
    status, data = post("A", "/friends/requests", {"session_token": ta2})
    check("/friends/requests shows the open request", [f["friend_ip"] for f in data["incoming"]] == [c2], data)
    status, data = post("A", "/friends/answer", {"session_token": ta2, "friend_ip": c2, "accept": True})
    meta, content = instruction("C", tc2, "friend_added")
    check("accepted -> active on both sides (+ instruction)", status == 200 and data["state"] == "active" and content is not None
          and friends_of("C", tc2).get(a2, {}).get("state") == "active", (data, content))
    status, data = post("C", "/friends/add", {"session_token": tc1, "address": f"{code['code']}@{URL['A']}"})
    check("the code was used once - now it is gone", status == 403, data)
    status, code2 = post("A", "/friends/invite", {"session_token": ta2, "accept": "manual"})
    status, data = post("B", "/friends/add", {"session_token": tb1, "address": f"{code2['code']}@{URL['A']}"})
    post("A", "/friends/answer", {"session_token": ta2, "friend_ip": b1, "accept": False})
    meta, content = instruction("B", tb1, "friend_declined")
    check("declined -> gone on both sides (+ instruction)", content is not None and b1 not in friends_of("A", ta2)
          and a2 not in friends_of("B", tb1), content)

    print("Trusted servers and the own server")
    post("B", "/friends/invite", {"session_token": tb1, "name": "b-one", "password": "passwort-b"})
    status, data = post("A", "/friends/add", {"session_token": ta1, "address": f"b-one@{URL['B']}", "password": "passwort-b"})
    check("A <-> B (trusted): via trusted", status == 200 and data["via"] == "trusted" and data["state"] == "active", data)
    status, code3 = post("A", "/friends/invite", {"session_token": ta2, "password": "lokal-123"})
    status, data = post("A", "/friends/add", {"session_token": ta1, "address": code3["code"], "password": "lokal-123"})
    check("same server (code without @): via local", status == 200 and data["via"] == "local", data)
    drain("A", ta2)
    drain("B", tb1)
    drain("C", tc1)
    status, data = post("A", "/friends/broadcast", {"session_token": ta1, "content": "an alle Freunde", "mode": "fast"})
    got = [receive(server, token, ["friend"])[1] for server, token in (("A", ta2), ("B", tb1), ("C", tc1))]
    check("broadcast to all friends (local, trusted, neutral)", status == 200 and data["sent"] == 3 and got == ["an alle Freunde"] * 3,
          (data, got))

    print("Guessing a password")
    post("A", "/friends/invite", {"session_token": ta2, "name": "rate-test", "password": "geheim-123"})
    answers = [post("C", "/friends/add", {"session_token": tc2, "address": f"rate-test@{URL['A']}", "password": f"falsch-{i}"})[0]
               for i in range(5)]
    status, data = post("C", "/friends/add", {"session_token": tc2, "address": f"rate-test@{URL['A']}", "password": "geheim-123"})
    check("after 5 wrong passwords even the right one is refused (429)", answers == [403] * 5 and status == 429, (answers, status))
    status, data = post("C", "/friends/add", {"session_token": tc1, "address": f"rate-test@{URL['A']}", "password": "geheim-123"})
    check("... only for that client - another one still gets in", status == 200, data)

    print("Status")
    post("C", "/friends/presence", {"session_token": tc1, "presence": "available"})
    friend = friends_of("A", ta1)[c1]
    check("school client: online active, speed fast", friend["status"]["online"] == "active" and friend["status"]["speed"] == "fast",
          friend["status"])
    post("C", "/friends/presence", {"session_token": tc1, "presence": "busy", "status_text": "in Mathe"})
    friend = friends_of("A", ta1)[c1]
    check("presence busy + status text", friend["status"]["presence"] == "busy" and friend["status"]["status_text"] == "in Mathe",
          friend["status"])
    time.sleep(2.5)
    friend = friends_of("A", ta1)[c1]
    check("without requests -> idle (test: after 2 s)", friend["status"]["online"] == "idle", friend["status"])
    post("C", "/friends/presence", {"session_token": tc1, "presence": "invisible"})
    friend = friends_of("A", ta1)[c1]
    check("invisible -> friends see offline, no last seen", friend["status"]["online"] == "offline"
          and friend["status"]["last_seen_s"] is None, friend["status"])
    post("C", "/friends/presence", {"session_token": tc1, "presence": "available", "status_text": ""})
    faults({URL["A"]: {"delay": 0.7}})
    friend = friends_of("C", tc1)[a1]
    check("slow line C -> A -> speed slow with the reason", friend["status"]["speed"] == "slow"
          and any("line" in reason for reason in friend["status"]["reasons"]), friend["status"])
    faults({})
    drain("C", tc1, ["friend"])
    for i in range(22):
        post("A", "/friends/send", {"session_token": ta1, "friend_ip": c1, "content": i, "mode": "fast"})
    friend = friends_of("A", ta1)[c1]
    check("22 of my messages wait there -> slow", friend["status"]["speed"] == "slow" and friend["status"]["waiting_from_you"] == 22,
          friend["status"])
    drain("C", tc1, ["friend"])
    status, data = post("A", "/friends/info", {"session_token": ta1, "friend_ip": c1})
    check("/friends/info: one friend with fresh status", status == 200 and data["friend_ip"] == c1 and "status" in data, data)

    print("Block list and friends_mode")
    status, data = post("A", "/admin/blocked/add", {"password": PASSWORD["A"], "url": URL["B"]})
    check("a trusted server cannot be blocked", status == 400, data)
    status, data = post("A", "/admin/blocked/add", {"password": PASSWORD["A"], "url": URL["C"]})
    check("A blocks C", status == 200 and URL["C"] in data["blocked_servers"], data)
    status, data = post("A", "/friends/send", {"session_token": ta1, "friend_ip": c1, "content": "x", "mode": "fast"})
    check("blocked: A -> C refused", status == 403 and detail(data).get("error") == "FRIEND_SERVER_NOT_ALLOWED", data)
    status, data = post("C", "/friends/send", {"session_token": tc1, "friend_ip": a1, "content": "x", "mode": "fast"})
    check("blocked: C -> A refused by A", status >= 400, data)
    check("the friend shows via blocked", friends_of("A", ta1)[c1]["via"] == "blocked")
    post("A", "/admin/blocked/remove", {"password": PASSWORD["A"], "url": URL["C"]})
    status, data = post("C", "/friends/send", {"session_token": tc1, "friend_ip": a1, "content": "wieder da", "mode": "fast"})
    meta, content = receive("A", ta1, ["friend"])
    check("unblocked: works again (new friend connection)", status == 200 and content == "wieder da", (data, content))
    post("A", "/admin/settings", {"password": PASSWORD["A"], "friends_mode": "trusted"})
    status, data = post("C", "/friends/send", {"session_token": tc1, "friend_ip": a1, "content": "x", "mode": "fast"})
    status_b, data_b = post("B", "/friends/send", {"session_token": tb1, "friend_ip": a1, "content": "von B", "mode": "fast"})
    meta, content = receive("A", ta1, ["friend"])
    check("friends_mode trusted: neutral C refused, trusted B fine", status >= 400 and status_b == 200 and content == "von B",
          (data, data_b, content))
    post("A", "/admin/settings", {"password": PASSWORD["A"], "friends_mode": "open"})

    print("Removing")
    drain("A", ta1)
    status, data = post("C", "/friends/remove", {"session_token": tc2, "friend_ip": a2})
    meta, content = instruction("A", ta2, "friend_removed")
    check("removed on both sides (+ instruction)", status == 200 and content is not None and c2 not in friends_of("A", ta2), content)
    status, data = post("C", "/friends/send", {"session_token": tc2, "friend_ip": a2, "content": "x", "mode": "fast"})
    check("no messages after removing", status == 404, data)

    print("Restart of A with backup (at B)")
    drain("A", ta1)
    time.sleep(2.5)
    stop("A")
    check("A is back", start("A"))
    friends = friends_of("A", ta1)
    check("friendships survived (neutral C and trusted B)", friends.get(c1, {}).get("state") == "active"
          and friends.get(b1, {}).get("state") == "active", list(friends))
    status, data = post("C", "/friends/send", {"session_token": tc1, "friend_ip": a1, "content": "nach Neustart", "mode": "fast"})
    meta, content = receive("A", ta1, ["friend"])
    check("C talks to A again (C's old friend connection is renewed by itself)", status == 200 and content == "nach Neustart",
          (data, content))
    status, data = post("C", "/friends/add", {"session_token": tc2, "address": home, "password": "sonnenblume"})
    check("the name door survived too (password still works)", status == 200 and data["state"] == "active", data)


if __name__ == "__main__":
    main()
