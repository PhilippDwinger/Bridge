"""End-to-end test with two real Bridge servers.

Run from the project folder:  python tests/e2e_two_servers.py
Needs: fastapi, uvicorn, argon2-cffi, httpx
"""
import hashlib
import json
import os
import subprocess
import sys
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT_A, PORT_B = 8101, 8102
A, B = f"http://127.0.0.1:{PORT_A}", f"http://127.0.0.1:{PORT_B}"
PASSWORD_A, PASSWORD_B = "admin-A", "admin-B"

results = {"ok": 0, "fail": 0}
SESSIONS = {}


def check(name, condition, info=None):
    if condition:
        results["ok"] += 1
        print(f"  OK    {name}")
    else:
        results["fail"] += 1
        print(f"  FAIL  {name}  {info if info is not None else ''}")


def post(server, path, body=None):
    response = httpx.post(server + path, json=body or {}, timeout=15)
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, None


def error_id(data):
    return (data or {}).get("detail", {}).get("error") if isinstance((data or {}).get("detail"), dict) else None


def register_and_login(server, name, password="pw-" + "x" * 8):
    status, data = post(server, "/client/register", {"name": name, "password": password})
    client_ip = data["client_ip"]
    status, data = post(server, "/client/login", {"client_ip": client_ip, "password": password})
    return client_ip, data["session_token"]


def receive(server, token):
    """Polls once and returns (mode, metadata, content). Safe messages are fetched, checked and completed."""
    status, data = post(server, "/message/poll", {"session_token": token})
    if data.get("message") is None:
        return None, None, None
    if data["mode"] == "fast":
        return "fast", data["message"], data["content"]
    pending_id, meta = data["pending_id"], data["message"]
    chunks = []
    for index in range(meta["chunk_count"]):
        status, chunk = post(server, "/message/chunk", {"session_token": token, "pending_id": pending_id, "chunk_index": index})
        chunks.append(chunk["chunk"])
    payload = "".join(chunks)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    status, done = post(server, "/message/complete", {"session_token": token, "pending_id": pending_id, "sha256": digest})
    assert status == 200, done
    return "safe", meta, json.loads(payload)


def receive_filtered(server, token, content_types):
    status, data = post(server, "/message/poll", {"session_token": token, "content_types": content_types})
    if data.get("message") is None:
        return None, None, None
    assert data["mode"] == "fast", data
    return "fast", data["message"], data["content"]


def wait_for(server):
    # Ready = the server finished looking for its backup at its trusted servers
    for _ in range(300):
        try:
            response = httpx.get(server + "/server/status", timeout=1)
            if response.status_code == 200 and response.json().get("ready"):
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    return False


def main():
    env = dict(os.environ, PYTHONUNBUFFERED="1", BRIDGE_TEST_OVERRIDES='{"backup_restore_wait_seconds": 3}')
    log_a = open(os.path.join(ROOT, "tests", "server_a.log"), "w")
    log_b = open(os.path.join(ROOT, "tests", "server_b.log"), "w")
    # A trusts B from the start, B does not trust A yet
    server_a = subprocess.Popen([sys.executable, "tests/run_server.py", str(PORT_A), PASSWORD_A, B], cwd=ROOT, stdout=log_a, stderr=log_a, env=env)
    env_b = dict(env, BRIDGE_TEST_OVERRIDES='{"max_registrations_per_host": 6, "backup_restore_wait_seconds": 3}')
    server_b = subprocess.Popen([sys.executable, "tests/run_server.py", str(PORT_B), PASSWORD_B], cwd=ROOT, stdout=log_b, stderr=log_b, env=env_b)
    try:
        assert wait_for(A) and wait_for(B), "servers did not start"
        run_scenarios()
        print("Restart of a server (everything is RAM only)")
        post(B, "/admin/trusted/add", {"password": PASSWORD_B, "url": A})
        server_a.terminate()
        server_a.wait(5)
        server_a = subprocess.Popen([sys.executable, "tests/run_server.py", str(PORT_A), PASSWORD_A, B], cwd=ROOT, stdout=log_a, stderr=log_a, env=env)
        check("A is back", wait_for(A))
        time.sleep(1.5)
        status, data = post(A, "/admin/trusted/list", {"password": PASSWORD_A})
        check("A reconnects to B by itself after restart", data["trusted_servers"][0]["status"] == "connected", data)
        a_new, t_a_new = register_and_login(A, "a-new")
        status, data = post(B, "/message/send", {"session_token": SESSIONS["b1"], "recipient_ip": a_new, "content": "welcome back", "mode": "fast"})
        check("B -> restarted A works with the new token", status == 200, data)
        check("message arrives", receive(A, t_a_new)[2] == "welcome back")
    finally:
        server_a.terminate()
        server_b.terminate()
        server_a.wait(5)
        server_b.wait(5)
    print(f"\n{results['ok']} ok, {results['fail']} failed")
    sys.exit(1 if results["fail"] else 0)


def run_scenarios():
    print("Status")
    status, data = httpx.get(A + "/server/status").status_code, httpx.get(A + "/server/status").json()
    check("A online with own URL", data["status"] == "online" and data["url"] == A)
    public_a = data["public_realm_address"]

    print("Clients")
    a1, t_a1 = register_and_login(A, "a1")
    a2, t_a2 = register_and_login(A, "a2")
    b1, t_b1 = register_and_login(B, "b1")
    SESSIONS["b1"] = t_b1
    check("IP contains home server", a1.startswith(A + "<|BRIDGE_IP_SPLIT|>") and b1.startswith(B + "<|BRIDGE_IP_SPLIT|>"))
    status, data = post(A, "/client/me", {"session_token": t_a1})
    check("/client/me", status == 200 and data["client_ip"] == a1 and data["name"] == "a1")
    status, data = post(A, "/client/me", {"session_token": "nope"})
    check("invalid session -> 401 SESSION_INVALID", status == 401 and error_id(data) == "SESSION_INVALID", data)
    status, data = post(A, "/client/login", {"client_ip": a1, "password": "wrong"})
    check("wrong password -> 401 INVALID_CREDENTIALS", status == 401 and error_id(data) == "INVALID_CREDENTIALS", data)

    print("Local messages")
    status, data = post(A, "/message/send", {"session_token": t_a1, "recipient_ip": a2, "content": {"hi": "fast"}, "mode": "fast"})
    check("send fast", status == 200, data)
    mode, meta, content = receive(A, t_a2)
    check("fast arrives in one piece as unverified direct message", mode == "fast" and content == {"hi": "fast"}
          and meta["sender_ip"] == a1 and meta["content_type"] == "direct" and meta["verified"] is False, meta)
    check("fast is gone after poll", receive(A, t_a2)[0] is None)

    big = {"text": "Grüße 🌍 " * 3000}
    status, data = post(A, "/message/send", {"session_token": t_a1, "recipient_ip": a2, "content": big, "mode": "safe"})
    check("send safe (big, multibyte)", status == 200, data)
    status, data = post(A, "/message/poll", {"session_token": t_a2})
    pending_id = data["pending_id"]
    check("safe gives pending_id and chunk_count > 1", data["mode"] == "safe" and data["message"]["chunk_count"] > 1)
    status, data = post(A, "/message/complete", {"session_token": t_a2, "pending_id": pending_id, "sha256": "0" * 64})
    check("wrong hash -> 409 HASH_MISMATCH", status == 409 and error_id(data) == "HASH_MISMATCH", data)
    status, data = post(A, "/message/cancel", {"session_token": t_a2, "pending_id": pending_id})
    check("cancel puts it back", status == 200)
    mode, meta, content = receive(A, t_a2)
    check("safe arrives complete after cancel", mode == "safe" and content == big)
    check("safe is gone after complete", receive(A, t_a2)[0] is None)

    status, data = post(A, "/message/send", {"session_token": t_a1, "recipient_ip": a2, "content": "x" * 70000, "mode": "fast"})
    check("fast > 64 KiB -> 413", status == 413 and error_id(data) == "MESSAGE_TOO_LARGE", data)
    status, data = post(A, "/message/send", {"session_token": t_a1, "recipient_ip": a2, "content": 1, "content_type": "instruction"})
    check("clients cannot send instructions -> 403", status == 403, data)
    status, data = post(A, "/message/send", {"session_token": t_a1, "recipient_ip": a2, "content": 1, "content_type": "task"})
    check("clients cannot send tasks directly -> 403", status == 403, data)
    status, data = post(A, "/message/send", {"session_token": t_a1, "recipient_ip": a2, "content": 1, "content_type": "response"})
    check("clients cannot fake responses -> 403", status == 403, data)
    status, data = post(A, "/message/send", {"session_token": t_a1, "recipient_ip": "garbage", "content": 1})
    check("invalid recipient -> 400", status == 400, data)
    status, data = post(A, "/message/send", {"session_token": t_a1, "content": 1})
    check("missing field -> 400 CLIENT_PAYLOAD_ERROR", status == 400 and error_id(data) == "CLIENT_PAYLOAD_ERROR", data)

    print("Trust between servers")
    status, data = post(A, "/message/send", {"session_token": t_a1, "recipient_ip": b1, "content": "hello B"})
    check("B does not trust A yet -> 403 SERVER_NOT_TRUSTED", status == 403 and error_id(data) == "SERVER_NOT_TRUSTED", data)
    status, data = post(B, "/admin/trusted/add", {"password": "wrong", "url": A})
    check("admin with wrong password -> 403", status == 403)
    status, data = post(B, "/admin/trusted/add", {"password": PASSWORD_B, "url": A + "/"})
    check("B adds A (URL gets normalized)", status == 200 and data["added"] == A, data)
    time.sleep(1.0)
    status, data = post(A, "/admin/trusted/list", {"password": PASSWORD_A})
    check("A sees B as connected", data["trusted_servers"][0]["status"] == "connected", data)
    status, data = post(B, "/admin/trusted/list", {"password": PASSWORD_B})
    check("B sees A as connected", data["trusted_servers"][0]["status"] == "connected", data)
    status, data = post(B, "/s2s/ping", {})
    check("s2s without token -> 403", status == 403)
    fake = httpx.post(B + "/s2s/message", json={"message": {}}, headers={"X-Bridge-From": A, "X-Bridge-Token": "fake"})
    check("s2s with fake token -> 403", fake.status_code == 403)
    status, data = post(B, "/s2s/handshake/deliver", {"from_url": A, "secret": "a" * 64})
    check("fake handshake deliver is rejected", not (data or {}).get("ok"), data)
    status, data = post(A, "/admin/trusted/list", {"password": PASSWORD_A})
    check("... and the real connection still works", data["trusted_servers"][0]["status"] == "connected")

    print("Messages between servers")
    status, data = post(A, "/message/send", {"session_token": t_a1, "recipient_ip": b1, "content": {"q": "ping"}, "mode": "safe"})
    check("a1 -> b1 (A -> B)", status == 200, data)
    first_id = data["message_id"]
    mode, meta, content = receive(B, t_b1)
    check("b1 receives it safe and complete", mode == "safe" and content == {"q": "ping"} and meta["sender_ip"] == a1)
    status, data = post(B, "/message/send", {"session_token": t_b1, "recipient_ip": a1, "content": {"a": "pong"},
                                             "causation_id": first_id, "conversation_id": meta["conversation_id"], "mode": "fast"})
    check("b1 answers a1 directly (B -> A)", status == 200, data)
    mode, meta, content = receive(A, t_a1)
    check("a1 gets the direct answer", mode == "fast" and content == {"a": "pong"} and meta["causation_id"] == first_id and meta["content_type"] == "direct")
    status, data = post(A, "/message/send", {"session_token": t_a1, "recipient_ip": B + "<|BRIDGE_IP_SPLIT|>doesnotexist", "content": 1})
    check("unknown remote recipient -> 404", status == 404 and error_id(data) == "RECIPIENT_NOT_FOUND", data)

    print("Private realm on A, used across servers")
    status, data = post(A, "/realm/create", {"session_token": t_a1, "realm_type": "private", "realm_name": "Workers"})
    private = data["realm_address"]
    check("a1 creates private realm", status == 200 and private.startswith(A))
    post(A, "/realm/role/create", {"session_token": t_a1, "realm_address": private, "role_name": "worker", "can_host_commands": True})
    post(A, "/realm/role/create", {"session_token": t_a1, "realm_address": private, "role_name": "caller"})
    status, data = post(A, "/realm/key/create", {"session_token": t_a1, "realm_address": private, "roles": ["worker"]})
    worker_key = data["access_key"]
    status, data = post(A, "/realm/key/create", {"session_token": t_a1, "realm_address": private, "roles": ["caller"]})
    caller_key = data["access_key"]
    status, data = post(A, "/realm/role/create", {"session_token": t_a2, "realm_address": private, "role_name": "hack"})
    check("non-owner cannot create roles", status == 403)
    status, data = post(B, "/realm/join", {"session_token": t_b1, "realm_address": private, "access_key": worker_key})
    check("b1 joins A's realm through B", status == 200, data)
    status, data = post(B, "/realm/command/create", {"session_token": t_b1, "realm_address": private, "command_name": "add", "allowed_roles": ["caller"]})
    check("b1 hosts 'add' (only for role caller)", status == 200, data)
    status, data = post(A, "/realm/join", {"session_token": t_a2, "realm_address": private, "access_key": "wrong"})
    check("wrong access key -> 403", status == 403)
    post(A, "/realm/join", {"session_token": t_a2, "realm_address": private, "access_key": caller_key})
    status, data = post(A, "/command/call", {"session_token": t_a2, "command_name": "add", "command_args": {"1": 2, "2": 3, "n": "x"}})
    check("a2 calls 'add' -> routed to b1", status == 200 and data["host_ip"] == b1, data)
    task_id = data.get("message_id")
    mode, meta, content = receive(B, t_b1)
    check("b1 gets the task (Lua table normalized)", content == {"command_name": "add", "command_args": [2, 3], "realm_address": private}, content)
    check("task is verified", meta["content_type"] == "task" and meta["verified"] is True and meta["message_id"] == task_id)
    status, data = post(A, "/command/respond", {"session_token": t_a1, "task_id": task_id, "content": 666})
    check("someone else cannot answer the task -> 404 TASK_NOT_FOUND", status == 404 and error_id(data) == "TASK_NOT_FOUND", data)
    status, data = post(B, "/command/respond", {"session_token": t_b1, "task_id": task_id, "content": 5})
    check("host answers with /command/respond (B -> A)", status == 200, data)
    status, data = post(B, "/command/respond", {"session_token": t_b1, "task_id": task_id, "content": 6})
    check("a task can only be answered once", status == 404, data)
    mode, meta, content = receive(A, t_a2)
    check("a2 gets the verified result", content == 5 and meta["causation_id"] == task_id and meta["content_type"] == "response" and meta["verified"] is True, meta)
    status, data = post(A, "/command/call", {"session_token": t_a1, "command_name": "add", "command_args": [1, 1]})
    check("owner may call everything", status == 200, data)
    receive(B, t_b1)
    status, data = post(A, "/realm/info", {"session_token": t_a1, "realm_address": private})
    check("owner info shows members and roles", status == 200 and b1 in data["members"] and "worker" in data["roles"], data)
    status, data = post(A, "/realm/kick", {"session_token": t_a1, "realm_address": private, "member_ip": b1})
    check("owner kicks b1", status == 200)
    status, data = post(A, "/command/call", {"session_token": t_a2, "command_name": "add"})
    check("command gone after kick -> 404", status == 404 and error_id(data) == "COMMAND_NOT_FOUND", data)

    print("Protected realm on B, used from A")
    status, data = post(B, "/realm/create", {"session_token": t_b1, "realm_type": "protected", "realm_name": "B-Zone", "access_key": "secret-key", "restricted_to_owner": True})
    protected = data["realm_address"]
    check("b1 creates protected realm", status == 200)
    status, data = post(A, "/realm/join", {"session_token": t_a1, "realm_address": protected, "access_key": "secret-key"})
    check("a1 joins B's protected realm", status == 200, data)
    status, data = post(A, "/realm/command/create", {"session_token": t_a1, "realm_address": protected, "command_name": "echo"})
    check("restricted_to_owner: a1 may not host -> 403", status == 403, data)
    post(B, "/realm/command/create", {"session_token": t_b1, "realm_address": protected, "command_name": "echo"})
    status, data = post(B, "/realm/code/create", {"session_token": t_b1, "realm_address": protected, "expires_in_minutes": 5})
    code = data["code"]
    check("invitation code has 8 easy characters", len(code) == 8 and all(c in "ABCDEFGHJKMNPQRSTUVWXYZ23456789" for c in code), code)
    status, data = post(A, "/realm/join", {"session_token": t_a2, "code": code.lower()[:4] + "-" + code.lower()[4:], "server_url": B})
    check("a2 joins with only the code (+ server), lowercase and dash work", status == 200 and data["realm_address"] == protected, data)
    status, data = post(A, "/command/call", {"session_token": t_a2, "command_name": "echo", "realm_address": protected, "command_args": "hey", "mode": "fast"})
    check("a2 calls echo on B", status == 200 and data["host_ip"] == b1, data)
    mode, meta, content = receive(B, t_b1)
    check("b1 gets echo task", mode == "fast" and content["command_args"] == "hey")
    status, data = post(A, "/realm/leave", {"session_token": t_a2, "realm_address": protected})
    check("a2 leaves", status == 200)
    status, data = post(A, "/command/call", {"session_token": t_a2, "command_name": "echo", "realm_address": protected})
    check("after leaving no access -> 403", status == 403, data)

    print("Public realm + load balancing")
    post(A, "/realm/command/create", {"session_token": t_a2, "realm_address": public_a, "command_name": "work"})
    for _ in range(3):
        post(A, "/command/call", {"session_token": t_a1, "command_name": "work", "mode": "fast"})
    post(B, "/realm/join", {"session_token": t_b1, "realm_address": public_a})
    post(B, "/realm/command/create", {"session_token": t_b1, "realm_address": public_a, "command_name": "work"})
    status, data = post(A, "/command/call", {"session_token": t_a1, "command_name": "work"})
    check("least busy host is chosen (b1, a2 has 3 open tasks)", status == 200 and data["host_ip"] == b1, data)
    post(A, "/message/send", {"session_token": t_a1, "recipient_ip": a2, "content": "hi", "mode": "fast"})
    mode, meta, content = receive_filtered(A, t_a2, ["direct"])
    check("poll only direct messages, tasks wait", content == "hi" and meta["content_type"] == "direct", meta)
    for _ in range(3):
        mode, meta, content = receive(A, t_a2)
    check("then the tasks come", meta["content_type"] == "task")
    receive(B, t_b1)

    print("Invitation codes")
    status, data = post(A, "/realm/create", {"session_token": t_a1, "realm_type": "protected", "realm_name": "Club"})
    club = data["realm_address"]
    status, data = post(A, "/realm/code/create", {"session_token": t_a1, "realm_address": club, "max_uses": 1, "preferred_code": "club2026"})
    check("own code (normalized to upper case)", status == 200 and data["code"] == "CLUB2026", data)
    status, data = post(A, "/realm/code/create", {"session_token": t_a1, "realm_address": club, "preferred_code": "CLUB2026"})
    check("same code twice -> 409", status == 409, data)
    status, data = post(A, "/realm/join", {"session_token": t_a2, "code": "CLUB2026"})
    check("join own server's realm with code only", status == 200 and data["realm_address"] == club, data)
    status, data = post(B, "/realm/join", {"session_token": t_b1, "code": "CLUB2026", "server_url": A})
    check("max_uses=1: second use is rejected", status == 403, data)
    a3, t_a3 = register_and_login(A, "a3")
    for _ in range(5):
        post(A, "/realm/join", {"session_token": t_a3, "code": "WRONG123"})
    status, data = post(A, "/realm/code/create", {"session_token": t_a1, "realm_address": club})
    status, data = post(A, "/realm/join", {"session_token": t_a3, "code": data["code"]})
    check("5 wrong codes -> locked even for a valid code (429)", status == 429, data)

    print("Untrust")
    status, data = post(B, "/admin/trusted/remove", {"password": PASSWORD_B, "url": A})
    check("B removes A", status == 200)
    status, data = post(A, "/message/send", {"session_token": t_a1, "recipient_ip": b1, "content": "still there?"})
    check("A can no longer send to B -> 403", status == 403 and error_id(data) == "SERVER_NOT_TRUSTED", data)
    status, data = post(B, "/admin/status", {"password": PASSWORD_B})
    check("admin status", status == 200 and data["clients"] == 1, data)

    print("Registration limit")
    codes = [post(B, "/client/register", {"name": f"x{i}", "password": "pw"})[0] for i in range(6)]
    check("B allows 6 registrations per host (test setting), then 429", codes == [200] * 5 + [429], codes)

    print("Brute force protection")
    for _ in range(5):
        post(A, "/admin/status", {"password": "wrong"})
    status, data = post(A, "/admin/status", {"password": PASSWORD_A})
    check("admin locked after 5 wrong passwords -> 429", status == 429, data)


if __name__ == "__main__":
    main()
