"""End-to-end test of BridgeExpress (command signatures + /express/schema) with two real Bridge servers A <-> B

Run from the project folder:  python tests/e2e_express.py
"""
import json
import os
import subprocess
import sys
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORTS = {"A": 8161, "B": 8162}
URL = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
PASSWORD = {"A": "admin-A", "B": "admin-B"}
TRUSTS = {"A": ["B"], "B": ["A"]}
OVERRIDES = {"realm_sync_seconds": 1, "realm_stale_seconds": 3, "backup_restore_wait_seconds": 3}
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
    logs.setdefault(name, open(os.path.join(ROOT, "tests", f"express_{name}.log"), "a"))
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


def details(data):
    detail = (data or {}).get("detail") or {}
    return detail.get("error"), (detail.get("details") or {}).get("problems")


def task_of(server, token, task_id):
    """Takes tasks until the one with task_id comes."""
    for _ in range(20):
        status, data = post(server, "/message/poll", {"session_token": token, "content_types": ["task"], "wait_seconds": 3})
        if not data.get("message"):
            return None
        if data["message"]["message_id"] == task_id:
            return data["content"]
    return None


def scenarios():
    a1, ta1 = register("A", "a1")
    a2, ta2 = register("A", "a2")
    b1, tb1 = register("B", "b1")
    public_a = httpx.get(URL["A"] + "/realm/public").json()["realm_address"]
    add_signature = {"params": [{"name": "a", "type": "number", "description": "first number"},
                                {"name": "b", "type": "number"}], "returns": "number"}

    print("Hosting with a signature")
    status, data = post("A", "/realm/command/create", {"session_token": ta1, "realm_address": public_a, "command_name": "bad",
                                                      "signature": {"params": [{"name": "1x", "type": "numbr"}], "returns": "list<"}})
    error, problems = details(data)
    check("invalid signature -> 400 with readable problems", status == 400 and problems and len(problems) == 2, data)
    status, data = post("A", "/realm/command/create", {"session_token": ta1, "realm_address": public_a, "command_name": "add",
                                                      "description": "adds two numbers", "signature": add_signature})
    check("a1 hosts 'add' with a signature (validate strict by default)", status == 200, data)
    status, data = post("A", "/realm/command/create", {"session_token": ta2, "realm_address": public_a, "command_name": "add",
                                                      "signature": {"params": [{"name": "x", "type": "string"}]}})
    check("second host with another signature -> 409 SIGNATURE_MISMATCH", status == 409 and details(data)[0] == "SIGNATURE_MISMATCH", data)
    status, data = post("A", "/realm/command/create", {"session_token": ta2, "realm_address": public_a, "command_name": "add",
                                                      "signature": {"params": [{"name": "a", "type": "number", "description": "other text"},
                                                                               {"name": "b", "type": "number"}], "returns": "number"}})
    check("same signature with other descriptions is fine", status == 200, data)
    post("A", "/realm/command/remove", {"session_token": ta2, "realm_address": public_a, "command_name": "add"})
    status, data = post("A", "/realm/command/create", {"session_token": ta2, "realm_address": public_a, "command_name": "add"})
    check("a host without a signature takes the existing one", status == 200, data)
    post("A", "/realm/command/remove", {"session_token": ta2, "realm_address": public_a, "command_name": "add"})

    print("Checking calls (strict)")
    call = {"session_token": tb1, "command_name": "add", "realm_address": public_a, "mode": "fast"}
    status, data = post("B", "/command/call", dict(call, command_args={"a": "two"}))
    error, problems = details(data)
    check("wrong arguments -> 400 ARGS_INVALID, nothing is sent (also across servers)", status == 400 and error == "ARGS_INVALID", data)
    check("... the details say what is wrong", problems == ["args.a: expected number, got string", "args.b: missing"], problems)
    status, data = post("B", "/command/call", dict(call, command_args=[2, 3]))
    check("a list instead of named arguments -> 400", status == 400 and details(data)[0] == "ARGS_INVALID", data)
    status, data = post("B", "/command/call", dict(call, command_args={"a": 2, "b": 3, "c": 4}))
    check("unknown argument -> 400", status == 400 and details(data)[1] == ["args.c: unknown field"], data)
    status, data = post("B", "/command/call", dict(call, command_args={"a": 2, "b": 3}))
    check("fitting arguments -> the task goes out", status == 200, data)
    task_id = data["task_id"]
    task = task_of("A", ta1, task_id)
    check("the host gets the named arguments", task and task["command_args"] == {"a": 2, "b": 3}, task)
    status, data = post("A", "/command/respond", {"session_token": ta1, "task_id": task_id, "content": "five", "mode": "fast"})
    check("response does not fit 'returns: number' -> 400 RESPONSE_INVALID", status == 400 and details(data)[0] == "RESPONSE_INVALID", data)
    status, data = post("A", "/command/respond", {"session_token": ta1, "task_id": task_id, "content": 5, "mode": "fast"})
    check("... the task stays open, a fitting response works", status == 200, data)
    status, data = post("B", "/message/poll", {"session_token": tb1, "content_types": ["response"], "wait_seconds": 3})
    check("b1 gets 5", data.get("content") == 5, data)

    print("Modes warn and off")
    post("A", "/realm/command/create", {"session_token": ta1, "realm_address": public_a, "command_name": "greet",
                                        "signature": {"params": [{"name": "player", "type": "{name: string, level?: integer}"}],
                                                      "returns": "string", "validate": "warn"}})
    status, data = post("B", "/command/call", {"session_token": tb1, "command_name": "greet", "realm_address": public_a,
                                               "mode": "fast", "command_args": {"player": {"name": "Paddy", "level": 1.5}}})
    check("warn: wrong arguments are sent anyway", status == 200, data)
    task = task_of("A", ta1, data["task_id"])
    check("... with validation_problems for the host", task and task.get("validation_problems") == ["args.player.level: expected integer, got 1.5"], task)
    status, data = post("A", "/command/respond", {"session_token": ta1, "task_id": data["task_id"], "content": 42, "mode": "fast"})
    check("warn: the response is not checked", status == 200, data)
    post("B", "/message/poll", {"session_token": tb1, "content_types": ["response"], "wait_seconds": 3})
    post("A", "/realm/command/create", {"session_token": ta1, "realm_address": public_a, "command_name": "free",
                                        "signature": {"params": [{"name": "text", "type": "string"}], "validate": "off"}})
    status, data = post("B", "/command/call", {"session_token": tb1, "command_name": "free", "realm_address": public_a,
                                               "mode": "fast", "command_args": [1, 2, 3]})
    check("off: anything goes, the signature is only information", status == 200, data)
    task = task_of("A", ta1, data["task_id"])
    check("... no validation_problems", task and "validation_problems" not in task, task)

    print("/express/schema")
    post("B", "/realm/join", {"session_token": tb1, "realm_address": public_a})
    time.sleep(0.5)
    status, schema = post("B", "/express/schema", {"session_token": tb1})
    check("schema answers", status == 200 and schema.get("changed") is True and schema.get("notation_version") == 1, schema)
    realms = {realm["realm_address"]: realm for realm in schema.get("realms", [])}
    check("contains the public realm of A (b1 joined it) and of B", public_a in realms and len(realms) == 2, list(realms))
    commands = {command["name"]: command for command in realms.get(public_a, {}).get("commands", [])}
    check("... with add, greet and free", set(commands) == {"add", "greet", "free"}, list(commands))
    signature = (commands.get("add") or {}).get("signature") or {}
    check("add: params with types, returns and validate",
          [(p["name"], p["type"], p["optional"]) for p in signature.get("params", [])] == [("a", "number", False), ("b", "number", False)]
          and signature.get("returns") == "number" and signature.get("validate") == "strict", signature)
    player = ((commands.get("greet") or {}).get("signature") or {}).get("params", [{}])[0]
    check("types come as text and as ready tree (no parser needed in the extension)",
          player.get("type") == "{name: string, level?: integer}" and player.get("type_tree") == {"kind": "object", "fields": [
              {"name": "name", "optional": False, "type": {"kind": "string"}},
              {"name": "level", "optional": True, "type": {"kind": "integer"}}]}, player)
    check("realm on another server comes from the synced copy", realms.get(public_a, {}).get("source") == "mirror", realms.get(public_a))
    status, again = post("B", "/express/schema", {"session_token": tb1, "if_version": schema["version"]})
    check("same version -> {changed: false}, nothing else", again == {"changed": False, "version": schema["version"]}, again)
    post("A", "/realm/command/create", {"session_token": ta1, "realm_address": public_a, "command_name": "time"})
    time.sleep(0.5)
    status, newer = post("B", "/express/schema", {"session_token": tb1, "if_version": schema["version"]})
    check("new command -> new version", newer.get("changed") is True and newer.get("version") != schema["version"], newer.get("version"))
    status, only = post("B", "/express/schema", {"session_token": tb1, "realm_address": public_a})
    check("realm_address limits the schema to one realm", [realm["realm_address"] for realm in only["realms"]] == [public_a])

    print("Schema only shows what the client may call")
    status, data = post("A", "/realm/create", {"session_token": ta1, "realm_type": "private", "realm_name": "Team"})
    team = data["realm_address"]
    post("A", "/realm/role/create", {"session_token": ta1, "realm_address": team, "role_name": "admin"})
    post("A", "/realm/command/create", {"session_token": ta1, "realm_address": team, "command_name": "ban", "allowed_roles": ["admin"],
                                        "signature": {"params": [{"name": "player", "type": "string"}, {"name": "reason", "type": "string | nil"}]}})
    post("A", "/realm/command/create", {"session_token": ta1, "realm_address": team, "command_name": "ping"})
    code = post("A", "/realm/code/create", {"session_token": ta1, "realm_address": team})[1]["code"]
    post("B", "/realm/join", {"session_token": tb1, "code": code, "server_url": URL["A"]})
    time.sleep(0.5)
    status, schema = post("B", "/express/schema", {"session_token": tb1, "realm_address": team})
    names = [command["name"] for command in schema["realms"][0]["commands"]] if schema.get("realms") else None
    check("member without role sees only 'ping'", names == ["ping"], names)
    post("A", "/realm/role/set", {"session_token": ta1, "realm_address": team, "member_ip": b1, "roles": ["admin"]})
    time.sleep(0.5)
    status, schema = post("B", "/express/schema", {"session_token": tb1, "realm_address": team})
    names = [command["name"] for command in schema["realms"][0]["commands"]] if schema.get("realms") else None
    check("with the role 'ban' is there too", names == ["ban", "ping"], names)
    status, data = post("B", "/command/call", {"session_token": tb1, "command_name": "ban", "realm_address": team, "mode": "fast",
                                               "command_args": {"player": "griefer"}})
    check("optional 'string | nil' may be left out", status == 200, data)


if __name__ == "__main__":
    main()
