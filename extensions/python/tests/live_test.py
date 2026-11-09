"""Live test of the Python extension against REAL Bridge servers (started by run_tests.py).

    python tests/live_test.py <bridge url> <admin password> <bridge url with a path, behind the path proxy>
"""
import hashlib
import json
import os
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bridge_client import (ADDRESS_SPLIT, BridgeClient, BridgeError, State, normalize_server,  # noqa: E402
                           sha256)

results = {"ok": 0, "fail": 0}
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never through an HTTP proxy


def check(name, condition, info=""):
    if condition:
        results["ok"] += 1
        print(f"  OK    {name}", flush=True)
    else:
        results["fail"] += 1
        print(f"  FAIL  {name}  {info}", flush=True)


def wait_for(condition, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.03)
    return condition()


def post(url, path, body):
    request = urllib.request.Request(url + path, data=json.dumps(body).encode("utf-8"),
                                     headers={"Content-Type": "application/json"}, method="POST")
    try:
        with _opener.open(request, timeout=20) as response:
            status, text = response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        status, text = error.code, error.read().decode("utf-8")
    try:
        answer = json.loads(text)
    except ValueError:
        answer = {}
    if not isinstance(answer, dict):
        answer = {"value": answer}
    answer["_status"] = status
    return answer


def catch(action):
    try:
        action()
        return None
    except BridgeError as error:
        return error


def raises(action, kind):
    try:
        action()
        return False
    except kind:
        return True


def increasing(values):
    return all(values[index] > values[index - 1] for index in range(1, len(values)))


def quiet(message):
    pass


def unit_checks():
    print("== offline", flush=True)
    check("normalize_server: https, /admin cut, :443 dropped",
          normalize_server(" Muttchen.ts.net:443/admin/ ") == "https://muttchen.ts.net",
          normalize_server(" Muttchen.ts.net:443/admin/ "))
    check("normalize_server: keeps a server id path, cuts /admin and /site",
          normalize_server("https://pc.ts.net:10000/momentum/admin") == "https://pc.ts.net:10000/momentum"
          and normalize_server("https://pc.ts.net/momentum/site/") == "https://pc.ts.net/momentum",
          normalize_server("https://pc.ts.net/momentum/site/"))
    cases = {
        "http://Example.COM:80/Alpha/Beta/CLIENT/login?x=1#y": "http://example.com/Alpha/Beta",
        "pc.ts.net/momentum?next=/admin": "https://pc.ts.net/momentum",
        "https://x.ts.net/adminx/site": "https://x.ts.net/adminx",
        "https://x.ts.net:8443//a//b/": "https://x.ts.net:8443/a/b",
        "https://x.ts.net/Site/index.html": "https://x.ts.net",
        "http://x.ts.net:443/a": "http://x.ts.net:443/a",
        "https://x.ts.net#frag": "https://x.ts.net",
    }
    wrong = {url: normalize_server(url) for url, want in cases.items() if normalize_server(url) != want}
    check("normalize_server: :80, query / hash, case of routes, empty segments, other ports", not wrong, wrong)
    check("sha256 = SHA-256 hex of the UTF-8 bytes",
          sha256("äöü 🚀") == hashlib.sha256("äöü 🚀".encode("utf-8")).hexdigest() and BridgeClient.sha256 is not None)
    check("identity_secret shorter than 32 characters -> ValueError",
          raises(lambda: BridgeClient("http://127.0.0.1:1", identity_secret="short", auto_start=False), ValueError))


def run(url, admin, path_url):
    unit_checks()
    print("== live", flush=True)
    errors = []
    a = BridgeClient(url + "/admin", name="Py A", warn=quiet)
    b = BridgeClient(url, name="Py B", warn=quiet)
    a.on_error(lambda error: errors.append("A " + str(error)))
    b.on_error(lambda error: errors.append("B " + str(error)))
    check("two clients connect by themselves", a.wait_for_connection(10) and b.wait_for_connection(10)
          and a.server == url and a.state is State.CONNECTED, a.server)
    check("different client IPs, public realm known", a.client_ip != b.client_ip and a.public_realm is not None
          and a.client_ip.startswith(a.server_url + ADDRESS_SPLIT), a.client_ip)

    # region topics
    got_b, got_a, senders = [], [], []

    def on_sync(data, event):
        got_b.append(data)
        senders.append(event.sender_ip)
    sub_b = b.subscribe("sync", on_sync)
    a.subscribe("sync", lambda data, event: got_a.append(data))
    opened = a._http.opened
    for tick in range(1, 21):
        a.publish("sync", {"tick": tick})
    check("keep-alive: 20 publishes need at most 2 new connections", a._http.opened - opened <= 2,
          a._http.opened - opened)
    check("20 events arrive at B in order", wait_for(lambda: len(got_b) == 20, 5)
          and got_b[0]["tick"] == 1 and got_b[19]["tick"] == 20 and senders[0] == a.client_ip, len(got_b))
    time.sleep(0.4)
    check("A does not get its own events", not got_a, len(got_a))
    before = b.request_count
    got_b.clear()
    futures = [a.publish_async("sync", {"tick": tick}) for tick in range(1, 41)]
    wait_for(lambda: len(got_b) >= 40, 8)
    check("40 events with few poll requests (batch poll)", len(got_b) == 40 and b.request_count - before <= 12,
          f"{len(got_b)} events, {b.request_count - before} requests")
    check("publish_async returns Futures with the answer", all(f.result(5).get("subscribers") == 1 for f in futures),
          [f.result(5) for f in futures[:2]])
    # endregion

    # region publish_latest + subscribe latest_only
    lazy = BridgeClient(url, name="Slow poller", poll_interval=0.7, warn=quiet)
    check("slow poller connects", lazy.wait_for_connection(10), lazy.state)
    all_values, newest = [], []
    sub_all = lazy.subscribe("pos", lambda data, event: all_values.append(data["n"]))
    sub_newest = lazy.subscribe("pos", lambda data, event: newest.append(data["n"]), latest_only=True)
    time.sleep(0.8)
    for n in range(1, 21):
        a.publish("pos", {"n": n})
    wait_for(lambda: len(all_values) >= 20, 5)
    time.sleep(0.3)
    check("subscribe: a normal handler gets all 20 events", len(all_values) == 20 and increasing(all_values),
          all_values)
    check("subscribe latest_only: only the newest of each poll (fewer, in order, ends with 20)",
          0 < len(newest) < 20 and newest[-1] == 20 and increasing(newest), newest)
    sub_all.close()
    newest.clear()
    requests_a = a.request_count
    for n in range(1, 301):
        a.publish_latest("pos", {"n": n})
    check("publish_latest: the newest value arrives", wait_for(lambda: newest and newest[-1] == 300, 5), newest)
    time.sleep(0.3)
    check("publish_latest: never an older value after a newer one", increasing(newest), newest)
    check("publish_latest: only the newest went out (far fewer requests than values)",
          a.request_count - requests_a < 100, f"{a.request_count - requests_a} requests for 300 values")
    check("publish_latest without data -> ValueError", raises(lambda: a.publish_latest("pos", None), ValueError))
    not_json = catch(lambda: a.publish_latest("pos", {"x": object()}))
    check("publish_latest with something that is not JSON -> ARGUMENT_ERROR at once",
          not_json is not None and not_json.id == "ARGUMENT_ERROR", not_json)
    sub_newest.close()
    lazy.close()
    # endregion

    # region direct messages
    inbox, replies = [], []
    b.on_message(inbox.append)
    a.on_message(replies.append)
    a.send(b.client_ip, {"hello": "welt"})
    check("direct message (auto -> fast)", wait_for(lambda: len(inbox) == 1, 5)
          and inbox[0].content["hello"] == "welt" and inbox[0].mode == "fast" and inbox[0].sender_ip == a.client_ip
          and inbox[0].verified is False, inbox)
    inbox[0].reply({"thanks": True})
    check("reply in the same conversation", wait_for(lambda: len(replies) == 1, 5)
          and replies[0].conversation_id == inbox[0].conversation_id and replies[0].content == {"thanks": True},
          replies)
    rows = [{"id": i, "name": f"Spieler {i} äöü 🚀", "pos": [i * 0.5, 3, -i]} for i in range(3000)]
    big = {"rows": rows}
    text = json.dumps(big, ensure_ascii=False, separators=(",", ":"))
    for mode in ("safe", "compressed"):
        inbox.clear()
        a.send(b.client_ip, big, mode=mode)
        arrived = wait_for(lambda: len(inbox) == 1, 20)
        check(f"{mode} message ({len(text) // 1024} KiB) arrives exactly", arrived and inbox[0].content == big
              and inbox[0].mode == mode, inbox[0].mode if inbox else "none")
    inbox.clear()
    a.send(b.client_ip, big)
    check("auto mode: big content goes as safe", wait_for(lambda: len(inbox) == 1, 20) and inbox[0].mode == "safe",
          inbox[0].mode if inbox else "none")
    inbox.clear()
    a.send(b.client_ip, {"short": "lived"}, mode="temporary")
    check("temporary message (lifetime added by itself)", wait_for(lambda: len(inbox) == 1, 5)
          and inbox[0].mode == "temporary", inbox)
    inbox.clear()
    sent = a.broadcast([b.client_ip], {"to": "all"})
    check("broadcast arrives", wait_for(lambda: len(inbox) == 1, 5) and inbox[0].content == {"to": "all"}
          and sent.get("sent") == 1, sent)
    inbox.clear()
    future = a.send_async(b.client_ip, {"async": True})
    check("send_async: Future with the answer, message arrives", "message_id" in future.result(10)
          and wait_for(lambda: len(inbox) == 1, 5), future.result(10))
    missing = catch(lambda: a.send(a.server_url + ADDRESS_SPLIT + "nobody", 1))
    check("errors carry the Bridge ID", missing is not None and missing.id == "RECIPIENT_NOT_FOUND"
          and missing.status == 404 and missing.path == "/message/send", missing)
    broken = catch(lambda: a.send(b.client_ip, {"x": {1, 2}}))
    check("content that is not JSON -> ARGUMENT_ERROR (nothing sent)", broken is not None
          and broken.id == "ARGUMENT_ERROR" and broken.status == 0, broken)
    b.set_direct_policy("nobody")
    rejected = catch(lambda: a.send(b.client_ip, {"blocked": True}))
    b.set_direct_policy("everyone")
    check("set_direct_policy nobody -> sender gets an error", rejected is not None, rejected)
    # endregion

    # region commands
    b.host_command("add", lambda args, task: args["a"] + args["b"])

    def boom(args, task):
        raise RuntimeError("kaputt")

    def slow(args, task):
        time.sleep(args["seconds"])
        return "done"

    def work(args, task):
        task.progress(50, {"step": 1})
        time.sleep(0.3)
        return "worked"
    b.host_command("boom", boom)
    b.host_command("slow", slow)
    b.host_command("work", work, description="sends progress")
    b.host_command("not_json", lambda args, task: object())
    check("call returns the host's answer", a.call("add", {"a": 2, "b": 3}) == 5)
    failed = catch(lambda: a.call("boom", {}))
    check("handler error -> COMMAND_FAILED with the text", failed is not None and failed.id == "COMMAND_FAILED"
          and "kaputt" in str(failed), failed)
    t0 = time.monotonic()
    late = a.call("slow", {"seconds": 1.2}, server_wait_seconds=0.2, timeout=10)
    check("late answer comes through the poll loop", late == "done" and time.monotonic() - t0 > 1.0, late)
    timeout = catch(lambda: a.call("slow", {"seconds": 2.5}, timeout=1))
    check("timeout -> TIMEOUT", timeout is not None and timeout.id == "TIMEOUT", timeout)
    time.sleep(2.5)
    responses = []
    a.on_response(responses.append)
    time.sleep(1.2)
    responses.clear()
    task_id = a.call_no_wait("add", {"a": 10, "b": 5})
    check("call_no_wait: answer comes as on_response", wait_for(lambda: responses, 5)
          and responses[0].task_id == task_id and responses[0].content == 15, responses)
    parallel = []
    lock = threading.Lock()

    def one_call(n):
        value = a.call("add", {"a": n, "b": 100})
        with lock:
            parallel.append(value)
    threads = [threading.Thread(target=one_call, args=(n,)) for n in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    check("10 calls at the same time all get their own answer", len(parallel) == 10 and sum(parallel) == 1045,
          parallel)
    future = a.call_async("add", {"a": 20, "b": 22})
    check("call_async: Future with the answer", future.result(10) == 42)
    progress = []
    a.on_progress(progress.append)
    worked = a.call("work", None, progress="all")
    check("progress of the host arrives as on_progress", worked == "worked" and wait_for(lambda: progress, 3)
          and progress[0].task_id is not None, progress)
    check("host answer that is not JSON -> caller gets COMMAND_FAILED (no hanging call)",
          getattr(catch(lambda: a.call("not_json", None, timeout=5)), "id", None) == "COMMAND_FAILED")
    commands = a.get_commands()
    check("get_commands shows B's commands", "add" in commands and "work" in commands, commands)
    tasks = []

    def manual(task):
        tasks.append(task)
        task.respond({"manual": task.args["x"] * 2})
    b.on_task(manual)
    b.raw("/realm/command/create", {"command_name": "manual", "realm_address": b.public_realm})
    check("command without handler -> on_task, task.respond", a.call("manual", {"x": 21}) == {"manual": 42}
          and tasks and tasks[0].command == "manual" and tasks[0].caller_ip == a.client_ip
          and raises(lambda: tasks[0].respond(1), BridgeError), tasks)
    b.raw("/realm/command/remove", {"command_name": "manual", "realm_address": b.public_realm})
    gone = b.host_command("gone", lambda args, task: "here")
    check("hosted command answers", a.call("gone") == "here")
    gone.close()
    removed = catch(lambda: a.call("gone", timeout=3))
    check("HostedCommand.close() removes the command", removed is not None and removed.id != "TIMEOUT", removed)
    # endregion

    # region realms
    realm = a.create_realm("protected", "Python Testrealm", access_key="geheim-1234")
    joined = b.join_realm(realm, access_key="geheim-1234")
    in_realm = []
    sub_realm = b.subscribe("realm-topic", lambda data, event: in_realm.append(event), realm=realm)
    a.publish("realm-topic", {"in": "realm"}, realm=realm)
    check("realm: create, join with access key, topic inside the realm", joined == realm
          and wait_for(lambda: in_realm, 5) and in_realm[0].realm == realm and in_realm[0].data == {"in": "realm"},
          in_realm)
    info = b.get_realm_info(realm)
    check("get_realm_info", isinstance(info, dict) and info.get("_status") is None and info, info)
    code = a.create_code(realm, max_uses=1)
    c_code = BridgeClient(url, name="Py Code", warn=quiet)
    by_code = c_code.join_realm(code=code, server_url=a.server_url)
    check("invitation code: create_code + join_realm(code=...)", isinstance(code, str) and by_code == realm,
          (code, by_code))
    c_code.close()
    sub_realm.close()
    b.leave_realm(realm)
    check("leave_realm: not joined again after a re-registration", realm not in b._realms
          and realm not in (b.get_me().get("realms") or []), b.get_me().get("realms"))
    # endregion

    # region sessions
    token_before = a._token
    a._token_expires_at = time.monotonic() + 60
    a.get_me()
    check("session renewed before it runs out", token_before != a._token)
    post(url, "/client/logout", {"session_token": a._token})
    check("SESSION_INVALID -> logs in again by itself", a.get_me().get("client_ip") == a.client_ip)
    # endregion

    # region identities
    secret = "python-identity-secret-0123456789-abcdef"
    c = BridgeClient(url, name="Py C", identity_secret=secret, warn=quiet)
    check("identity client connects", c.wait_for_connection(10), c.state)
    ip_c = c.client_ip
    c.close()
    c2 = BridgeClient(url, name="Py C", identity_secret=secret, warn=quiet)
    check("same identity_secret -> same client IP", c2.wait_for_connection(10) and c2.client_ip == ip_c,
          c2.client_ip)
    p = BridgeClient(url, name="Py P", password="python-password-123", warn=quiet)
    p.connect(10)
    ip_p = p.client_ip
    p.close()
    p2 = BridgeClient(url, name="Py P", password="python-password-123", client_ip=ip_p, warn=quiet)
    check("password client: close() only logs out, client_ip + password logs in again",
          p2.wait_for_connection(10) and p2.client_ip == ip_p and p2.get_me().get("client_ip") == ip_p, p2.state)
    p2.close()
    p3 = BridgeClient(url, name="Py P", password="wrong-password", client_ip=ip_p, warn=quiet)
    wrong = catch(lambda: p3.connect(10))
    check("wrong password -> INVALID_CREDENTIALS, state FAILED", wrong is not None
          and wrong.id == "INVALID_CREDENTIALS" and p3.state is State.FAILED, (wrong, p3.state))
    p3.close()
    # endregion

    # region subscribe before connected + context manager
    f = BridgeClient(url, name="Py F", auto_start=False, connect_timeout=0, warn=quiet)
    got_f = []
    f.subscribe("sync", lambda data, event: got_f.append(data))
    check("subscribe before the connection does not raise", f.state in (State.IDLE, State.CONNECTING), f.state)
    f.wait_for_connection(10)
    a.publish("sync", {"tick": 555})
    check("... and gets the event once connected", wait_for(lambda: got_f, 5), got_f)
    f.close()
    with BridgeClient(url, name="Py With", warn=quiet) as w:
        w.connect(10)
        ip_w, password_w = w.client_ip, w._password
    login_w = post(url, "/client/login", {"client_ip": ip_w, "password": password_w})
    check("with BridgeClient(...) as w: closes (and deletes) the client at the end", w.state is State.CLOSED
          and login_w["_status"] == 401 and w.wait_closed(0), login_w)
    # endregion

    # region Bridge reset (restart without backup)
    old_a, old_b, old_realm = a.client_ip, b.client_ip, a.public_realm
    changed = []
    a.on_client_ip_changed(lambda now, old: changed.append(old))
    check("server reset", post(url, "/admin/reset", {"password": admin})["_status"] == 200)
    got_b.clear()
    a.publish("sync", {"tick": 1000})
    check("A registered again by itself, new IP, on_client_ip_changed", a.client_ip != old_a
          and wait_for(lambda: changed == [old_a], 3), a.client_ip)
    check("new public realm address is used", a.public_realm is not None and a.public_realm != old_realm,
          a.public_realm)
    check("B (only polling) came back by itself",
          wait_for(lambda: b.client_ip != old_b and b.state is State.CONNECTED, 15), b.state)
    wait_for(lambda: got_b, 3)
    for tick in range(1001, 1004):
        a.publish("sync", {"tick": tick})
    check("B's subscription restored", wait_for(lambda: got_b and got_b[-1]["tick"] == 1003, 8), got_b)
    check("B's commands restored", a.call("add", {"a": 1, "b": 1}) == 2)
    check("identity client: same IP after the reset", c2.get_me().get("client_ip") == ip_c and c2.client_ip == ip_c,
          c2.client_ip)
    # endregion

    # region close
    sub_b.close()
    time.sleep(0.3)
    published = a.publish("sync", {"tick": 2000})
    check("closing the last handler unsubscribes", published.get("subscribers") == 0, published)
    last_ip, last_password = a.client_ip, a._password
    bye = []

    def on_close():
        a.publish("sync", {"bye": True})
        bye.append(True)
    a.on_close(on_close)
    a.close()
    login = post(url, "/client/login", {"client_ip": last_ip, "password": last_password})
    check("close: on_close ran first, the ephemeral client is deleted", bye == [True] and login["_status"] == 401,
          login)
    destroyed = catch(lambda: a.send(b.client_ip, 1))
    check("a closed client raises DESTROYED", destroyed is not None and destroyed.id == "DESTROYED"
          and a.wait_closed(0), destroyed)
    e = BridgeClient("http://127.0.0.1:1", name="nobody", warn=quiet)
    t0 = time.monotonic()
    not_connected = catch(lambda: e.connect(2))
    check("unreachable server -> NOT_CONNECTED after the timeout", not_connected is not None
          and not_connected.id == "NOT_CONNECTED" and time.monotonic() - t0 < 4, not_connected)
    e.close()
    b.close()
    c2.close()
    # endregion

    # region server URL with a path (several servers on one host and port, behind a proxy)
    print("== server with a path behind a proxy", flush=True)
    x = BridgeClient(path_url + "/admin", name="Py Path X", warn=quiet)
    y = BridgeClient(path_url + "/site/", name="Py Path Y", warn=quiet)
    x.on_error(lambda error: errors.append("X " + str(error)))
    y.on_error(lambda error: errors.append("Y " + str(error)))
    check("path server: both connect through the proxy, the path is kept", x.wait_for_connection(15)
          and y.wait_for_connection(15) and x.server == path_url and y.server == path_url
          and x.server_url == path_url and x.client_ip.startswith(path_url + ADDRESS_SPLIT), (x.server, x.server_url))
    path_inbox, path_events = [], []
    y.on_message(path_inbox.append)
    y.subscribe("path-topic", lambda data, event: path_events.append(data))
    y.host_command("echo", lambda args, task: {"echo": args})
    x.send(y.client_ip, big, mode="compressed")
    x.publish("path-topic", {"via": "proxy"})
    check("path server: compressed message, event and command through the proxy",
          wait_for(lambda: path_inbox and path_events, 15) and path_inbox[0].content == big
          and path_events[0] == {"via": "proxy"} and x.call("echo", [1, 2]) == {"echo": [1, 2]},
          (len(path_inbox), path_events))
    z = BridgeClient(path_url, name="Py Path Z", identity_secret=secret, warn=quiet)
    check("path server: identity IP derived with the path URL", z.wait_for_connection(15)
          and z.get_me().get("client_ip") == z.client_ip and z.client_ip.startswith(path_url + ADDRESS_SPLIT),
          z.client_ip)
    for client in (x, y, z):
        client.close()
    # endregion

    allowed = ("SESSION_INVALID", "INVALID_CREDENTIALS", "DESTROYED", "CLIENT_NOT_FOUND", "cannot be sent as JSON")
    unexpected = [text for text in errors if not any(word in text for word in allowed)]
    check("no unexpected background errors", not unexpected, unexpected)


def main():
    url, admin, path_url = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        run(url, admin, path_url)
    except Exception:
        results["fail"] += 1
        print("  CRASH", flush=True)
        traceback.print_exc(file=sys.stdout)
    print()
    print(f"{results['ok']} ok, {results['fail']} failed", flush=True)
    return 1 if results["fail"] else 0


if __name__ == "__main__":
    code = main()
    sys.stdout.flush()
    os._exit(code)  # do not wait for anything still running in the background
