"""End-to-end test: several Bridge servers behind ONE host and port, each under its own path.

    https://pc.ts.net:10000/alpha  -> server A        https://pc.ts.net:10000/beta -> server B

That is how BridgeControll hosts many servers on the three Tailscale Funnel ports. Here a small proxy
(tests/path_proxy.py) plays Tailscale - once stripping the mount path (like Tailscale does), once keeping it - and
everything a server does must work in both: pages, admin API, client API, trust between the two servers, messages
across them, block list per server (an entry with a path) or per host (an entry without a path).

Run from the project folder:  python tests/e2e_paths.py
"""
import hashlib
import json
import os
import subprocess
import sys
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
PROXY_PORT, PORT_A, PORT_B = 8261, 8262, 8263
HOST = f"http://127.0.0.1:{PROXY_PORT}"
A, B = HOST + "/alpha", HOST + "/beta"
LOCAL = {A: f"http://127.0.0.1:{PORT_A}", B: f"http://127.0.0.1:{PORT_B}"}
PW = {A: "admin-alpha", B: "admin-beta"}
SPLIT = "<|BRIDGE_IP_SPLIT|>"

results = {"ok": 0, "fail": 0}


def check(name, condition, info=None):
    if condition:
        results["ok"] += 1
        print(f"  OK    {name}")
    else:
        results["fail"] += 1
        print(f"  FAIL  {name}  {info if info is not None else ''}")


def post(url, body=None, timeout=20):
    response = httpx.post(url, json=body or {}, timeout=timeout)
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, None


def admin(server, path, body=None):
    return post(f"{server}/admin/{path}", dict(body or {}, password=PW[server]))


def wait_ready(url, seconds=40):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            response = httpx.get(url + "/server/status", timeout=1)
            if response.status_code == 200 and response.json().get("ready"):
                return True
        except (httpx.HTTPError, ValueError):
            pass
        time.sleep(0.1)
    return False


def start(args, env, log):
    return subprocess.Popen([sys.executable] + args, cwd=ROOT, stdin=subprocess.PIPE, stdout=log,
                            stderr=subprocess.STDOUT, env=env)


def stop(process, timeout=25):
    if process.poll() is not None:
        return
    try:
        process.stdin.close()
    except Exception:
        pass
    try:
        process.wait(timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(5)


def receive(server, token):
    status, data = post(server + "/message/poll", {"session_token": token})
    if not data or data.get("message") is None:
        return None, None
    if data["mode"] == "fast":
        return data["message"], data["content"]
    pending, meta = data["pending_id"], data["message"]
    parts = [post(server + "/message/chunk", {"session_token": token, "pending_id": pending, "chunk_index": i})[1]["chunk"]
             for i in range(meta["chunk_count"])]
    payload = "".join(parts)
    post(server + "/message/complete", {"session_token": token, "pending_id": pending,
                                        "sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest()})
    return meta, json.loads(payload)


def offline_checks():
    print("== address rules ==")
    from bridge.core import address
    check("URL with server path is kept", address.normalize_url("https://PC.ts.net:10000/momentum/") == "https://pc.ts.net:10000/momentum")
    check("route after the server path is cut", address.normalize_url("https://pc.ts.net:10000/momentum/admin") == "https://pc.ts.net:10000/momentum")
    check("/site is cut like a route", address.normalize_url("https://pc.ts.net/momentum/site/x") == "https://pc.ts.net/momentum")
    check("two paths = two servers", address.server_identity("https://pc.ts.net/a") != address.server_identity("https://pc.ts.net/b"))
    check("scheme does not matter", address.server_identity("http://pc.ts.net/a") == address.server_identity("https://pc.ts.net/a"))
    check("same machine key", address.server_key("https://pc.ts.net/a") == address.server_key("https://pc.ts.net/b"))
    check("block with path hits only that server", address.block_covers("https://pc.ts.net/a", "https://pc.ts.net/a")
          and not address.block_covers("https://pc.ts.net/a", "https://pc.ts.net/b"))
    check("block without path hits the whole host", address.block_covers("https://pc.ts.net", "https://pc.ts.net/b")
          and not address.block_covers("https://pc.ts.net", "https://other.ts.net/b"))
    check("reserved segment detected", address.has_reserved_segment("https://x/client")
          and address.has_reserved_segment("https://x/site/") and not address.has_reserved_segment("https://x/momentum"))
    code = ("import bridge\ntry:\n    bridge.Bridge('127.0.0.1', 9, 'pw', 'https://x.ts.net/client')\n    print('NO')\n"
            "except ValueError as e:\n    print('REFUSED')\n")
    out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=60)
    check("a public URL with a Bridge route in its path is refused", "REFUSED" in out.stdout, out.stdout + out.stderr[-300:])


def scenario(mode):
    print(f"== proxy mode: {mode} ==")
    for server in (A, B):
        status = httpx.get(server + "/server/status", timeout=5).json()
        check(f"{server.rsplit('/', 1)[1]}: status over the shared port, own URL", status.get("url") == server, status)
    check("unknown path on the port -> 404 from the proxy", httpx.get(HOST + "/gamma/server/status").status_code == 404)

    landing = httpx.get(A + "/", timeout=5).text
    check("landing page links with the base path", 'href="/alpha/admin"' in landing and 'href="/alpha/server/status"' in landing)
    landing = httpx.get(A, timeout=5).text
    check("landing page also without trailing slash", 'href="/alpha/admin"' in landing)
    page = httpx.get(A + "/admin", timeout=5).text
    check("dashboard knows its base path", 'const BASE="/alpha";' in page and 'href="/alpha/site/"' in page)
    check("dashboard keeps the password per server", 'PW_KEY="bridge-admin-pw:"+BASE' in page)
    check("dashboard also at /admin/ (no redirect to a wrong address)",
          httpx.get(A + "/admin/", timeout=5, follow_redirects=False).status_code == 200)
    site = httpx.get(A + "/site/", timeout=5)
    check("/site/ placeholder links back with the base path", site.status_code == 404 and 'href="/alpha/admin"' in site.text)

    status, data = admin(A, "overview")
    check("admin API through the shared port", status == 200 and isinstance(data, dict), (status, data))
    status, _ = post(A + "/admin/overview", {"password": PW[B]})
    check("password of B does not open A", status in (401, 403), status)
    check("direct local call without the path works", httpx.get(LOCAL[A] + "/server/status").json().get("url") == A)
    check("direct local call with the path works", httpx.get(LOCAL[A] + "/alpha/server/status").json().get("url") == A)

    # Clients on both servers, through the shared port
    password = "pw-" + "y" * 10
    ips, tokens = {}, {}
    for server, name in ((A, f"a-{mode}"), (B, f"b-{mode}")):
        status, data = post(server + "/client/register", {"name": name, "password": password})
        ips[server] = data["client_ip"]
        status, data = post(server + "/client/login", {"client_ip": ips[server], "password": password})
        tokens[server] = data["session_token"]
    check("client IPs carry the full server URL with path",
          ips[A].startswith(A + SPLIT) and ips[B].startswith(B + SPLIT), ips)

    status, data = post(A + "/message/send", {"session_token": tokens[A], "recipient_ip": ips[B],
                                              "content": {"hi": mode}, "mode": "fast"})
    check("A -> B across servers on one port (fast)", status == 200, data)
    meta, content = receive(B, tokens[B])
    check("B receives it from A's client", content == {"hi": mode} and meta and meta.get("sender_ip") == ips[A], (meta, content))
    big = {"text": "Brücke " * 4000}
    status, data = post(B + "/message/send", {"session_token": tokens[B], "recipient_ip": ips[A], "content": big, "mode": "safe"})
    check("B -> A (safe, chunked)", status == 200, data)
    meta, content = receive(A, tokens[A])
    check("A receives the safe message complete", content == big, meta)

    # Block list: per server (with path) or per host (without path)
    gamma = HOST + "/gamma"
    status, data = admin(A, "blocked/add", {"url": gamma})
    check("block one server on the shared port", status == 200, data)
    status, data = admin(A, "trusted/list")
    check("... B (same host and port) stays connected", data["trusted_servers"][0]["status"] == "connected", data)
    status, data = post(A + "/message/send", {"session_token": tokens[A], "recipient_ip": ips[B], "content": "still", "mode": "fast"})
    check("... and messages to B still go through", status == 200 and receive(B, tokens[B])[1] == "still", data)
    status, data = admin(A, "blocked/add", {"url": HOST})
    check("whole-host block refused (it would hit trusted B and A itself)", status >= 400, (status, data))
    status, data = admin(A, "blocked/add", {"url": B})
    check("blocking trusted B itself refused", status >= 400, (status, data))
    status, data = admin(A, "blocked/remove", {"url": gamma + "/admin"})
    check("unblock with another spelling of the same server", status == 200, data)
    status, data = admin(A, "blocked/list")
    check("block list empty again", status == 200 and data.get("blocked_servers") == [], data)


def main():
    offline_checks()
    env = dict(os.environ, PYTHONUNBUFFERED="1",
               BRIDGE_TEST_OVERRIDES='{"backup_restore_wait_seconds": 2, "backup_interval_seconds": 3}')
    logs = {name: open(os.path.join(ROOT, "tests", f"paths_{name}.log"), "w") for name in ("A", "B", "proxy")}
    servers = [
        start(["tests/run_server.py", str(PORT_A), PW[A], B], dict(env, BRIDGE_TEST_PUBLIC_URL=A), logs["A"]),
        start(["tests/run_server.py", str(PORT_B), PW[B], A], dict(env, BRIDGE_TEST_PUBLIC_URL=B), logs["B"]),
    ]
    proxy = None
    try:
        for mode in ("strip", "keep"):
            proxy = start(["tests/path_proxy.py", str(PROXY_PORT), mode, f"/alpha={PORT_A}", f"/beta={PORT_B}"],
                          env, logs["proxy"])
            if not (wait_ready(A) and wait_ready(B)):
                check(f"servers ready behind the {mode} proxy", False)
                return
            if mode == "strip":
                # Both trust each other from the start (env) - they connect over the shared port
                deadline = time.time() + 30
                while time.time() < deadline:
                    lists = [admin(s, "trusted/list")[1]["trusted_servers"] for s in (A, B)]
                    if all(entry and entry[0]["status"] == "connected" for entry in lists):
                        break
                    for s in (A, B):
                        admin(s, "trusted/connect", {"url": B if s == A else A})
                    time.sleep(1)
                check("A and B trust each other over one host and port", all(
                    entry and entry[0]["status"] == "connected" for entry in lists), lists)
            scenario(mode)
            proxy.terminate()
            proxy.wait(10)
            proxy = None
    finally:
        if proxy is not None:
            proxy.terminate()
        for process in servers:
            stop(process)
        for handle in logs.values():
            handle.close()
    print(f"\n{results['ok']} ok, {results['fail']} failed")


if __name__ == "__main__":
    try:
        main()
    finally:
        sys.exit(1 if results["fail"] else 0)
