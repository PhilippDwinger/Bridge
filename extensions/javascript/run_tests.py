"""Runs the live test of the JavaScript extension against real Bridge servers started here.

    python extensions/javascript/run_tests.py      (needs Node 18+; the browser check needs Playwright with chromium)

Starts (all on 127.0.0.1):
  8511  Bridge server for the main test
  8512  tests/path_proxy.py (plays Tailscale, strips the mount path): /alpha -> 8513, /alpha/site -> 8514
  8513  Bridge server with the public URL http://127.0.0.1:8512/alpha (a server URL with a path)
  8514  a static web server for this folder - so the test page is http://127.0.0.1:8512/alpha/site/tests/site/
Then runs tests/live_test.mjs with node. Playwright is looked up through NODE_PATH (default: `npm root -g`).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))   # the Bridge folder
PORT, PROXY_PORT, PATH_PORT, SITE_PORT = 8511, 8512, 8513, 8514
PASSWORD = "admin-js-test"
PATH_PASSWORD = "admin-js-path-test"
URL = f"http://127.0.0.1:{PORT}"
PATH_URL = f"http://127.0.0.1:{PROXY_PORT}/alpha"


def wait_ready(url, seconds=40):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/server/status", timeout=1) as response:
                if json.load(response).get("ready"):
                    return True
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    return False


def wait_page(url, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


def stop(process, timeout=25):
    if process.poll() is not None:
        return
    try:
        process.stdin.close()   # Bridge servers with BRIDGE_STDIN_CONTROL=1 stop normally
    except Exception:
        pass
    try:
        process.wait(timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(5)


def node_path():
    if os.environ.get("NODE_PATH"):
        return os.environ["NODE_PATH"]
    npm = shutil.which("npm")
    if not npm:
        return ""
    try:
        return subprocess.run([npm, "root", "-g"], capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def main():
    if not shutil.which("node"):
        print("node not found (Node 18+ is needed)")
        return 1
    logs = tempfile.mkdtemp(prefix="bridge-js-")
    overrides = json.dumps({"backup_restore_wait_seconds": 0})
    base_env = dict(os.environ, PYTHONUNBUFFERED="1", BRIDGE_STDIN_CONTROL="1", BRIDGE_TEST_OVERRIDES=overrides)
    processes = []

    def start(name, args, env=None, graceful=False):
        log = open(os.path.join(logs, name + ".log"), "w")
        process = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT,
                                   env=env or base_env)
        processes.append((process, graceful))
        return process

    print("== start Bridge servers, proxy and web server")
    start("bridge_main", [sys.executable, "tests/run_server.py", str(PORT), PASSWORD], graceful=True)
    start("bridge_path", [sys.executable, "tests/run_server.py", str(PATH_PORT), PATH_PASSWORD],
          env=dict(base_env, BRIDGE_TEST_PUBLIC_URL=PATH_URL), graceful=True)
    start("proxy", [sys.executable, "tests/path_proxy.py", str(PROXY_PORT), "strip",
                    f"/alpha={PATH_PORT}", f"/alpha/site={SITE_PORT}"])
    start("site", [sys.executable, "-m", "http.server", str(SITE_PORT), "--bind", "127.0.0.1", "--directory", HERE])
    result = 1
    try:
        if not wait_ready(URL):
            print("Bridge server did not start (log: " + logs + ")")
            return 1
        if not wait_ready(PATH_URL):
            print("Bridge server behind the proxy did not start (log: " + logs + ")")
            return 1
        if not wait_page(PATH_URL + "/site/tests/site/index.html"):
            print("test page not reachable through the proxy (log: " + logs + ")")
            return 1
        print("== live test (node tests/live_test.mjs)")
        env = dict(os.environ, NODE_PATH=node_path())
        try:
            result = subprocess.run(["node", os.path.join(HERE, "tests", "live_test.mjs"), URL, PASSWORD, PATH_URL,
                                     PATH_PASSWORD], cwd=HERE, env=env, timeout=300).returncode
        except subprocess.TimeoutExpired:
            print("live test did not end within 300 s")
            result = 1
    finally:
        for process, graceful in reversed(processes):
            if graceful:
                stop(process)
            else:
                process.kill()
                process.wait(5)
        if result == 0:
            shutil.rmtree(logs, ignore_errors=True)
        else:
            print("server logs: " + logs)
    print("\nALL OK" if result == 0 else "\nFAILURES")
    return result


if __name__ == "__main__":
    sys.exit(main())
