"""Runs the live test of the Python extension against real Bridge servers started here.

    python extensions/python/run_tests.py

Starts a Bridge server on port 8501, plus one behind the path proxy (proxy on 8502, server on 8503 with the public
URL http://127.0.0.1:8502/alpha - like several servers on one Tailscale Funnel port). Needs the packages of the
Bridge server (fastapi, uvicorn, httpx, argon2-cffi, cryptography); the extension itself needs none.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # the Bridge folder
PORT, PROXY_PORT, PATH_PORT = 8501, 8502, 8503
PASSWORD = "admin-python-test"
TEST_TIMEOUT = 420
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def wait_ready(url, seconds=40):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with _opener.open(url + "/server/status", timeout=1) as response:
                if json.load(response).get("ready"):
                    return True
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    return False


def start(args, log, **env):
    environment = dict(os.environ, PYTHONUNBUFFERED="1", **env)
    return subprocess.Popen([sys.executable] + args, cwd=ROOT, stdin=subprocess.PIPE, stdout=log,
                            stderr=subprocess.STDOUT, env=environment)


def start_bridge(port, log, public_url=None):
    env = {
        "BRIDGE_STDIN_CONTROL": "1",  # stops normally when stdin closes (also on Windows)
        "BRIDGE_TEST_OVERRIDES": json.dumps({"backup_restore_wait_seconds": 0, "max_registrations_per_host": 500}),
    }
    if public_url:
        env["BRIDGE_TEST_PUBLIC_URL"] = public_url
    return start(["tests/run_server.py", str(port), PASSWORD], log, **env)


def stop(process, timeout=25):
    if process.poll() is not None:
        return
    try:
        process.stdin.close()
    except OSError:
        pass
    try:
        process.wait(timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(5)


def main():
    url = f"http://127.0.0.1:{PORT}"
    path_url = f"http://127.0.0.1:{PROXY_PORT}/alpha"
    log_path = os.path.join(tempfile.gettempdir(), "bridge_python_test.log")
    log = open(log_path, "w")
    processes = []
    try:
        print("== start Bridge servers", flush=True)
        processes.append(start_bridge(PORT, log))
        processes.append(start_bridge(PATH_PORT, log, public_url=path_url))
        proxy = start(["tests/path_proxy.py", str(PROXY_PORT), "strip", f"/alpha={PATH_PORT}"], log)
        processes.append(proxy)
        if not wait_ready(url) or not wait_ready(path_url):
            print(f"Bridge server did not start (log: {log_path})")
            return 1
        try:
            result = subprocess.run([sys.executable, "-u", os.path.join(HERE, "tests", "live_test.py"), url, PASSWORD,
                                     path_url], timeout=TEST_TIMEOUT).returncode
        except subprocess.TimeoutExpired:
            print(f"\nlive test did not finish within {TEST_TIMEOUT} s")
            result = 1
    finally:
        # Bridge servers first (they answer waiting long polls at once), then the proxy (holds nothing worth keeping)
        for process in processes[:2]:
            stop(process)
        for process in processes[2:]:
            process.kill()
            process.wait(5)
        log.close()
    print("\nALL OK" if result == 0 else f"\nFAILURES (server log: {log_path})")
    return result


if __name__ == "__main__":
    sys.exit(main())
