"""Runs the tests of the Roblox extension with Lune (https://github.com/lune-org/lune):
unit tests (SHA-256, Base64, zlib inflate) and the live test against a real Bridge server started here.

    python extensions/roblox/tests/run_tests.py [path/to/lune]
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))   # the Bridge folder
LUNE = sys.argv[1] if len(sys.argv) > 1 else "lune"
PORT = 8196
PASSWORD = "admin-roblox-test"


def wait_ready(url, seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url + "/server/status", timeout=1) as response:
                if json.load(response).get("ready"):
                    return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


def main():
    failed = False
    subprocess.run([sys.executable, os.path.join(HERE, "make_vectors.py"), os.path.join(HERE, "vectors.json")], check=True)
    print("== unit tests")
    failed |= subprocess.run([LUNE, "run", "test_compile.luau"], cwd=HERE).returncode != 0
    failed |= subprocess.run([LUNE, "run", "test_units.luau"], cwd=HERE).returncode != 0

    print("== live test against a real Bridge server")
    url = f"http://127.0.0.1:{PORT}"
    log = open(os.path.join(tempfile.gettempdir(), "bridge_roblox_test.log"), "w")
    env = dict(os.environ, PYTHONUNBUFFERED="1",
               BRIDGE_TEST_OVERRIDES=json.dumps({"backup_restore_wait_seconds": 0}))
    server = subprocess.Popen([sys.executable, "tests/run_server.py", str(PORT), PASSWORD], cwd=ROOT,
                              stdin=subprocess.PIPE, stdout=log, stderr=log, env=env)
    try:
        if not wait_ready(url):
            print("Bridge server did not start (see bridge_roblox_test.log)")
            return 1
        live_env = dict(os.environ, BRIDGE_URL=url, BRIDGE_ADMIN_PASSWORD=PASSWORD)
        failed |= subprocess.run([LUNE, "run", "test_live.luau"], cwd=HERE, env=live_env, timeout=300).returncode != 0
    finally:
        server.kill()
        server.wait()
        try:
            os.remove(os.path.join(HERE, "vectors.json"))
        except OSError:
            pass
    print("\nALL OK" if not failed else "\nFAILURES")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
