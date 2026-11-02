"""Compiles the Java extension and runs its live test against a real Bridge server started here.

    python extensions/java/run_tests.py            (needs a JDK 21+ with javac on PATH)
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
PORT = 8197
PASSWORD = "admin-java-test"


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
    out = tempfile.mkdtemp(prefix="bridge-java-")
    sources = [os.path.join(folder, name) for base in ("src/main/java", "src/test/java")
               for folder, _, files in os.walk(os.path.join(HERE, base)) for name in files if name.endswith(".java")]
    env = {key: value for key, value in os.environ.items() if key != "JAVA_TOOL_OPTIONS"}
    print("== compile")
    if subprocess.run(["javac", "--release", "21", "-Xlint:all", "-d", out] + sources, env=env).returncode != 0:
        return 1
    print("== live test against a real Bridge server")
    url = f"http://127.0.0.1:{PORT}"
    log = open(os.path.join(tempfile.gettempdir(), "bridge_java_test.log"), "w")
    server_env = dict(os.environ, PYTHONUNBUFFERED="1", BRIDGE_TEST_OVERRIDES=json.dumps({"backup_restore_wait_seconds": 0}))
    server = subprocess.Popen([sys.executable, "tests/run_server.py", str(PORT), PASSWORD], cwd=ROOT,
                              stdin=subprocess.PIPE, stdout=log, stderr=log, env=server_env)
    try:
        if not wait_ready(url):
            print("Bridge server did not start")
            return 1
        result = subprocess.run(["java", "-cp", out, "io.github.philippdwinger.bridge.LiveTest", url, PASSWORD],
                                env=env, timeout=300).returncode
    finally:
        server.kill()
        server.wait()
        shutil.rmtree(out, ignore_errors=True)
    print("\nALL OK" if result == 0 else "\nFAILURES")
    return result


if __name__ == "__main__":
    sys.exit(main())
