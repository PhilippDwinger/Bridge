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


def playersync(url):
    scenarios = {
        "A": {"players": [-101, -102, -103], "seconds": 17, "events": [
            {"at": 8, "action": "observe", "name": "t8"},
            {"at": 10, "action": "leave", "userId": -103},
            {"at": 16, "action": "shutdown"}]},
        "B": {"players": [201, 202], "seconds": 19.5, "events": [
            {"at": 8, "action": "observe", "name": "t8"},
            {"at": 13, "action": "observe", "name": "t13"},
            {"at": 18.5, "action": "observe", "name": "t18"}]},
    }
    runs = {label: subprocess.Popen([LUNE, "run", "sim_playersync.luau", url, label, json.dumps(scenario)], cwd=HERE,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for label, scenario in scenarios.items()}
    seen = {}
    for label, run in runs.items():
        out, _ = run.communicate(timeout=120)
        line = next((l for l in out.splitlines() if l.startswith("OBSERVATIONS ")), None)
        if line is None:
            print(out)
        seen[label] = json.loads(line[len("OBSERVATIONS "):]) if line else {"observations": {}}
        seen[label]["output"] = [l for l in out.splitlines() if not l.startswith("OBSERVATIONS ")]
    results = {"ok": 0, "fail": 0}

    def check(name, condition, info=""):
        results["ok" if condition else "fail"] += 1
        print(("  OK    " if condition else "  FAIL  ") + name + ("" if condition else f"  {info}"))

    a, b = seen["A"]["observations"], seen["B"]["observations"]
    a8 = (a.get("t8") or {}).get("servers", {})
    b8 = (b.get("t8") or {}).get("servers", {})
    check("game A shows the 2 players of game B as NPCs", len(a8.get("Server B", [])) == 2, a8)
    check("players without a Roblox avatar (negative ids, like Minecraft) get one without errors",
          not any("rror" in line or "Stack Begin" in line for line in seen["B"].get("output", [])), seen["B"].get("output"))
    check("game B shows the 3 players of game A as NPCs", len(b8.get("Server A", [])) == 3, b8)
    npcs = a8.get("Server B", []) + b8.get("Server A", [])
    check("NPCs are named 'DisplayName · Label', anchored, without scripts",
          npcs and all(n["display"].endswith((" · A", " · B")) and n["anchored"] and n["scripts"] == 0 for n in npcs), npcs)
    check("NPCs stand where the players walk (on their circle, radius 20)",
          npcs and all(abs((n["x"] ** 2 + n["z"] ** 2) ** 0.5 - 20) < 4 for n in npcs), [(n["x"], n["z"]) for n in npcs])
    b13 = (b.get("t13") or {}).get("servers", {})
    check("a player leaves game A -> its NPC is gone in game B", len(b13.get("Server A", [])) == 2
          and not any("Player-103" in n["name"] for n in b13.get("Server A", [])), b13)
    b18 = (b.get("t18") or {}).get("servers", {})
    check("game A shuts down -> 'bye', game B removes its NPCs at once (before the 6 s timeout)", "Server A" not in b18, b18)
    for label in ("A", "B"):
        rate = seen[label].get("requests", 0) / max(seen[label].get("minutes", 1), 0.01)
        check(f"game {label}: {rate:.0f} HTTP requests per minute (Roblox allows 500)", 0 < rate < 420, rate)
    print(f"\n{results['ok']} ok, {results['fail']} failed")
    return results["fail"] == 0


def main():
    failed = False
    subprocess.run([sys.executable, os.path.join(HERE, "make_vectors.py"), os.path.join(HERE, "vectors.json")], check=True)
    print("== unit tests")
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
        print("== PlayerSync: the real script as game A and game B (two processes)")
        failed |= not playersync(url)
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
