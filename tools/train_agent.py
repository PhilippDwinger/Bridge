"""Trains the start values (baseline.json) of the BridgeAgent.

Starts two real Bridge servers (A <-> B), lets simulated hosts and callers work for a while and saves what the
agents learned as bridge/subservices/bridge_agent/baseline.json. Every server starts from it and keeps learning
on its own.

Run from the project folder:   python tools/train_agent.py            (60 seconds)
                               python tools/train_agent.py --seconds 120
Only timings and sizes are learned - no contents. Run it on a computer similar to the real server for the best start.
"""
import argparse
import json
import math
import os
import random
import subprocess
import sys
import threading
import time

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(ROOT, "bridge", "subservices", "bridge_agent", "baseline.json")
PORTS = {"A": 8191, "B": 8192}
URL = {name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()}
PASSWORD = {"A": "train-A", "B": "train-B"}
OTHER = {"A": "B", "B": "A"}
# Host types: (median seconds of work, uses long polling)
HOST_TYPES = [(0.03, True), (0.1, True), (0.3, True), (0.8, True), (0.15, False), (0.5, False)]

stop = threading.Event()
http = threading.local()


def post(server, path, body):
    client = getattr(http, "client", None)
    if client is None:
        client = http.client = httpx.Client(timeout=40)
    try:
        response = client.post(URL[server] + path, json=body)
        return response.status_code, response.json()
    except (httpx.HTTPError, ValueError):
        return 0, {}


def register(server, name):
    data = post(server, "/client/register", {"name": name, "password": "pw-" + name})[1]
    return data["client_ip"], post(server, "/client/login", {"client_ip": data["client_ip"], "password": "pw-" + name})[1]["session_token"]


def host_loop(server, token, median, long_poll):
    while not stop.is_set():
        status, data = post(server, "/message/poll", {"session_token": token, "content_types": ["task"],
                                                     "wait_seconds": 2 if long_poll else 0})
        if not data.get("message"):
            if not long_poll:
                time.sleep(random.uniform(0.2, 1.0))
            continue
        if data["mode"] == "safe":
            meta, pending = data["message"], data["pending_id"]
            chunks = [post(server, "/message/chunk", {"session_token": token, "pending_id": pending, "chunk_index": i})[1].get("chunk", "")
                      for i in range(meta["chunk_count"])]
            import hashlib
            post(server, "/message/complete", {"session_token": token, "pending_id": pending,
                                               "sha256": hashlib.sha256("".join(chunks).encode()).hexdigest()})
        time.sleep(median * math.exp(random.gauss(0, 0.5)))
        post(server, "/command/respond", {"session_token": token, "task_id": data["message"]["message_id"],
                                          "content": {"ok": True}, "mode": "fast"})


def caller_loop(server, token, realms, recipients):
    while not stop.is_set():
        args = {"data": "x" * random.choice([10, 200, 2000, 20000])}
        if random.random() < 0.75:
            post(server, "/command/call", {"session_token": token, "command_name": "job", "realm_address": random.choice(realms),
                                           "command_args": args, "mode": random.choice(["fast", "safe"]),
                                           "strategy": random.choice(["least_busy", "random", "fastest"]),
                                           "wait_seconds": 10})
        else:
            post(server, "/message/send", {"session_token": token, "recipient_ip": random.choice(recipients),
                                           "content": args, "mode": "fast"})
        post(server, "/message/poll", {"session_token": token})  # take responses / messages that came in
        time.sleep(random.uniform(0.05, 0.4))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=60)
    seconds = parser.parse_args().seconds
    env = dict(os.environ, PYTHONUNBUFFERED="1", BRIDGE_STDIN_CONTROL="1",
               BRIDGE_TEST_OVERRIDES=json.dumps({"backup_mode": "off", "max_registrations_per_host": 1000}))
    log = open(os.path.join(ROOT, "tools", "train_agent.log"), "w")
    processes = {name: subprocess.Popen([sys.executable, "tests/run_server.py", str(port), PASSWORD[name], URL[OTHER[name]]],
                                        cwd=ROOT, stdin=subprocess.PIPE, stdout=log, stderr=log, env=env)
                 for name, port in PORTS.items()}
    try:
        for name in PORTS:
            for _ in range(300):
                try:
                    if httpx.get(URL[name] + "/server/status", timeout=1).json().get("ready"):
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.1)
        time.sleep(2)
        for name in PORTS:
            post(name, "/admin/agent", {"password": PASSWORD[name], "action": "reset"})
        realms = [httpx.get(URL[name] + "/realm/public").json()["realm_address"] for name in PORTS]
        threads, recipients = [], []
        for name in PORTS:
            for index, (median, long_poll) in enumerate(HOST_TYPES):
                ip, token = register(name, f"host-{name}-{index}")
                recipients.append(ip)
                post(name, "/realm/command/create", {"session_token": token, "realm_address": realms[0 if name == "A" else 1],
                                                     "command_name": "job"})
                threads.append(threading.Thread(target=host_loop, args=(name, token, median, long_poll), daemon=True))
        for name in PORTS:
            for index in range(4):
                ip, token = register(name, f"caller-{name}-{index}")
                threads.append(threading.Thread(target=caller_loop, args=(name, token, realms, recipients), daemon=True))
        for thread in threads:
            thread.start()
        print(f"Training for {seconds} s with {len(HOST_TYPES) * 2} hosts and 8 callers on two servers ...")
        for second in range(seconds):
            time.sleep(1)
            if second % 10 == 9:
                print(f"  {second + 1} s")
        stop.set()
        time.sleep(3)
        exports = {name: post(name, "/admin/agent", {"password": PASSWORD[name], "action": "export"})[1] for name in PORTS}
        baseline = {"format": 1, "created_at": exports["A"]["created_at"], "kinds": {},
                    "note": f"Trained by tools/train_agent.py for {seconds} s on two servers "
                            f"({len(HOST_TYPES) * 2} simulated hosts, 8 callers). Start values only - every server keeps learning."}
        for kind in exports["A"]["kinds"]:
            # Per kind the server that saw more samples
            best = max(exports.values(), key=lambda export: export["kinds"][kind]["samples"])
            baseline["kinds"][kind] = best["kinds"][kind]
        with open(BASELINE, "w", encoding="utf-8") as file:
            json.dump(baseline, file, indent=1)
        print(f"Saved {BASELINE}")
        for kind, state in baseline["kinds"].items():
            typical = math.exp(state["w"][0])
            print(f"  {kind:10} samples {state['samples']:6}  typical ~{typical:.3f} s  worst x{math.exp(state['spread']):.1f}")
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.stdin.close()
        for process in processes.values():
            try:
                process.wait(25)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    main()
