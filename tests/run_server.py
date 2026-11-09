import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge
from bridge.core import protocol

# Helper for the e2e tests: python tests/run_server.py <port> <password> [trusted_url ...]
port = int(sys.argv[1])
password = sys.argv[2]
protocol.debug = False
# Optional limits for tests, e.g. BRIDGE_TEST_OVERRIDES='{"max_registrations_per_host": 6}'
for name, value in json.loads(os.getenv("BRIDGE_TEST_OVERRIDES", "{}")).items():
    setattr(protocol, name, value)
# BRIDGE_TEST_PUBLIC_URL: public URL with a path, behind the path proxy of e2e_paths.py
app = bridge.Bridge("127.0.0.1", port, password, os.getenv("BRIDGE_TEST_PUBLIC_URL") or f"http://127.0.0.1:{port}")
for url in sys.argv[3:]:
    app.add_trusted_server(password, url)


def _stop_when_stdin_closes():
    # Normal stop that also works on Windows (there is no Ctrl+C for other processes):
    # the test closes our stdin, the server stops like with Ctrl+C and sends its last backup.
    try:
        while sys.stdin.readline():
            pass
    except Exception:
        pass
    app.stop_server()
    # Safety net: if the normal stop hangs, end the process anyway
    safety_net = threading.Timer(20, lambda: os._exit(0))
    safety_net.daemon = True
    safety_net.start()


def _inject_link_faults(path):
    # Test only: makes lines to other servers broken or slow. The JSON file is read again on every request:
    # {"http://127.0.0.1:8203": {"fail": true}}  or  {"http://127.0.0.1:8203": {"delay": 0.5}}
    import asyncio
    import httpx
    from bridge.server import s2s_client
    original_post = s2s_client._post

    async def faulty_post(peer_url, *args, **kwargs):
        try:
            with open(path, encoding="utf-8") as file:
                fault = json.load(file).get(peer_url) or {}
        except (OSError, ValueError):
            fault = {}
        if fault.get("delay"):
            await asyncio.sleep(fault["delay"])
        if fault.get("fail"):
            raise httpx.ConnectError("line broken (test)")
        return await original_post(peer_url, *args, **kwargs)

    s2s_client._post = faulty_post


if os.getenv("BRIDGE_TEST_LINK_FAULTS_FILE"):
    _inject_link_faults(os.getenv("BRIDGE_TEST_LINK_FAULTS_FILE"))

if os.getenv("BRIDGE_STDIN_CONTROL") == "1":
    threading.Thread(target=_stop_when_stdin_closes, daemon=True).start()

app.start_server()
