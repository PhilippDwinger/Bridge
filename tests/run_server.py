import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bridge
from bridge.core import protocol

# Helper for e2e_two_servers.py: python tests/run_server.py <port> <password> [trusted_url ...]
port = int(sys.argv[1])
password = sys.argv[2]
protocol.debug = False
# Optional limits for tests, e.g. BRIDGE_TEST_OVERRIDES='{"max_registrations_per_host": 6}'
for name, value in json.loads(os.getenv("BRIDGE_TEST_OVERRIDES", "{}")).items():
    setattr(protocol, name, value)
app = bridge.Bridge("127.0.0.1", port, password, f"http://127.0.0.1:{port}")
for url in sys.argv[3:]:
    app.add_trusted_server(password, url)
app.start_server()
