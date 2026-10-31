import os

import bridge
from bridge import ConnectionMode

# Start a Bridge server.
#   BRIDGE_PASSWORD    - password to control this server (required in production!)
#   BRIDGE_PUBLIC_URL  - URL under which clients and other servers reach this server, e.g. https://bridge.example.com
#   BRIDGE_TRUSTED     - comma separated URLs of other Bridge servers this server trusts
#   PORT               - port (default 8000)

host = "0.0.0.0"
port = int(os.getenv("PORT", 8000))
password = os.getenv("BRIDGE_PASSWORD", "BridgePassword")

app = bridge.Bridge(host, port, password, os.getenv("BRIDGE_PUBLIC_URL"))

for trusted_url in filter(None, (url.strip() for url in os.getenv("BRIDGE_TRUSTED", "").split(","))):
    app.add_trusted_server(password, trusted_url)

app.start_server(ConnectionMode.UNSAFE)
