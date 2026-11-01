import os
import secrets

import bridge
from bridge import ConnectionMode
from bridge.core import protocol

# Behind a TLS proxy (nginx/caddy on a VM, or a platform that terminates TLS): read X-Forwarded-For so the rate
# limits see the real client address. Only turn this on when a trusted proxy sits in front.
protocol.trust_proxy = os.getenv("BRIDGE_TRUST_PROXY", "").strip().lower() in ("1", "true", "yes")

# Start a Bridge server.
#   BRIDGE_PASSWORD    - password to control this server (without it a random one is made and printed)
#   BRIDGE_PUBLIC_URL  - URL under which clients and other servers reach this server, e.g. https://bridge.example.com
#   BRIDGE_TRUSTED     - comma separated URLs of other Bridge servers this server trusts
#   BRIDGE_BLOCKED     - comma separated URLs of Bridge servers this server blocks (BridgeFriends, relaying)
#   BRIDGE_TRUST_PROXY - "1" when a trusted TLS proxy sits in front (read X-Forwarded-For for the rate limits)
#   PORT               - port (default 8000)

host = "0.0.0.0"
port = int(os.getenv("PORT", 8000))
password = os.getenv("BRIDGE_PASSWORD")
if not password:
    # Never a fixed default password: everybody could use /admin (reset, mailboxes, trust) and read the backups.
    # Without BRIDGE_PASSWORD a random one is made for this start and printed once.
    password = secrets.token_urlsafe(18)
    print(f"BRIDGE_PASSWORD is not set - admin password for this start: {password}")
    print("Set BRIDGE_PASSWORD to keep it (the backup at the trusted servers needs the same password after a restart).")

app = bridge.Bridge(host, port, password, os.getenv("BRIDGE_PUBLIC_URL"))

for trusted_url in filter(None, (url.strip() for url in os.getenv("BRIDGE_TRUSTED", "").split(","))):
    app.add_trusted_server(password, trusted_url)
for blocked_url in filter(None, (url.strip() for url in os.getenv("BRIDGE_BLOCKED", "").split(","))):
    app.block_server(password, blocked_url)

app.start_server(ConnectionMode.UNSAFE)
