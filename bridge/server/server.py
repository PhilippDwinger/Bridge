import sys

import uvicorn

from bridge import errors
from bridge.banker import mailbox_store
from bridge.core import protocol
from bridge.errors.exceptions import Exceptions
from bridge.server.app import create_app
from bridge.server.connection_modes import ConnectionMode

# The running uvicorn server, so stop_server() can end it normally (also from another thread)
_running_server = None


class _BridgeServer(uvicorn.Server):
    async def shutdown(self, sockets=None):
        # Waiting long polls answer right away (empty) - they don't hold up the stop and the last backup
        mailbox_store.wake_all_for_shutdown()
        await super().shutdown(sockets=sockets)


def start_server(bridge_instance, host: str, port: int, connection_mode: ConnectionMode,
                 ssl_keyfile="localhost+2-key.pem", ssl_certfile="localhost+2.pem"):
    global _running_server
    if not isinstance(connection_mode, ConnectionMode):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Unsupported connection mode: {connection_mode}")
        return Exceptions.ARGUMENT_ERROR

    app = create_app(bridge_instance)
    options = {
        "host": host,
        "port": port,
        # Safety net: requests still running after this are cancelled, so the last backup is not held back
        "timeout_graceful_shutdown": protocol.shutdown_grace_seconds,
    }
    if protocol.trust_proxy:
        # Behind a trusted TLS proxy: believe X-Forwarded-For so the rate limits see the real client address
        options["proxy_headers"] = True
        options["forwarded_allow_ips"] = "*"
    if connection_mode == ConnectionMode.SAFE:
        options.update(ssl_keyfile=ssl_keyfile, ssl_certfile=ssl_certfile)

    server = _BridgeServer(uvicorn.Config(app, **options))
    _running_server = server
    try:
        server.run()
    except KeyboardInterrupt:
        pass
    finally:
        _running_server = None
    if not server.started:
        # Same as uvicorn.run: e.g. the port is already in use
        sys.exit(3)
    return None


def stop_server():
    """Ends the running server normally, like Ctrl+C: the lifespan still sends the last backup.
    Works from any thread and on every OS (Windows cannot send Ctrl+C to another process)."""
    server = _running_server
    if server is None:
        return False
    server.should_exit = True
    return True
