import uvicorn

from bridge import errors
from bridge.errors.exceptions import Exceptions
from bridge.server.app import create_app
from bridge.server.connection_modes import ConnectionMode


def start_server(bridge_instance, host: str, port: int, connection_mode: ConnectionMode,
                 ssl_keyfile="localhost+2-key.pem", ssl_certfile="localhost+2.pem"):
    if not isinstance(connection_mode, ConnectionMode):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"Unsupported connection mode: {connection_mode}")
        return Exceptions.ARGUMENT_ERROR

    app = create_app(bridge_instance)

    if connection_mode == ConnectionMode.SAFE:
        uvicorn.run(
            app,
            host=host,
            port=port,
            ssl_keyfile=ssl_keyfile,
            ssl_certfile=ssl_certfile,
        )
    elif connection_mode == ConnectionMode.UNSAFE:
        uvicorn.run(
            app,
            host=host,
            port=port,
        )
    return None
