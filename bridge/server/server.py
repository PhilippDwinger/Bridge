import uvicorn

from bridge.server.app import create_app
from bridge.server.connection_modes import ConnectionMode


def start_server(host: str, port: int, connection_mode: ConnectionMode) -> None:
    if not isinstance(connection_mode, ConnectionMode):
        raise ValueError(f"Unsupported connection mode: {connection_mode}")

    app = create_app()

    if connection_mode == ConnectionMode.SAFE:
        uvicorn.run(
            app,
            host=host,
            port=port,
            ssl_keyfile="localhost+2-key.pem",
            ssl_certfile="localhost+2.pem",
        )
    elif connection_mode == ConnectionMode.UNSAFE:
        uvicorn.run(
            app,
            host=host,
            port=port,
        )