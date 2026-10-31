import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from bridge.banker import trust_store
from bridge.core import backup, protocol
from bridge.errors.exceptions import Exceptions, get_exception_id
from bridge.server import runtime, s2s_client
from bridge.server.routes.admin import Router as AdminRouter
from bridge.server.routes.client import Router as ClientRouter
from bridge.server.routes.commands import Router as CommandRouter
from bridge.server.routes.messages import Router as MessageRouter
from bridge.server.routes.realms import Router as RealmRouter
from bridge.server.routes.s2s import Router as S2SRouter
from bridge.server.routes.status import Router as StatusRouter


CLIENT_PATHS = ("/client/", "/message/", "/command/", "/realm/")


def create_app(bridge_instance) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        runtime.set_loop(asyncio.get_running_loop())
        # Connect to all trusted servers that were added before the server started
        for server in trust_store.list_servers():
            if server["status"] != trust_store.STATUS_CONNECTED:
                runtime.schedule(s2s_client.handshake(server["url"]))
        # Restore from the trusted servers (if they keep a backup of us), then back up regularly
        backup_task = asyncio.create_task(backup.run())
        yield
        await backup.final_backup()
        backup_task.cancel()
        runtime.set_loop(None)

    app = FastAPI(title="Bridge", version=protocol.current_protocol.version, lifespan=lifespan)
    app.state.bridge = bridge_instance

    @app.middleware("http")
    async def wait_for_restore(request, call_next):
        # While the server restores its backup, clients get "try again" - so nobody registers into an
        # empty server and blocks the restore. Admin, status and server to server requests always work.
        if not backup.is_ready() and request.url.path.startswith(CLIENT_PATHS):
            error = Exceptions.SERVER_STARTING
            return JSONResponse(status_code=error.status_code, content={"detail": {
                "error": get_exception_id(error), "name": error.name, "message": error.default_message}})
        return await call_next(request)

    app.include_router(StatusRouter)
    app.include_router(ClientRouter)
    app.include_router(MessageRouter)
    app.include_router(RealmRouter)
    app.include_router(CommandRouter)
    app.include_router(AdminRouter)
    app.include_router(S2SRouter)
    return app
