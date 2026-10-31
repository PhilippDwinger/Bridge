import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI

from bridge.banker import trust_store
from bridge.core import protocol
from bridge.server import runtime, s2s_client
from bridge.server.routes.admin import Router as AdminRouter
from bridge.server.routes.client import Router as ClientRouter
from bridge.server.routes.commands import Router as CommandRouter
from bridge.server.routes.messages import Router as MessageRouter
from bridge.server.routes.realms import Router as RealmRouter
from bridge.server.routes.s2s import Router as S2SRouter
from bridge.server.routes.status import Router as StatusRouter


def create_app(bridge_instance) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        runtime.set_loop(asyncio.get_running_loop())
        # Connect to all trusted servers that were added before the server started
        for server in trust_store.list_servers():
            if server["status"] != trust_store.STATUS_CONNECTED:
                runtime.schedule(s2s_client.handshake(server["url"]))
        yield
        runtime.set_loop(None)

    app = FastAPI(title="Bridge", version=protocol.current_protocol.version, lifespan=lifespan)
    app.state.bridge = bridge_instance
    app.include_router(StatusRouter)
    app.include_router(ClientRouter)
    app.include_router(MessageRouter)
    app.include_router(RealmRouter)
    app.include_router(CommandRouter)
    app.include_router(AdminRouter)
    app.include_router(S2SRouter)
    return app
