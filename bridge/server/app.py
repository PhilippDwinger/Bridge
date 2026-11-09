import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.gzip import GZipMiddleware

from bridge.banker import trust_store
from bridge.core import backup, metrics, protocol
from bridge.errors.exceptions import Exceptions, get_exception_id
from bridge.messenger import outbox, service as messenger_service
from bridge.realm import sync as realm_sync
from bridge.subservices.bridge_agent import routing, service as agent_service  # noqa: F401 (registers the task expiry hook)
from bridge.server import compression, runtime, s2s_client
from bridge.server.base_path import BasePathMiddleware
from bridge.server.routes.admin import Router as AdminRouter
from bridge.server.routes.agent import Router as AgentRouter
from bridge.server.routes.client import Router as ClientRouter
from bridge.server.routes.commands import Router as CommandRouter
from bridge.server.routes.conversations import Router as ConversationRouter
from bridge.server.routes.express import Router as ExpressRouter
from bridge.server.routes.friends import Router as FriendsRouter, S2SRouter as FriendsS2SRouter
from bridge.server.routes.messages import Router as MessageRouter
from bridge.server.routes.realms import Router as RealmRouter
from bridge.server.routes.dashboard import Router as DashboardRouter
from bridge.server.routes.s2s import Router as S2SRouter
from bridge.server.routes.site import Router as SiteRouter, check_reserved as check_site_reserved
from bridge.server.routes.status import Router as StatusRouter


# Server to server paths that work while the server restores its backup (needed for the restore itself)
S2S_ALWAYS = ("/s2s/handshake/", "/s2s/backup/", "/s2s/friends/link/", "/s2s/ping")
CLIENT_PATHS = ("/client/", "/message/", "/command/", "/realm/", "/express/", "/agent/", "/conversation/", "/friends/")


def create_app(bridge_instance) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        runtime.set_loop(asyncio.get_running_loop())
        from bridge.banker import mailbox_store
        mailbox_store.opening()
        # Connect to all trusted servers that were added before the server started
        for server in trust_store.list_servers():
            if server["status"] != trust_store.STATUS_CONNECTED:
                runtime.schedule(s2s_client.handshake(server["url"]))
        # Restore from the trusted servers (if they keep a backup of us), then back up regularly
        backup_task = asyncio.create_task(backup.run())
        # Servers keep talking: realm versions are compared regularly
        sync_task = asyncio.create_task(realm_sync.run())
        # Deletes messages whose lifetime is over (also "temporary" ones) every second
        cleaner_task = asyncio.create_task(messenger_service.run_cleaner())
        # Sends planned messages when their time has come
        scheduler_task = asyncio.create_task(outbox.run_scheduler())
        # Servers exchange their line tables (BridgeAgent routing)
        links_task = asyncio.create_task(routing.run())
        yield
        links_task.cancel()
        scheduler_task.cancel()
        cleaner_task.cancel()
        sync_task.cancel()
        await backup.final_backup()
        backup_task.cancel()
        await s2s_client.close_http_clients()
        runtime.set_loop(None)

    app = FastAPI(title="Bridge", version=protocol.current_protocol.version, lifespan=lifespan)
    app.state.bridge = bridge_instance
    # Small data on the wire: gzip answers from 1 KiB, gzip/deflate requests are unpacked (see compression.py)
    app.add_middleware(GZipMiddleware, minimum_size=compression.GZIP_MIN_RESPONSE_BYTES)
    app.add_middleware(compression.GzipRequestMiddleware)
    # Analysis: requests per endpoint, duration, errors
    app.add_middleware(metrics.RequestMetricsMiddleware)

    @app.middleware("http")
    async def wait_for_restore(request, call_next):
        # While the server restores its backup, clients get "try again" - so nobody registers into an
        # empty server and blocks the restore. Other servers get "try again" too: an empty server would answer
        # "unknown" (e.g. a friendship that the backup brings back) and they would act on it.
        # Admin, status, handshakes and the backup itself always work.
        if not backup.is_ready():
            path = request.url.path
            error = Exceptions.SERVER_STARTING
            if path.startswith(CLIENT_PATHS):
                return JSONResponse(status_code=error.status_code, content={"detail": {
                    "error": get_exception_id(error), "name": error.name, "message": error.default_message}})
            if path.startswith("/s2s/") and not path.startswith(S2S_ALWAYS):
                # Status 200 like every s2s answer: a starting server is no broken line for the BridgeAgent
                return JSONResponse(status_code=200, content={
                    "ok": False, "error": get_exception_id(error), "message": error.default_message})
        return await call_next(request)

    # Outermost (added last): a public URL with a path (https://pc.ts.net:10000/momentum) - requests may come with or
    # without that path in front; everything inside sees the plain Bridge path (see base_path.py)
    app.add_middleware(BasePathMiddleware)

    app.include_router(StatusRouter)
    app.include_router(DashboardRouter)
    app.include_router(ClientRouter)
    app.include_router(MessageRouter)
    app.include_router(RealmRouter)
    app.include_router(CommandRouter)
    app.include_router(ConversationRouter)
    app.include_router(ExpressRouter)
    app.include_router(AgentRouter)
    app.include_router(AdminRouter)
    app.include_router(FriendsRouter)
    app.include_router(S2SRouter)
    app.include_router(FriendsS2SRouter)
    # /site belongs to the website a host app (BridgeControll) mounts next to this server - see routes/site.py
    app.include_router(SiteRouter)
    check_site_reserved(app, StatusRouter, DashboardRouter, ClientRouter, MessageRouter, RealmRouter, CommandRouter,
                        ConversationRouter, ExpressRouter, AgentRouter, AdminRouter, FriendsRouter, S2SRouter,
                        FriendsS2SRouter)
    for router in (StatusRouter, DashboardRouter, ClientRouter, MessageRouter, RealmRouter, CommandRouter, ConversationRouter,
                   ExpressRouter, AgentRouter, AdminRouter, FriendsRouter, S2SRouter, FriendsS2SRouter):
        metrics.known_paths.update(getattr(route, "path", "") for route in router.routes)
    return app
