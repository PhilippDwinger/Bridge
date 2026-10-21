from fastapi import FastAPI
from bridge.server.routes.status import Router as StatusRouter


def create_app() -> FastAPI:
    app = FastAPI()
    app.include_router(StatusRouter)
    return app