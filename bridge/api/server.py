from fastapi import FastAPI

import bridge


def create_app(bridge : bridge.Bridge):
    app = FastAPI()

    @app.get("/")
    async def root():
        return {"Hello from Bridge!"}

    @app.post("/realms/{realm_name}")
    async def create_private_realm(realm_name):
        key = bridge.register_realm(realm_name)
        return {"key": key}

