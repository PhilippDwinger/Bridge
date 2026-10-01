from fastapi import FastAPI, HTTPException

import bridge
from bridge import banker

def create_app(current_bridge_app):
    app = FastAPI()

    @app.get("/")
    async def root():
        return {"Hello from Bridge!"}

    @app.post("/client")
    async def client_registration(payload : dict):
        requested_client_name = payload["client_name"]
        password = payload["password"]
        client_key = current_bridge_app.register_client(requested_client_name, password)
        return {"client_name": requested_client_name, "client_key": client_key}

    @app.post("/login")
    async def login(payload : dict):
        client_key = payload["client_key"]
        password = payload["password"]
        return bridge.login_client(client_key, password)

    @app.post("/realm/create/protected")
    async def create_protected_realm(payload : dict):
        pass

    @app.post("/realm/create/private")
    async def create_private_realm(payload : dict):
        pass

    @app.post("/realm/join/protected")
    async def join_protected_realm(payload : dict):
        pass

    @app.post("/realm/join/private")
    async def join_private_realm(payload : dict):
        pass

    return app