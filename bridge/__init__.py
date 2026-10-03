import datetime
import os
from logging import warning

import uvicorn
from fastapi import HTTPException

from bridge import security, banker
from bridge.api import server
from bridge.realm import Realm, PrivateRealm, PublicRealm

def login_client(client_key: str, password: str):
    client_entry = banker.get_client_by_key(client_key)
    if not client_entry:
        raise HTTPException(status_code=404, detail="Client not found")
    if not security.verify_password(password, client_entry["hashed_password"]):
        raise HTTPException(status_code=403, detail="Incorrect password")
    session_token = banker.generate_session_token(client_key)
    if not session_token:
        raise HTTPException(status_code=500, detail="A problem occurred")
    return session_token

def restart():
    os._exit(0)

class Bridge:
    _instance = None
    def __new__(cls, host : str, port : int):
        if cls._instance is not None:
            raise RuntimeError("Bridge can only be instantiated once")

        cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, host : str, port : int):
        self.application_data = {
            "host": host,
            "port": port,
        }
        self._metadata = {
            "initialization_time": datetime.datetime.now(),
        }
        self.Realms = {
            "PublicRealm" : PublicRealm("Bridge"),
            "PrivateRealm": {},
        }
        self.clients = {}

    def register_client(self, requested_client_name: str, password: str):
        client_key = banker.register_new_client(requested_client_name, password)
        if not client_key:
            warning(f"Client {requested_client_name} is not registered")
            return None

        self.clients[client_key] = {
            "private_realms" : {},
            "protected_realms" : {},
        }

        return client_key

    def start(self, connection_mode="unsafe"):
        app = server.create_app(self)
        host = self.application_data["host"]
        port = self.application_data["port"]

        if connection_mode == "safe":
            uvicorn.run(
                app,
                host=host,
                port=port,
                ssl_keyfile="localhost+2-key.pem",
                ssl_certfile="localhost+2.pem",
            )
        elif connection_mode == "unsafe":
            uvicorn.run(app, host=host, port=port)
        else:
            raise ValueError("Invalid connection mode")
    def stop(self):
        pass
