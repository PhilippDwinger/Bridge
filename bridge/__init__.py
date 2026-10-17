import datetime
import os
from logging import warning
from argon2.exceptions import VerifyMismatchError

import uvicorn
from fastapi import HTTPException

from bridge import security, banker
from bridge.api import server
from bridge.messenger.sender import get_client_mailbox_from_client_key
from bridge.realm import Realm, PrivateRealm, PublicRealm

def login_client(client_key: str, password: str):
    client_entry = banker.get_client_by_key(client_key)
    if not client_entry:
        raise HTTPException(status_code=404, detail="Client not found")
    try:
        password_matches = security.verify_password(
            password, client_entry["hashed_password"]
        )
    except VerifyMismatchError:
        password_matches = False

    if not password_matches:
        raise HTTPException(status_code=403, detail="Incorrect password")
    session_token, remaining_minutes = banker.generate_session_token(client_key)
    if not session_token:
        raise HTTPException(status_code=500, detail="A problem occurred")
    return session_token, remaining_minutes

def restart():
    os._exit(0)

def get_all_accessible_command_hosts_for_client(command_name, client_key: str):
    client_entry = banker.get_client_by_key(client_key)

    found_hosts = []

    for i, v in banker.realms.items():
        if v.realm_type == "public" or v.realm_type == "protected":
            result = v.get_all_accessible_hosts_for_command(command_name)
            if result:
                for host in result:
                    if host in found_hosts:
                        continue
                    found_hosts.append(host)
        elif v.realm_type == "private":
            result = v.get_all_accessible_hosts_for_command(client_key, command_name)
            if result:
                for host in result:
                    if host in found_hosts:
                        continue
                    found_hosts.append(host)
        else:
            warning("Realm is not supported")
            continue
    return found_hosts

def get_least_busy_client(clients : list):
    busy_points_record = {}
    for client_key in clients:
        mailbox = get_client_mailbox_from_client_key(client_key)
        busy_points = mailbox.get_busy_points()
        if busy_points is not None:
            busy_points_record[busy_points] = client_key
    if len(busy_points_record) == 0:
        return None
    return busy_points_record[max(busy_points_record)]

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
        self.public_realm = PublicRealm("Bridge")
        self.clients = {}

    def register_client(self, requested_client_name: str, password: str, bridge_url):
        client_key = banker.register_new_client(requested_client_name, password, bridge_url)
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
