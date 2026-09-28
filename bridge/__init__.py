import datetime
import os

import uvicorn
from fastapi import HTTPException

from bridge import security, banker
from bridge.api import server
from bridge.realm import Realm, PrivateRealm, PublicRealm

def restart():
    os._exit(0)

class Bridge:
    def __init__(self, host, port):
        self.private_realms = {}
        self.public_realm = PublicRealm("Bridge")
        self.host = host
        self.port = port
        self.clients = {}
    def register_realm(self, realm_name, preferred_key=None):
        print("Registering realm: " + realm_name)
        registered_realm = PrivateRealm(realm_name)
        if self.private_realms.get(realm_name) is not None:
            raise HTTPException(status_code=500, detail="Realm already registered in banker but not in Bridge!")
        if not preferred_key:
            register_key = security.generate_key()
        else:
            register_key = preferred_key
        self.private_realms[registered_realm.name] = {
            "realm": registered_realm,
            "key": register_key
        }
        print("Created realm! Name: " + registered_realm.name + " | Register_Key: " + register_key)
        return register_key
    def delete_realm(self, realm_name, key):
        if self.private_realms.get(realm_name) is not None:
            if self.private_realms[realm_name]["key"] == key:
                del self.private_realms[realm_name]
                print("Deleted realm! Name: " + realm_name + " | Key: " + key)
                return
        raise HTTPException(status_code=404, detail="Realm not registered in Bridge!")
    def get_realm(self, realm_name, key):
        if self.private_realms.get(realm_name) is None:
            raise HTTPException(status_code=404, detail="Realm not registered in Bridge!")
        if self.private_realms[realm_name]["key"] == key:
            return self.private_realms[realm_name]["realm"]
        raise HTTPException(status_code=403, detail="Realm key is wrong!")
    def is_realm_change_authorized(self, realm_name, key):
        print("------------")
        print("Checking realm: " + realm_name)
        print("Checking key: " + key)
        print(self.private_realms)
        if self.private_realms.get(realm_name) is None:
            return False
        if self.private_realms[realm_name]["key"] == key:
            return True
        return False

    def register_client(self, client_name):
        client_key = security.generate_client_key(client_name)
        self.public_realm.register_client(client_key)
        self.clients[client_key] = {
            "key": client_key,
            "name": client_name,
            "last_updated": datetime.datetime.now(datetime.timezone.utc),
            "realms": {
                self.public_realm.name: {
                    "realm_type": "public",
                    "realm": self.public_realm
                }
            }
        }
        return client_key
    def unregister_client(self, client_key):
        if self.private_realms.get(client_key) is None:
            raise HTTPException(status_code=404, detail="Realm not registered in Bridge!")
        del self.private_realms[client_key]
    def is_client_authorized(self, client_key, client_name):
        if self.clients.get(client_key) is None:
            return False
        if self.clients.get(client_key)["key"] == client_key:
            return True
        return False

    def host_command(self, client_key, command_key):
        self.public_realm.add_command(command_key, client_key)

    def host_command_in_private_realm(self, client_key, command_key, realm_name, realm_key):
        target_realm = banker.get_realm(realm_name)
        print("Got realm from banker: ", target_realm)
        target_realm.add_command_to_realm_key(realm_key, command_key, client_key)

    def register_client_to_private_realm(self, client_key, realm_name, realm_key, key):
        print("=================")
        print("1. client_key: " + client_key)
        print("2. realm_name: " + realm_name)
        print("3. realm_key: " + realm_key)
        print("4. clients: ", self.clients)
        realm = self.get_realm(realm_name, realm_key)
        realm.register_client(client_key)
        realm.register_client_to_realm(client_key, realm_key)
        if self.clients[client_key]["realms"][realm_name] is not None:
            self.clients[client_key]["realms"][realm_name]["realm_keys"].append(realm_key)
        else:
            self.clients[client_key]["realms"][realm_name] = {
                "realm_type": "private",
                "realm": realm,
                "realm_keys": [realm_key]
            }

    def call(self, client_key, command_key, args):
        print("Calling for command: " + command_key)
        realms_with_command = []
        for clients_realm_name, clients_realm in self.clients[client_key]["realms"].items():
            print("Searching realm: " + clients_realm_name + " | Type: " + clients_realm["realm_type"])
            if clients_realm["realm_type"] == "private":
                providers = clients_realm["realm"].get_command_from_realm_key(
                    clients_realm["realm_key"],
                    command_key
                )
                if providers is not None:
                    for provider in providers:
                        realms_with_command.append({
                            "realm_type": "private",
                            "provider_realm": provider,
                            "realm_key": clients_realm["realm_key"],
                        })
            elif clients_realm["realm_type"] == "public":
                providers = clients_realm["realm"].get_command(command_key)
                if providers is not None:
                    for provider in providers:
                        realms_with_command.append({
                            "realm_type": "public",
                            "provider_realm": provider
                        })
            else:
                print(clients_realm)
                raise ValueError("Invalid realm type")
        print("Found command in: ", realms_with_command)

    def start(self, connection_mode="unsafe"):
        app = server.create_app(self)

        if connection_mode == "safe":
            uvicorn.run(
                app,
                host=self.host,
                port=self.port,
                ssl_keyfile="localhost+2-key.pem",
                ssl_certfile="localhost+2.pem",
            )
        elif connection_mode == "unsafe":
            uvicorn.run(app, host=self.host, port=self.port)
        else:
            raise ValueError("Invalid connection mode")
    def stop(self):
        pass
