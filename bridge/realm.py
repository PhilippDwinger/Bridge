from typing import override

from fastapi import HTTPException
from bridge import banker
import hashlib

def generate_password(string1, string2):
    data = f"{string1}:{string2}".encode()
    salt = b"bridge_password"
    return hashlib.pbkdf2_hmac("sha256", data, salt, 600000).hex()

class Realm:
    def __init__(self, name):
        if not banker.is_realm_name_free(name):
            raise HTTPException(status_code=409, detail="Realm name is already in use!")
        self.name = name
        self.handler_client_keys = {}
        self.clients = {}
        self._realm_type = "None"
        banker.create_realm(self)

    def generate_handler_client_key(self, realm_key, handler_client_name, password):
        key = generate_password(handler_client_name, password)
        if self.handler_client_keys.get(key) is None:
            self.handler_client_keys[key] = True
            return key
        raise HTTPException(status_code=500, detail="Couldn't generate client key!")

    def is_client_registered(self, client_key):
        return self.clients.get(client_key) is not None
    def register_client(self, client_key):
        if not self.is_client_registered(client_key):
            self.clients[client_key] = True

class PublicRealm(Realm):
    def __init__(self, name):
        super().__init__(name)
        self.commands = {}
        self._realm_type = "public"

    def add_command(self, command_key, handler_client_key):
        print("Adding command!")
        if not command_key or not handler_client_key:
            raise HTTPException(status_code=400, detail="Missing arguments!")
        if command_key not in self.commands:
            self.commands[command_key] = []

        entry = {
            "handler_client_key": handler_client_key,
            "command_key": command_key
        }
        if entry not in self.commands[command_key]:
            self.commands[command_key].append(entry)
        else:
            raise HTTPException(status_code=409, detail="Command is already attached to realm!")
        print("Done adding command!", self.commands)
    def remove_command(self, command_key, handler_client_key):
        if not command_key or not handler_client_key:
            raise HTTPException(status_code=400, detail="Missing arguments!")
        if command_key not in self.commands:
            raise HTTPException(status_code=404, detail="Command not found!")

        for entry in self.commands[command_key]:
            if entry["handler_client_key"] == handler_client_key:
                self.commands[command_key].remove(entry)

                if not self.commands[command_key]:
                    del self.commands[command_key]

                return

        raise HTTPException(status_code=404, detail="Command not found!")

    # Public API
    def get_command(self, command_key):
        if not command_key:
            raise HTTPException(status_code=400, detail="Missing or invalid arguments!")
        if command_key not in self.commands:
            raise HTTPException(status_code=404, detail="Command not found!")
        return self.commands[command_key]

class PrivateRealm(Realm):
    def __init__(self, name):
        super().__init__(name)
        self.realm_keys = {}
        #self.realm_keys.realm_key.command_key = {
        #    "handler_client_key": handler_client_key,
        #    "http_method": http_method,
        #    "command_key": command_key
        #}
        self._realm_type = "private"

    def attach_realm_key(self, realm_key):
        if realm_key not in self.realm_keys:
            self.realm_keys[realm_key] = {}
    def detach_realm_key(self, realm_key):
        if realm_key not in self.realm_keys:
            raise HTTPException(status_code=404, detail="Realm key is not valid")
        del self.realm_keys[realm_key]
    def clean_realm_key(self, realm_key):
        if realm_key not in self.realm_keys:
            raise HTTPException(status_code=404, detail="Realm key is not valid")
        self.realm_keys[realm_key] = {}

    def add_command_to_realm_key(self, realm_key, command_key, handler_client_key):
        print("Adding command!")
        print("Realm key:", realm_key)
        print("Realm Keys:", self.realm_keys)
        if realm_key not in self.realm_keys:
            raise HTTPException(status_code=404, detail="Realm key is not valid")
        if not command_key or not handler_client_key:
            raise HTTPException(status_code=400, detail="Missing arguments!")
        if command_key not in self.realm_keys[realm_key]:
            self.realm_keys[realm_key][command_key] = []

        entry = {
            "handler_client_key": handler_client_key,
            "command_key": command_key
        }
        if entry not in self.realm_keys[realm_key][command_key]:
            self.realm_keys[realm_key][command_key].append(entry)
        else:
            raise HTTPException(status_code=409, detail="Command is already attached to realm key!")
        print("Done! New Keys:", self.realm_keys)
    def remove_command_from_realm_key(self, realm_key, command_key, handler_client_key):
        if realm_key not in self.realm_keys:
            raise HTTPException(status_code=404, detail="Realm key is not valid")
        if not command_key or not handler_client_key:
            raise HTTPException(status_code=400, detail="Missing arguments!")
        if command_key not in self.realm_keys[realm_key]:
            raise HTTPException(status_code=404, detail="Command not found!")

        for entry in self.realm_keys[realm_key][command_key]:
            if entry["handler_client_key"] == handler_client_key:
                self.realm_keys[realm_key][command_key].remove(entry)

                if not self.realm_keys[realm_key][command_key]:
                    del self.realm_keys[realm_key][command_key]

                return

        raise HTTPException(status_code=404, detail="Command not found!")

    # Public API
    def get_command_from_realm_key(self, realm_key, command_key):
        if realm_key not in self.realm_keys:
            raise HTTPException(status_code=404, detail="Realm key is not valid")
        if not command_key:
            raise HTTPException(status_code=400, detail="Missing or invalid arguments!")
        if command_key not in self.realm_keys[realm_key]:
            raise HTTPException(status_code=404, detail="Command not found!")
        return self.realm_keys[realm_key][command_key]

    def register_client(self, client_key):
        if not self.is_client_registered(client_key):
            self.clients[client_key] = {"connected_realms" : []}

    def register_client_to_realm(self, client_key, realm_key):
        print("Registering client on realm!")
        print(self.realm_keys)
        print("searching key:", realm_key)
        if self.realm_keys[realm_key]:
            self.clients[client_key]["connected_realms"].append(realm_key)
        else:
            raise HTTPException(status_code=404, detail="Realm key is not valid!")