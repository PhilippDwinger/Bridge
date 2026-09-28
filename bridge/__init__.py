from fastapi import HTTPException

from bridge import security
from bridge.realm import Realm


class Bridge:
    def __init__(self, host, port):
        self.private_realms = {}
        self.public_realm = Realm("Bridge")
        self.host = host
        self.port = port
    def register_realm(self, realm_name):
        print("Registering realm: " + realm_name)
        registered_realm = Realm(realm_name)
        if self.private_realms.get(realm_name) is not None:
            raise HTTPException(status_code=500, detail="Realm already registered in banker but not in Bridge!")
        register_key = security.generate_key()
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