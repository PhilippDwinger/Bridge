from fastapi import HTTPException
from bridge import banker, security


class Realm:
    def __init__(self, name):
        self.name = name
        self.handler_client_keys = {}
        self.clients = {}
        self.realm_type = "None"

        realm_id = banker.add_realm(self)
        self.id = realm_id

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return str(self.__dict__)

class PublicRealm(Realm):
    def __init__(self, name):
        super().__init__(name)
        self.realm_type = "public"
        self.commands = {}

class ProtectedRealm(Realm):
    def __init__(self, name):
        super().__init__(name)
        self.realm_type = "protected"
        self.commands = {}
        self.access_key = None
        self.restricted_to_owner = False
        self.owner_client_key = None

    def join(self, realm_access_key, client_key):
        if not realm_access_key == self.access_key:
            raise HTTPException(status_code=403, detail="Invalid realm access key")
        self.clients[client_key] = client_key

class PrivateRealm(Realm):
    def __init__(self, name):
        super().__init__(name)
        self.realm_type = "private"
        self.roles = {}
        self.commands = {}
        self.access_keys = {}
        self.owner_client_key = None

    def join(self, access_key, client_key):
        if not access_key in self.access_keys:
            raise HTTPException(status_code=403, detail="Invalid access key")
        self.join_empty(client_key)
        entry = self.access_keys[access_key]
        granted_roles = entry["roles"]
        self.give_client_roles(client_key, granted_roles)
    def join_empty(self, client_key):
        self.clients[client_key] = {
            "roles": [],
        }
    def create_role(self, role_name):
        if role_name in self.roles:
            raise HTTPException(status_code=400, detail="Role already exists")
        self.roles[role_name] = {}
    def create_command(self):
        pass
    def create_access_key(self, giving_roles, preferred_key):
        if not preferred_key or isinstance(preferred_key, str):
            preferred_key = security.get_free_key_in_dict(self.access_keys)
        if self.access_keys.get(preferred_key):
            raise HTTPException(status_code=403, detail="Role already exists")
        self.access_keys[preferred_key] = {
            "key": preferred_key,
            "roles": giving_roles,
        }
        return preferred_key
    def give_client_role(self, client_key, role):
        client_roles = self.clients[client_key]["roles"]
        if role not in client_roles:
            self.clients[client_key]["roles"].append(role)
    def give_client_roles(self, client_key, roles):
        for role in roles:
            self.give_client_role(client_key, role)