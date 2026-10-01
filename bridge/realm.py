from fastapi import HTTPException
from bridge import banker

class Realm:
    def __init__(self, name):
        self.name = name
        self.handler_client_keys = {}
        self.clients = {}
        self._realm_type = "None"

class PublicRealm(Realm):
    def __init__(self, name):
        super().__init__(name)
        self._realm_type = "public"
        self.commands = {}

class ProtectedRealm(Realm):
    def __init__(self, name):
        super().__init__(name)
        self._realm_type = "private"
        self.commands = {}
        self.access_key = None

class PrivateRealm(Realm):
    def __init__(self, name):
        super().__init__(name)
        self._realm_type = "protected"
        self.roles = {}
        self.commands = {}
        self.access_keys = {}