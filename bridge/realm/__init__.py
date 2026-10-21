class Realm:
    def __init__(self, name, owner_client_key="None", realm_password=None):
        self.properties = {
            "name": name,
            "realm_type": "None"
        }

        self.storage = {
            "clients": {}
        }

        self.owner_ship = {
            "owner_client_key": owner_client_key,
            "administration_keys": [],
        }
    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return str(self.__dict__)

    def change_name(self, name):
        self.properties["name"] = name

    def set_client(self, client_key, data):
        self.storage["clients"][client_key] = data
    def remove_client(self, client_key):
        del self.storage["clients"][client_key]

    def transfer_ownership(self, owner_client_key, data):
        self.storage["clients"][owner_client_key] = data