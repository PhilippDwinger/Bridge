from fastapi import FastAPI, HTTPException

from bridge import banker


def create_app(bridge_reference):
    def client_authorization_check(data: dict, bridge_reference):
        client_key = data["client_key"]
        client_name = data["client_name"]
        if bridge_reference.is_client_authorized(client_key, client_name) is not True:
            raise HTTPException(status_code=401, detail="Client is not authorized!")
    def realm_authorization_check(data: dict, bridge_reference):
        key = data["key"]
        realm_name = data["realm_name"]
        if bridge_reference.is_realm_change_authorized(realm_name, key) is not True:
            raise HTTPException(status_code=401, detail="Realm is not authorized!")


    app = FastAPI()

    @app.get("/")
    async def root():
        return {"Hello from Bridge!"}

    @app.post("/realm/create")
    async def create_private_realm(data: dict):
        realm_name = data["realm_name"]
        realm_preferred_key = data.get("realm_preferred_key")
        key = bridge_reference.register_realm(realm_name, realm_preferred_key)
        return {"key": key}

    @app.post("/realm/key")
    async def add_realm_key(data: dict):
        key = data["key"]
        realm_name = data["realm_name"]
        realm_key = data["realm_key"]
        realm_authorization_check(data, bridge_reference)
        realm = banker.get_realm(realm_name)
        realm.attach_realm_key(realm_key)

    @app.post("/client")
    async def register_client(data: dict):
        client_name = data["client_name"]
        client_key = bridge_reference.register_client(client_name)
        return {"client_key": client_key}

    @app.post("/realm/join")
    async def join_realm(data: dict):
        client_key = data["client_key"]
        client_authorization_check(data, bridge_reference)
        realm_name = data["realm_name"]
        realm_key = data["realm_key"]
        key = data["key"]
        realm_authorization_check(data, bridge_reference)
        return bridge_reference.register_client_to_private_realm(client_key, realm_name, realm_key, key)

    @app.post("/realm/host")
    async def host_command(data: dict):
        print("Got request to host command | public")
        client_key = data["client_key"]
        client_authorization_check(data, bridge_reference)
        command_key = data["command_key"]
        bridge_reference.host_command(client_key, command_key)
        print("Host command received | public")

    @app.post("/realm/private/host")
    async def host_command_private(data: dict):
        print("Got request to host command | private")
        client_key = data["client_key"]
        client_authorization_check(data, bridge_reference)
        realm_name = data["realm_name"]
        realm_key = data["realm_key"]
        command_key = data["command_key"]
        bridge_reference.host_command_in_private_realm(client_key, command_key, realm_name, realm_key)
        print("Host command received | private")

    @app.post("/call")
    async def call_command(data: dict):
        client_key = data["client_key"]
        command_key = data["command_key"]
        args = data["args"]
        bridge_reference.call(client_key, command_key, args)

    async def create_realm_key(realm_name, key, command_key, handler_client_key, http_method):
        realm = bridge_reference.get_realm(realm_name, key)
        realm.add_command()

    return app

