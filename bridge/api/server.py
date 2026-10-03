from fastapi import FastAPI, HTTPException

import bridge
from bridge import banker, security
from bridge.realm import PublicRealm, PrivateRealm, ProtectedRealm

def create_app(current_bridge_app):
    # region defaults
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

    # endregion
    # region realms
    # region protected
    @app.post("/realm/create/protected")
    async def create_protected_realm(payload : dict):
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        restricted_to_owner = payload["restricted_to_owner"]
        realm_name = payload.get("realm_name") or "unnamed-realm"
        access_key = payload["access_key"]
        protected_realm = ProtectedRealm(realm_name)
        protected_realm.access_key = access_key
        protected_realm.restricted_to_owner = restricted_to_owner
        client_key = banker.get_client_key_from_session_token(session_token)
        protected_realm.owner_client_key = client_key
        await join_protected_realm({
            "realm_access_key": access_key,
            "realm_id": protected_realm.id,
            "session_token": session_token
        })
        return protected_realm.id

    @app.post("/realm/join/protected")
    async def join_protected_realm(payload : dict):
        realm_id = payload["realm_id"]
        realm_access_key = payload["realm_access_key"]
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        protected_realm : ProtectedRealm = banker.get_realm_from_id(realm_id)
        if not protected_realm or not protected_realm.realm_type == "protected":
            raise HTTPException(status_code=403, detail="Invalid arguments")
        client_key = banker.get_client_key_from_session_token(session_token)
        if not protected_realm or not realm_access_key or not client_key:
            raise HTTPException(status_code=403, detail="Invalid arguments")
        protected_realm.join(realm_access_key, client_key)

    @app.post("/realm/command/protected")
    async def create_command_in_protected_realm(payload: dict):
        session_token = payload["session_token"]
        realm_id = payload["realm_id"]
        security.authenticate_session(session_token)
        client_key = banker.get_client_key_from_session_token(session_token)
        protected_realm : ProtectedRealm = banker.get_realm_from_id(realm_id)
        if not protected_realm or not protected_realm.realm_type == "protected":
            raise HTTPException(status_code=403, detail="Invalid arguments")
        if not protected_realm.is_client_key_allowed_to_host_command(client_key):
            raise HTTPException(status_code=401, detail="Client is not allowed to host command")
        command_name = payload["command_name"]
        protected_realm.create_command(command_name, client_key)

    # endregion
    # region private
    @app.post("/realm/create/private")
    async def create_private_realm(payload : dict):
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        realm_name = payload.get("realm_name") or "unnamed-realm"
        private_realm = PrivateRealm(realm_name)
        client_key = banker.get_client_key_from_session_token(session_token)
        private_realm.owner_client_key = client_key
        private_realm.join_empty(client_key)
        return private_realm.id

    @app.post("/realm/create/private/key")
    async def create_private_realm_key(payload: dict):
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        realm_id = payload["realm_id"]
        private_realm : PrivateRealm = banker.get_realm_from_id(realm_id)
        if not private_realm or not private_realm.realm_type == "private":
            raise HTTPException(status_code=403, detail="Invalid arguments")
        giving_roles = payload["giving_roles"]
        preferred_key = payload.get("preferred_key") or None
        return private_realm.create_access_key(giving_roles, preferred_key)

    @app.post("/realm/create/private/role")
    async def create_private_realm_role(payload: dict):
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        realm_id = payload["realm_id"]
        private_realm : PrivateRealm = banker.get_realm_from_id(realm_id)
        if not private_realm or not private_realm.realm_type == "private":
            raise HTTPException(status_code=403, detail="Invalid arguments")
        role_name = payload["role_name"]
        role_permissions = payload["role_permissions"]
        private_realm.create_role(role_name, role_permissions)

    @app.post("/realm/join/private")
    async def join_private_realm(payload : dict):
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        realm_id = payload["realm_id"]
        realm_access_key = payload["realm_access_key"]
        client_key = banker.get_client_key_from_session_token(session_token)
        private_realm : PrivateRealm = banker.get_realm_from_id(realm_id)
        if not private_realm or not private_realm.realm_type == "private":
            raise HTTPException(status_code=403, detail="Invalid arguments")
        private_realm.join(realm_access_key, client_key)

    @app.post("/realm/command/private")
    async def create_command_in_private_realm(payload: dict):
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        realm_id = payload["realm_id"]
        client_key = banker.get_client_key_from_session_token(session_token)
        private_realm : PrivateRealm = banker.get_realm_from_id(realm_id)
        if not private_realm or not private_realm.realm_type == "private":
            raise HTTPException(status_code=403, detail="Invalid arguments")
        allowed_roles = payload["allowed_roles"]
        command_name = payload["command_name"]
        if not private_realm.can_client_host_commands(client_key):
            raise HTTPException(status_code=403, detail="Client is not allowed to host commands")
        private_realm.create_command(command_name, allowed_roles, client_key)

    # endregion
    # endregion
    # region events
    # endregion
    # region messaging
    # endregion
    # region admin
    @app.post("/admin/realm/view")
    def realm_view(payload: dict):
        realm_id = payload["realm_id"]
        realm = banker.get_realm_from_id(realm_id)
        print(realm)
    # endregion

    return app