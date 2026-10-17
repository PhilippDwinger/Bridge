from fastapi import FastAPI, HTTPException, Request

import bridge
from bridge import banker, security
from bridge.messenger import sender
from bridge.messenger.mailbox import MailBox
from bridge.realm import PublicRealm, PrivateRealm, ProtectedRealm
from bridge.transfer import transfer, universal


def get_bridge_url_from_request(request: Request):
    return str(request.base_url).rstrip("/")


def normalize_lua_hybrid_tables(value):
    if isinstance(value, list):
        return [normalize_lua_hybrid_tables(item) for item in value]

    if not isinstance(value, dict):
        return value

    array_items = []
    has_keyed_items = False

    for key, item in value.items():
        if isinstance(key, str) and key.isdecimal() and int(key) > 0 and str(int(key)) == key:
            array_items.append((int(key), item))
        else:
            has_keyed_items = True

    if array_items and has_keyed_items:
        return [
            normalize_lua_hybrid_tables(item)
            for _, item in sorted(array_items)
        ]

    return {
        key: normalize_lua_hybrid_tables(item)
        for key, item in value.items()
    }


def create_app(current_bridge_app):
    # region defaults
    app = FastAPI()

    @app.get("/")
    async def root():
        return {"Hello from Bridge!"}

    @app.post("/client")
    async def client_registration(payload : dict, request: Request):
        bridge_url = get_bridge_url_from_request(request)
        requested_client_name = payload["client_name"]
        password = payload["password"]
        client_key = current_bridge_app.register_client(requested_client_name, password, bridge_url)
        return {"client_name": requested_client_name, "client_key": client_key}

    @app.post("/login")
    async def login(payload : dict):
        client_key = payload["client_key"]
        password = payload["password"]
        session_token, remaining_minutes = bridge.login_client(client_key, password)
        return {
            "session_token": session_token,
            "remaining_minutes": remaining_minutes
        }

    # endregion
    # region realms
    # region public
    @app.post("/realm/command")
    async def create_command_in_public_realm(payload : dict):
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        client_key = banker.get_client_key_from_session_token(session_token)
        if not client_key:
            raise HTTPException(status_code=403, detail="Invalid arguments")
        command_name = payload["command_name"]
        public_realm : PublicRealm = current_bridge_app.public_realm
        if not public_realm:
            raise ValueError("Public realm was not found!")

        public_realm.create_command(command_name, client_key)

        return None

    # endregion
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
        security.authenticate_session(session_token)
        realm_id = payload["realm_id"]
        client_key = banker.get_client_key_from_session_token(session_token)
        protected_realm : ProtectedRealm = banker.get_realm_from_id(realm_id)
        if not protected_realm or not protected_realm.realm_type == "protected":
            raise HTTPException(status_code=403, detail="Invalid arguments")
        if not protected_realm.is_client_in_realm(client_key):
            raise HTTPException(status_code=403, detail="Client is not a member of the realm")
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
        client_key = banker.get_client_key_from_session_token(session_token)
        if not private_realm.is_client_owner(client_key):
            raise HTTPException(status_code=401, detail="Client is not allowed to host command")
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
        client_key = banker.get_client_key_from_session_token(session_token)
        if not private_realm.is_client_owner(client_key):
            raise HTTPException(status_code=401, detail="Client is not allowed to host command")
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
    @app.post("/poll")
    async def poll_client_mailbox(payload: dict):
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        client_key = banker.get_client_key_from_session_token(session_token)
        mailbox = sender.get_client_mailbox_from_client_key(client_key)
        pending_id = mailbox.poll_most_overdue()
        return pending_id

    @app.post("/poll/chunk")
    async def poll_client_chunk(payload: dict):
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        pending_id = payload["pending_id"]
        chunk_index = payload["chunk_index"]
        client_key = banker.get_client_key_from_session_token(session_token)
        mailbox = sender.get_client_mailbox_from_client_key(client_key)
        return mailbox.get_chunk_of_pending_message(pending_id, chunk_index)

    @app.post("/poll/complete")
    async def poll_client_complete(payload: dict):
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        client_key = banker.get_client_key_from_session_token(session_token)
        mailbox = sender.get_client_mailbox_from_client_key(client_key)
        pending_id = payload["pending_id"]
        return universal.encode(mailbox.complete_message(pending_id))

    @app.post("/poll/stats")
    async def poll_stats(payload: dict):
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        client_key = banker.get_client_key_from_session_token(session_token)
        mailbox = sender.get_client_mailbox_from_client_key(client_key)
        pending_id = payload["pending_id"]
        return mailbox.get_pending_id_stats(pending_id)

    @app.post("/call/command")
    async def call_command(payload: dict, request: Request):
        session_token = payload["session_token"]
        security.authenticate_session(session_token)
        client_key = banker.get_client_key_from_session_token(session_token)
        command_name = payload["command_name"]
        command_args = payload.get("command_args")
        hosting_clients = bridge.get_all_accessible_command_hosts_for_client(command_name, client_key)
        if not hosting_clients:
            raise HTTPException(status_code=402, detail="No hosting clients found")
        best_client = bridge.get_least_busy_client(hosting_clients)
        if not best_client:
            raise HTTPException(status_code=500, detail="Error while getting best client")
        best_client_ip = sender.get_client_ip(best_client)
        client_ip = sender.get_client_ip(client_key)
        result = await send_message({
            "session_token": session_token,
            "client_ip": client_ip,
            "target_recipient_ip": best_client_ip,
            "content": normalize_lua_hybrid_tables(command_args),
        }, request)
        return result

    @app.post("/send")
    async def send_message(payload: dict, request: Request):
        bridge_url = get_bridge_url_from_request(request)

        session_token = payload["session_token"]
        security.authenticate_session(session_token)

        content = payload["content"]
        target_recipient_ip = payload["target_recipient_ip"]
        client_key = banker.get_client_key_from_session_token(session_token)
        client_ip = sender.get_client_ip(client_key)

        message = transfer.create_message(
            client_ip,
            target_recipient_ip,
            content,
            "task",
            None,
            None,
            client_ip,
            bridge_url,
            "direct",
            "long"
        )
        result = sender.send_message(message)
        return result

    @app.post("/respond/message")
    async def respond_to_client_with_msg(payload: dict):
        pass

    @app.post("/respond/acknowledge")
    async def acknowledge_message(payload: dict):
        pass

    # endregion
    # region admin
    @app.post("/admin/realm/view")
    def realm_view(payload: dict):
        realm_id = payload["realm_id"]
        realm = banker.get_realm_from_id(realm_id)
        print(realm)

    @app.get("/admin/view/realms")
    def view_all_realms():
        print(banker.realms)
    # endregion

    return app