from bridge.realm import Realm, RealmType


class PublicRealm(Realm):
    """Everyone can join, host commands and call them."""
    realm_type = RealmType.PUBLIC

    def __init__(self, realm_id, name, owner_ip=None):
        super().__init__(realm_id, name, owner_ip)

    def join(self, client_ip, access_key=None, code=None):
        return self.add_member(client_ip)

    def can_see_commands(self, client_ip):
        return True

    def can_host(self, client_ip):
        return True

    def can_call(self, client_ip, host_entry):
        return True

    def create_command(self, client_ip, command_name, allowed_roles=None):
        # Hosting makes the client a member, so leaving cleans up its commands
        result = super().create_command(client_ip, command_name, allowed_roles)
        if result is True:
            self.add_member(client_ip)
        return result
