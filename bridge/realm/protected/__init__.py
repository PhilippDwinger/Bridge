from bridge import errors
from bridge.errors.exceptions import Exceptions
from bridge.realm import Realm, RealmType
from bridge.security.hasher import secrets_equal


class ProtectedRealm(Realm):
    """Join with the access key or an invitation code. Members can call commands.
    With restricted_to_owner only the owner may host commands."""
    realm_type = RealmType.PROTECTED

    def __init__(self, realm_id, name, owner_ip, access_key=None, restricted_to_owner=False):
        super().__init__(realm_id, name, owner_ip)
        self.access_key = access_key
        self.restricted_to_owner = bool(restricted_to_owner)

    def join(self, client_ip, access_key=None, code=None):
        if self.is_member(client_ip):
            return True
        if access_key is not None and self.access_key is not None and secrets_equal(access_key, self.access_key):
            return self.add_member(client_ip)
        if code is not None and self._take_code(code) is not None:
            return self.add_member(client_ip)
        errors.handle_error(Exceptions.NOT_ALLOWED, "Invalid access key or invitation code")
        return Exceptions.NOT_ALLOWED

    def can_host(self, client_ip):
        if not self.is_member(client_ip):
            return False
        return not self.restricted_to_owner or self.is_owner(client_ip)

    def info(self, client_ip):
        data = super().info(client_ip)
        if isinstance(data, dict):
            data["restricted_to_owner"] = self.restricted_to_owner
            if self.is_owner(client_ip):
                data["has_access_key"] = self.access_key is not None
        return data
