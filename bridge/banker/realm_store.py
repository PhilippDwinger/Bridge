from bridge.security.generator import generate_key

# realm_id -> Realm (only realms that live on this server)
realm_storage = {}
# realm_id of this server's default public realm
public_realm_id = None

def generate_realm_id():
    for _ in range(100):
        realm_id = generate_key(16)
        if realm_id not in realm_storage:
            return realm_id
    return None

def add_realm(realm):
    realm_storage[realm.realm_id] = realm

def get_realm(realm_id):
    return realm_storage.get(realm_id)

def remove_realm(realm_id):
    realm_storage.pop(realm_id, None)

def set_public_realm_id(realm_id):
    global public_realm_id
    public_realm_id = realm_id

def reset():
    global public_realm_id
    realm_storage.clear()
    public_realm_id = None
