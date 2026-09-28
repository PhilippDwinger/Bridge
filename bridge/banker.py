realms = {}

def is_realm_name_free(name):
    return name not in realms

def create_realm(realm):
    realms[realm.name] = realm

def get_realm(realm_name):
    return realms[realm_name]