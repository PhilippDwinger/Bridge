realms = {}

def is_realm_name_free(name):
    return name in realms

def create_realm(realm):
    realms[realm.name] = realm