"""/express/schema: every command a client may call, with signatures - ready to be turned into types by an extension."""
import hashlib
import json

from bridge.banker import realm_store
from bridge.core import address, clients
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.server import url_env
from bridge.subservices.bridge_express.types import BASIC_TYPES, CONTAINER_TYPES

# Raise when the notation or the layout of the schema changes, so extensions can check if they understand it
NOTATION_VERSION = 1
UNREACHABLE = (Exceptions.REMOTE_SERVER_ERROR, Exceptions.SERVER_NOT_TRUSTED, Exceptions.SERVER_STARTING)


def _commands(catalog):
    commands = []
    for name in sorted(catalog):
        entry = catalog[name]
        commands.append({
            "name": name,
            "descriptions": list(entry.get("descriptions") or []),
            "hosts": entry.get("hosts", 0),
            "signature": entry.get("signature"),
        })
    return commands


async def _realm_entry(caller_ip, realm_address):
    """(entry, source, stale) for one realm, or None if the client cannot see it."""
    # Late imports: realm modules import a lot, the schema is only built on request
    from bridge.realm import service as realm_service, sync as realm_sync
    server_url, realm_id = address.split_address(realm_address)
    if server_url == url_env.base_root:
        realm = realm_store.get_realm(realm_id)
        if realm is None:
            return None
        catalog = realm.list_commands(caller_ip)
        if is_exception(catalog):
            return None
        return {"realm_address": realm_address, "name": realm.name, "realm_type": str(realm.realm_type),
                "commands": _commands(catalog)}, "local", False
    view, _ = realm_sync.member_view(realm_address, caller_ip)
    if view is not None and not realm_sync.is_stale(realm_address):
        return {"realm_address": realm_address, "name": view["name"], "realm_type": view["realm_type"],
                "commands": _commands(realm_sync.mirror_catalog(realm_address, caller_ip))}, "mirror", False
    catalog = await realm_service.execute(caller_ip, realm_address, "list_commands", {})
    if catalog in UNREACHABLE and view is not None:
        return {"realm_address": realm_address, "name": view["name"], "realm_type": view["realm_type"],
                "commands": _commands(realm_sync.mirror_catalog(realm_address, caller_ip))}, "mirror", True
    if is_exception(catalog) or not isinstance(catalog, dict):
        return None
    return {"realm_address": realm_address, "name": view["name"] if view else None,
            "realm_type": view["realm_type"] if view else None, "commands": _commands(catalog)}, "realm_server", False


async def build_schema(client_key, realm_address=None, if_version=None):
    from bridge.realm import service as realm_service
    caller_ip = clients.get_client_ip(client_key)
    if caller_ip is None:
        return Exceptions.CLIENT_NOT_FOUND
    if realm_address is not None:
        realm_addresses = [realm_address]
    else:
        realm_addresses = [realm_service.get_public_realm_address()] + clients.get_realm_memberships(client_key)
        realm_addresses = sorted(dict.fromkeys(a for a in realm_addresses if a))
    realms = []
    sources = {}
    for current in realm_addresses:
        result = await _realm_entry(caller_ip, current)
        if result is None:
            continue
        entry, source, stale = result
        realms.append(entry)
        sources[current] = {"source": source, "stale": stale}
    # The version only depends on the content: same commands and signatures -> same version
    version = hashlib.sha256(json.dumps(realms, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]
    if if_version is not None and if_version == version:
        return {"changed": False, "version": version}
    for entry in realms:
        entry.update(sources[entry["realm_address"]])
    return {
        "changed": True,
        "version": version,
        "notation_version": NOTATION_VERSION,
        "notation": {
            "basic": list(BASIC_TYPES),
            "containers": list(CONTAINER_TYPES),
            "object": "{name: T, level?: T}",
            "union": "T | U",
            "literal": '"text"',
        },
        "args": "With a signature, command_args are an object with the parameter names, e.g. {\"a\": 1, \"b\": 2}.",
        "realms": realms,
    }
