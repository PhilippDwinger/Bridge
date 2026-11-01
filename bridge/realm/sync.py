"""Realm sync: realm states are the same on every server that has members in the realm.

- The server a realm lives on is the only truth. Only it checks permissions and changes the realm.
- Every realm has a version that goes up with every change.
- After a change the realm server tells every server with members right away (push, server to server).
  Those servers keep a copy ("mirror"): a view made only for them - their own members with roles,
  their catalog and their topics. Access keys and invitation codes are never in a mirror.
- Every realm_sync_seconds the member servers also compare the versions and fetch what they missed
  (e.g. after being offline). If the realm server is not reachable, the mirror is marked as stale.
- Clients are never pushed to: they see the result when they ask (/client/me, /realm/commands, /realm/info).
"""
import asyncio
import datetime
import secrets

from bridge import errors
from bridge.banker import client_key_store, mirror_store, realm_store, trust_store
from bridge.core import address, clients, protocol
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.server import runtime, s2s_client, url_env

# Changes the mirrors. Codes and access keys are left out - they are never in a mirror.
MUTATING_ACTIONS = {
    "join", "leave", "kick", "transfer_ownership", "create_command", "remove_command",
    "subscribe", "unsubscribe", "create_role", "set_member_roles",
}

# Random per server start. With it a member server knows that a lower version is not old but comes
# from a realm server that restarted (e.g. restored an older backup).
INSTANCE = secrets.token_hex(8)

# realm_id -> server URLs that need a push
_dirty = {}
_flush_scheduled = False
state = {"last_sync": None, "last_error": None}


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


# Mirrors we removed: realm_address -> (instance, version) - so a late old push cannot bring them back
_tombstones = {}


# region realm server side
def member_servers(realm):
    """Other servers that have members in the realm."""
    servers = {address.server_of(ip) for ip in realm.members}
    servers.discard(url_env.base_root)
    servers.discard(None)
    return servers

def local_members(realm):
    return {ip for ip in realm.members if address.server_of(ip) == url_env.base_root}

def before_change(realm):
    """Call before a change, pass the result to realm_changed()."""
    return member_servers(realm), local_members(realm)

def realm_changed(realm, before):
    """A realm of this server changed: new version, local memberships, push to the member servers."""
    global _flush_scheduled
    before_servers, before_local = before
    realm.version += 1
    _update_local_memberships(realm.address, before_local, local_members(realm))
    targets = before_servers | member_servers(realm)
    if targets:
        _dirty.setdefault(realm.realm_id, set()).update(targets)
        if not _flush_scheduled and runtime.schedule(_flush()):
            _flush_scheduled = True

def view_for_server(realm, server_url):
    """What a server may know about a realm: its own members and what they may see."""
    group_keys = {}
    catalogs = {}
    members = {}
    for ip, entry in realm.members.items():
        if address.server_of(ip) != server_url:
            continue
        # Members with the same rights see the same catalog - it is sent only once
        group = ("owner" if realm.is_owner(ip) else "member") + "|" + ",".join(sorted(entry["roles"]))
        if group not in group_keys:
            group_keys[group] = f"g{len(group_keys)}"
            catalog = realm.list_commands(ip)
            catalogs[group_keys[group]] = catalog if not is_exception(catalog) else {}
        members[ip] = {
            "roles": list(entry["roles"]),
            "catalog": group_keys[group],
            "topics": [topic for topic, subscribers in realm.topics.items() if ip in subscribers],
            "joined_at": entry["joined_at"].isoformat(),
        }
    return {
        "realm_address": realm.address,
        "realm_type": str(realm.realm_type),
        "name": realm.name,
        "owner_ip": realm.owner_ip,
        "version": realm.version,
        "instance": INSTANCE,
        "member_count": len(realm.members),
        "commands": {name: len(hosts) for name, hosts in realm.commands.items()},
        "topics": {topic: len(subscribers) for topic, subscribers in realm.topics.items()},
        "catalogs": catalogs,
        "members": members,
        "generated_at": _now().isoformat(),
    }

def _realm_for(realm_address, asking_server):
    """Our realm, but only for a server that has members in it - other servers learn nothing about it
    (not even that it exists)."""
    server, realm_id = address.split_address(realm_address)
    realm = realm_store.get_realm(realm_id) if server == url_env.base_root else None
    if realm is None or asking_server not in member_servers(realm):
        return None
    return realm

def versions_for(realm_addresses, asking_server):
    """Answer for a member server: {address: {"version", "instance"} or None (does not exist / no members there)}."""
    result = {}
    for realm_address in realm_addresses:
        realm = _realm_for(realm_address, asking_server)
        result[realm_address] = {"version": realm.version, "instance": INSTANCE} if realm else None
    return result

def mirror_for(realm_address, server_url):
    realm = _realm_for(realm_address, server_url)
    if realm is None:
        return None
    return view_for_server(realm, server_url)

async def _flush():
    global _flush_scheduled
    try:
        # Many changes in a short time (e.g. many joins) become one push
        await asyncio.sleep(protocol.realm_push_delay_seconds)
    finally:
        _flush_scheduled = False
    dirty = dict(_dirty)
    _dirty.clear()
    pushes = []
    for realm_id, targets in dirty.items():
        realm = realm_store.get_realm(realm_id)
        if realm is None:
            continue
        for server_url in targets:
            if _is_connected(server_url):
                pushes.append(_push(server_url, view_for_server(realm, server_url)))
    if pushes:
        await asyncio.gather(*pushes)

async def _push(server_url, view):
    result = await s2s_client.realm_push(server_url, view)
    if is_exception(result):
        # Not bad: the member server fetches the change itself with the next sync
        errors.debug_print(f"Realm push to {server_url} failed - it will sync itself")

async def push_all_to(server_url):
    """After a (re)connect: send the server the views of all our realms it has members in."""
    pushes = [_push(server_url, view_for_server(realm, server_url))
              for realm in list(realm_store.realm_storage.values()) if server_url in member_servers(realm)]
    if pushes:
        await asyncio.gather(*pushes)
# endregion realm server side


# region member server side
def _is_connected(server_url):
    entry = trust_store.trusted_servers.get(server_url)
    return entry is not None and entry["status"] == trust_store.STATUS_CONNECTED

def _set_membership(client_ip, realm_address, member):
    client_key = clients.get_client_key_from_ip(client_ip)
    if client_key is None:
        return
    if member:
        clients.add_realm_membership(client_key, realm_address)
    else:
        clients.remove_realm_membership(client_key, realm_address)

def _update_local_memberships(realm_address, before, after):
    for client_ip in before - after:
        _set_membership(client_ip, realm_address, False)
    for client_ip in after - before:
        _set_membership(client_ip, realm_address, True)

def _clients_with_realm(realm_address):
    return {entry["client_ip"] for entry in client_key_store.client_key_storage.values()
            if realm_address in entry.get("realms", []) and entry.get("client_ip")}

def _valid_view(view):
    """The view comes from another server - only well-formed views are stored (they are shown to our clients)."""
    if not isinstance(view, dict):
        return False
    texts = ("realm_address", "realm_type", "name", "instance")
    if any(not isinstance(view.get(key), str) for key in texts) or not isinstance(view.get("version"), int):
        return False
    if view.get("owner_ip") is not None and not isinstance(view["owner_ip"], str):
        return False
    if not isinstance(view.get("member_count"), int) or not all(isinstance(view.get(key), dict) for key in ("commands", "topics", "catalogs", "members")):
        return False
    for ip, member in view["members"].items():
        if (not isinstance(ip, str) or not isinstance(member, dict) or not isinstance(member.get("roles"), list)
                or not isinstance(member.get("topics"), list) or not isinstance(member.get("catalog"), str)
                or member["catalog"] not in view["catalogs"]):
            return False
    return all(isinstance(catalog, dict) and all(isinstance(entry, dict) for entry in catalog.values())
               for catalog in view["catalogs"].values())


def apply_view(view, source_url, authoritative=False):
    """Stores the view of a realm server and updates the memberships of our clients.
    authoritative: the view was fetched by the sync, so it is the current truth even if the version is lower."""
    if not _valid_view(view):
        errors.handle_error(Exceptions.ARGUMENT_ERROR, f"{source_url} sent a malformed realm view")
        return Exceptions.ARGUMENT_ERROR
    realm_address = view.get("realm_address")
    if address.server_of(realm_address) != source_url or source_url == url_env.base_root:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"{source_url} sent a realm view for a realm of another server")
        return Exceptions.NOT_ALLOWED
    stored = mirror_store.get_mirror(realm_address)
    if stored and not authoritative:
        old = stored["view"]
        if old.get("instance") == view.get("instance") and view.get("version", 0) < old.get("version", 0):
            return True  # an older push that arrived late
    gone = _tombstones.get(realm_address)
    if not stored and not authoritative and gone and gone[0] == view.get("instance") and view.get("version", 0) <= gone[1]:
        return True  # a late push from before our clients left - it must not bring the mirror back
    before = set(stored["view"]["members"]) if stored else _clients_with_realm(realm_address)
    after = {ip for ip in view["members"] if address.server_of(ip) == url_env.base_root}
    view = dict(view, members={ip: entry for ip, entry in view["members"].items() if ip in after})
    _update_local_memberships(realm_address, before, after)
    if after:
        mirror_store.set_mirror(realm_address, view, source_url)
        _tombstones.pop(realm_address, None)
    else:
        mirror_store.remove_mirror(realm_address)
        _remember_gone(realm_address, view.get("instance"), view.get("version", 0))
    return True

def _remember_gone(realm_address, instance, version):
    if len(_tombstones) > 10000:
        _tombstones.clear()
    _tombstones[realm_address] = (instance, version)

def realm_gone(realm_address):
    """The realm server says the realm does not exist anymore."""
    stored = mirror_store.get_mirror(realm_address)
    _update_local_memberships(realm_address, _clients_with_realm(realm_address), set())
    mirror_store.remove_mirror(realm_address)
    if stored:
        _remember_gone(realm_address, stored["view"].get("instance"), stored["view"].get("version", 0))

def _remote_realms():
    """All realms on other servers our clients are in (from the mirrors and the memberships)."""
    realms = set(mirror_store.addresses())
    for entry in client_key_store.client_key_storage.values():
        for realm_address in entry.get("realms", []):
            if address.server_of(realm_address) not in (url_env.base_root, None):
                realms.add(realm_address)
    return realms

async def sync_server(server_url, realm_addresses=None):
    """Compares the versions with one realm server and fetches what changed."""
    if realm_addresses is None:
        realm_addresses = [realm for realm in _remote_realms() if address.server_of(realm) == server_url]
    if not realm_addresses or not _is_connected(server_url):
        return
    versions = await s2s_client.realm_versions(server_url, realm_addresses)
    if is_exception(versions) or not isinstance(versions, dict):
        state["last_error"] = f"{server_url}: {getattr(versions, 'name', versions)}"
        return
    for realm_address in realm_addresses:
        if realm_address not in versions:
            continue
        remote = versions[realm_address]
        if remote is None:
            realm_gone(realm_address)
            continue
        stored = mirror_store.get_mirror(realm_address)
        if (stored and stored["view"].get("version") == remote.get("version")
                and stored["view"].get("instance") == remote.get("instance")):
            mirror_store.touch(realm_address)
            continue
        view = await s2s_client.realm_mirror(server_url, realm_address)
        if isinstance(view, dict) and view.get("found") is False:
            realm_gone(realm_address)
        elif isinstance(view, dict):
            apply_view(view, server_url, authoritative=True)

async def sync_all():
    by_server = {}
    for realm_address in _remote_realms():
        by_server.setdefault(address.server_of(realm_address), []).append(realm_address)
    if by_server:
        await asyncio.gather(*(sync_server(server_url, realms) for server_url, realms in by_server.items()))
    state["last_sync"] = _now()

async def on_connected(server_url):
    """A trusted server is (again) connected: exchange the realm states right away."""
    await asyncio.gather(sync_server(server_url), push_all_to(server_url))

async def run():
    """The servers keep talking: compare the realm versions regularly."""
    from bridge.core import backup
    while True:
        await asyncio.sleep(protocol.realm_sync_seconds)
        if not backup.is_ready():
            continue
        try:
            await sync_all()
        except Exception as error:
            state["last_error"] = repr(error)
            errors.handle_error(Exceptions.FAILED, f"Realm sync failed: {error!r}")
# endregion member server side


# region reading
def is_stale(realm_address):
    entry = mirror_store.get_mirror(realm_address)
    if entry is None:
        return True
    too_old = _now() - entry["synced_at"] > datetime.timedelta(seconds=protocol.realm_stale_seconds)
    return too_old or not _is_connected(entry["source"])

def member_view(realm_address, client_ip):
    """(view, member entry) of a mirror, or (None, None) if this client is not in it."""
    entry = mirror_store.get_mirror(realm_address)
    if entry is None or client_ip not in entry["view"]["members"]:
        return None, None
    return entry["view"], entry["view"]["members"][client_ip]

def mirror_catalog(realm_address, client_ip):
    view, member = member_view(realm_address, client_ip)
    if view is None:
        return None
    return view["catalogs"].get(member["catalog"], {})

def mirror_info(realm_address, client_ip):
    """Realm info from the mirror - used when the realm server cannot be reached."""
    view, member = member_view(realm_address, client_ip)
    if view is None:
        return None
    return {
        "realm_address": realm_address,
        "realm_type": view["realm_type"],
        "name": view["name"],
        "owner_ip": view["owner_ip"],
        "is_owner": view["owner_ip"] == client_ip,
        "is_member": True,
        "member_count": view["member_count"],
        "commands": dict(view["commands"]),
        "topics": dict(view["topics"]),
        "my_topics": list(member["topics"]),
        "my_roles": list(member["roles"]),
        "version": view["version"],
        "from_mirror": True,
        "stale": is_stale(realm_address),
    }

def realm_details(realm_addresses):
    """For /client/me: name, type, version and whether the state is up to date."""
    details = {}
    for realm_address in realm_addresses:
        server_url, realm_id = address.split_address(realm_address)
        if server_url == url_env.base_root:
            realm = realm_store.get_realm(realm_id)
            if realm is not None:
                details[realm_address] = {"name": realm.name, "realm_type": str(realm.realm_type),
                                          "version": realm.version, "local": True, "stale": False}
            continue
        entry = mirror_store.get_mirror(realm_address)
        if entry is None:
            details[realm_address] = {"local": False, "stale": True}
        else:
            view = entry["view"]
            details[realm_address] = {"name": view["name"], "realm_type": view["realm_type"],
                                      "version": view["version"], "local": False, "stale": is_stale(realm_address)}
    return details

def status():
    return {
        "mirrors": len(mirror_store.mirror_storage),
        "stale_mirrors": sum(1 for realm_address in mirror_store.addresses() if is_stale(realm_address)),
        "sync_seconds": protocol.realm_sync_seconds,
        "last_sync": state["last_sync"].isoformat() if state["last_sync"] else None,
        "last_error": state["last_error"],
    }
# endregion reading
