"""Encrypted backup of everything in RAM at trusted servers.

- Bridge keeps nothing on disk. Instead it sends an encrypted snapshot to every connected trusted server
  (every protocol.backup_interval_seconds if something changed, and once more when it shuts down).
- The key comes from the Bridge password (PBKDF2), so the other servers can store the backup but never read it.
- After a (re)start the server asks its trusted servers for its newest backup and restores it - but only if
  it is still empty, so a running server is never overwritten by accident.
Mode: protocol.backup_mode = "peers" (default) or "off".
"""
import asyncio
import base64
import datetime
import hashlib
import json
import secrets
import zlib

from bridge import errors
from bridge.banker import (client_key_store, friend_store, ip_store, mailbox_store, realm_store, schedule_store,
                           session_store, status_store, task_store, trust_store)
from bridge.core import protocol
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.server import s2s_client, url_env
from bridge.subservices.bridge_agent import agent

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # backup is optional - Bridge runs without it
    AESGCM = None

BACKUP_VERSION = 2
KEY_ITERATIONS = 300_000

_key = None
# (peer_url, owner_url) -> highest epoch we already relayed to that peer (so we forward each copy only once)
_relayed = {}
# What happened - shown by /admin/backup/status
state = {
    "restore_done": False,
    "last_backup_at": None,
    "last_backup_size": None,
    "last_backup_peers": [],
    "last_restore": None,
    "last_error": None,
    # Set when own backups at the peers could not be read at the start - regular backups wait for an admin
    "paused": None,
    # The last backup was too big and was sent without the mailbox contents
    "without_messages": False,
}
# peer_url -> (digest of the last snapshot sent, connected_at of the peer at that time)
_sent_to = {}


def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def _iso(value):
    return value.isoformat() if isinstance(value, datetime.datetime) else value

def _parse(value):
    return datetime.datetime.fromisoformat(value) if isinstance(value, str) else value

def available():
    return AESGCM is not None


def is_ready():
    """False while the server is still trying to restore its backup after a start."""
    return state["restore_done"]


# region key
def set_password(password, server_url):
    """Derives the backup key from the Bridge password. Called by Bridge() and on password change."""
    global _key
    salt = f"bridge-backup|{server_url}".encode("utf-8")
    _key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, KEY_ITERATIONS, 32)
    _sent_to.clear()  # new key -> every peer gets a fresh backup
    _relayed.clear()
# endregion key


# region snapshot
def create_snapshot(include_messages=True):
    """Everything in RAM as JSON-ready data. include_messages=False: without mailbox contents (if it is too big)."""
    clients = {}
    for client_key, entry in client_key_store.client_key_storage.items():
        clients[client_key] = {key: _iso(value) for key, value in entry.items()}
    mailboxes = {}
    for client_key, mailbox in (mailbox_store.mailbox_storage.items() if include_messages else ()):
        pools = {}
        for pool_name in mailbox.POLL_ORDER:
            pools[str(pool_name)] = [message.to_dict() for message in mailbox._get_pool(pool_name)]
        # Pending messages go back into their pool on restore (the client fetches them again)
        for entry in mailbox.pending_messages.values():
            pools.setdefault(str(entry["pool_name"]), []).insert(0, entry["message"].to_dict())
        mailboxes[client_key] = pools
    now = _now()
    return {
        "version": BACKUP_VERSION,
        "server_url": url_env.base_root,
        "created_at": now.isoformat(),
        # Version counter of this server's backups. Climbs with the wall clock, so it keeps rising across restarts
        # and a newer backup always wins over an older one - also when it was relayed through other servers.
        "epoch": int(now.timestamp() * 1000),
        "clients": clients,
        "mailboxes": mailboxes,
        "sessions": {token: {key: _iso(value) for key, value in entry.items()}
                     for token, entry in session_store.session_storage.items()},
        "realms": [realm.to_state() for realm in realm_store.realm_storage.values()],
        "public_realm_id": realm_store.public_realm_id,
        "realm_codes": {code: {key: _iso(value) for key, value in entry.items()}
                        for code, entry in realm_store.realm_codes.items()},
        "outgoing_tasks": {task_id: {key: _iso(value) for key, value in entry.items()}
                           for task_id, entry in task_store.outgoing_tasks.items()},
        "incoming_tasks": {task_id: {key: _iso(value) for key, value in entry.items()}
                           for task_id, entry in task_store.incoming_tasks.items()},
        # What the BridgeAgent learned on this server (the whole snapshot is compressed and encrypted)
        "agent": agent.to_state() if agent.enabled() else None,
        # Planned messages - sent after a restore (late ones right away, with late_by_seconds)
        "scheduled": {message_id: {"client_key": entry["client_key"], "send_at": entry["send_at"].isoformat(),
                                   "message": entry["message"].to_dict(), "lifetime_seconds": entry["lifetime_seconds"],
                                   "default_lifetime": entry["default_lifetime"], "created_at": entry["created_at"].isoformat()}
                      for message_id, entry in schedule_store.scheduled.items()},
        # BridgeFriends: friendships, invitations (only the argon2 key, never a password), presence, block list
        "friends": friend_store.to_state(),
    }


def is_fresh():
    """A server that just started: no clients and only the default public realm."""
    return not client_key_store.client_key_storage and len(realm_store.realm_storage) <= 1


def restore_snapshot(snapshot):
    """Replaces the RAM state with the snapshot. Returns counts of what was restored."""
    from bridge.core.clients import DEFAULT_NAME
    from bridge.messenger.mailbox import Mailbox, PoolName
    from bridge.messenger.message import message_from_dict
    from bridge.realm import RealmType
    from bridge.realm.private import PrivateRealm
    from bridge.realm.protected import ProtectedRealm
    from bridge.realm.public import PublicRealm

    if snapshot.get("server_url") != url_env.base_root:
        errors.handle_error(Exceptions.NOT_ALLOWED, "The backup belongs to another server URL")
        return Exceptions.NOT_ALLOWED

    session_store.reset()
    mailbox_store.reset()
    ip_store.reset()
    client_key_store.reset()
    realm_store.reset()
    task_store.reset()

    for client_key, entry in snapshot["clients"].items():
        restored = {key: _parse(value) if key in ("created_at", "last_signal") else value for key, value in entry.items()}
        restored.setdefault("name", DEFAULT_NAME)
        restored.setdefault("realms", [])
        client_key_store.client_key_storage[client_key] = restored
        ip_store.ip_storage[restored["client_ip"]] = client_key
        mailbox_store.set_mailbox(client_key, Mailbox())

    restored_messages = 0
    dropped_messages = 0
    for client_key, pools in snapshot["mailboxes"].items():
        mailbox = mailbox_store.get_mailbox(client_key)
        if mailbox is None:
            continue
        for pool_name, messages in pools.items():
            for data in messages:
                message = message_from_dict(data)
                if is_exception(message):
                    dropped_messages += 1  # expired in the meantime
                    continue
                mailbox._insert_into_pool(message, PoolName(pool_name), ignore_limit=True)
                restored_messages += 1

    for token, entry in snapshot["sessions"].items():
        session_store.session_storage[token] = {key: _parse(value) if key != "client_key" else value
                                                for key, value in entry.items()}
    session_store.rebuild_index()

    classes = {RealmType.PUBLIC: PublicRealm, RealmType.PROTECTED: ProtectedRealm, RealmType.PRIVATE: PrivateRealm}
    for realm_state in snapshot["realms"]:
        realm_class = classes[RealmType(realm_state["realm_type"])]
        realm = realm_class(realm_state["realm_id"], realm_state["name"], realm_state["owner_ip"])
        realm.load_state(realm_state)
        realm_store.add_realm(realm)
    realm_store.set_public_realm_id(snapshot.get("public_realm_id"))

    for code, entry in snapshot["realm_codes"].items():
        realm_store.realm_codes[code] = {key: _parse(value) if key == "expires_at" else value for key, value in entry.items()}
    for task_id, entry in snapshot["outgoing_tasks"].items():
        task_store.outgoing_tasks[task_id] = {key: _parse(value) if key == "expires_at" else value for key, value in entry.items()}
    for task_id, entry in snapshot["incoming_tasks"].items():
        task_store.incoming_tasks[task_id] = {key: _parse(value) if key == "expires_at" else value for key, value in entry.items()}
    task_store.rebuild_counts()
    if snapshot.get("agent"):
        agent.load_state(snapshot["agent"])
    schedule_store.reset()
    for message_id, entry in (snapshot.get("scheduled") or {}).items():
        planned = message_from_dict(entry["message"])
        if is_exception(planned) or entry["client_key"] not in client_key_store.client_key_storage:
            continue
        # Our own planned message: its lifetime may be longer than what we accept from other servers
        planned.expires_at = _parse(entry["message"]["expires_at"])
        schedule_store.add(message_id, {"client_key": entry["client_key"], "send_at": _parse(entry["send_at"]),
                                        "message": planned, "lifetime_seconds": entry.get("lifetime_seconds"),
                                        "default_lifetime": entry.get("default_lifetime", True),
                                        "created_at": _parse(entry["created_at"])})
        status_store.remember_scheduled(planned)

    if "friends" in snapshot:
        friend_store.load_state(snapshot["friends"])

    return {
        "clients": len(client_key_store.client_key_storage),
        "messages": restored_messages,
        "expired_messages": dropped_messages,
        "realms": len(realm_store.realm_storage),
        "sessions": len(session_store.session_storage),
    }
# endregion snapshot


# region encryption
def encrypt(snapshot):
    if AESGCM is None or _key is None:
        return Exceptions.FAILED
    data = zlib.compress(json.dumps(snapshot, separators=(",", ":")).encode("utf-8"), 6)
    nonce = secrets.token_bytes(12)
    created_at = snapshot["created_at"]
    epoch = int(snapshot.get("epoch", 0))
    associated = _aad(snapshot["server_url"], created_at, epoch, BACKUP_VERSION)
    encrypted = AESGCM(_key).encrypt(nonce, data, associated)
    return {
        "version": BACKUP_VERSION,
        "server_url": snapshot["server_url"],
        "created_at": created_at,
        "epoch": epoch,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "data": base64.b64encode(encrypted).decode("ascii"),
    }


def _aad(server_url, created_at, epoch, version):
    # The authenticated header. Version 1 backups (no epoch) used only server_url|created_at.
    if version >= 2:
        return f"{server_url}|{created_at}|{epoch}|v{version}".encode("utf-8")
    return f"{server_url}|{created_at}".encode("utf-8")


def decrypt(blob):
    if AESGCM is None or _key is None:
        return Exceptions.FAILED
    # A newer server must still be able to read an older backup of itself (rolling upgrade): try the header of the
    # blob's own version.
    try:
        version = int(blob.get("version", 1))
        associated = _aad(blob["server_url"], blob["created_at"], int(blob.get("epoch", 0)), version)
        data = AESGCM(_key).decrypt(base64.b64decode(blob["nonce"]), base64.b64decode(blob["data"]), associated)
        return json.loads(zlib.decompress(data).decode("utf-8"))
    except Exception as error:
        errors.handle_error(Exceptions.NOT_ALLOWED, f"Backup could not be decrypted (other password?): {type(error).__name__}")
        return Exceptions.NOT_ALLOWED


def blob_size(blob):
    return len(blob.get("data", "")) + len(blob.get("nonce", ""))
# endregion encryption


def _connected_peers():
    return [server for server in trust_store.list_servers() if server["status"] == trust_store.STATUS_CONNECTED]


# region backup
def _digest(snapshot):
    return hashlib.sha256(json.dumps({key: value for key, value in snapshot.items() if key != "created_at"},
                                     sort_keys=True, default=str).encode("utf-8")).hexdigest()


async def backup_now(force=False):
    """Sends the current snapshot to every connected trusted server that does not have it yet."""
    if not available():
        state["last_error"] = "cryptography is not installed (pip install cryptography)"
        return Exceptions.FAILED
    if state.get("paused") and not force:
        # Own backups at the peers could not be read at the start - they are not overwritten automatically
        return {"sent_to": [], "size_bytes": 0, "paused": state["paused"]}
    state["paused"] = None
    peers = _connected_peers()
    if not peers:
        return {"sent_to": [], "size_bytes": 0}
    snapshot = create_snapshot()
    # Hashing, packing and encrypting run in a thread - the server keeps answering meanwhile
    digest = await asyncio.to_thread(_digest, snapshot)
    targets = [peer for peer in peers
               if force or _sent_to.get(peer["url"]) != (digest, peer["connected_at"])]
    if not targets:
        return {"sent_to": [], "size_bytes": state["last_backup_size"] or 0, "unchanged": True}
    blob = await asyncio.to_thread(encrypt, snapshot)
    if is_exception(blob):
        return blob
    size = blob_size(blob)
    state["without_messages"] = False
    if size > protocol.max_backup_mb * 1024 * 1024:
        # Too big (e.g. one client keeps huge messages): better a backup of everything else than none at all
        blob = await asyncio.to_thread(encrypt, create_snapshot(include_messages=False))
        if is_exception(blob):
            return blob
        size = blob_size(blob)
        state["without_messages"] = True
        errors.handle_error(Exceptions.FAILED, "Backup too large - sent without the mailbox contents")
        if size > protocol.max_backup_mb * 1024 * 1024:
            state["last_error"] = f"Backup too large even without messages ({size} bytes)"
            errors.handle_error(Exceptions.FAILED, state["last_error"])
            return Exceptions.FAILED
    sent_to = []
    for peer in targets:
        result = await s2s_client.backup_store(peer["url"], blob)
        if result is True:
            _sent_to[peer["url"]] = (digest, peer["connected_at"])
            sent_to.append(peer["url"])
        else:
            state["last_error"] = f"{peer['url']}: {getattr(result, 'name', result)}"
    if sent_to:
        state["last_backup_at"] = _now().isoformat()
        state["last_backup_size"] = size
        state["last_backup_peers"] = sorted(set(state["last_backup_peers"]) | set(sent_to))
        errors.debug_print(f"Backup ({size} bytes) sent to {len(sent_to)} server(s)")
    return {"sent_to": sent_to, "size_bytes": size}
async def relay_held_backups():
    """Spreads the backups we keep for OTHER servers to our other trusted peers, so a backup survives even when the
    server that first kept it goes down (A -> B, B relays A's backup to C; if B closes, C still has it and A gets it
    back from C). Each copy is forwarded to a peer only once per epoch. The owner itself is never a target - it does
    not keep its own backup."""
    if not available():
        return
    from bridge.banker import backup_store
    held = backup_store.held_backups()
    if not held:
        return
    peers = [peer["url"] for peer in _connected_peers()]
    for owner_url, blob, size, epoch in held:
        for peer_url in peers:
            if peer_url == owner_url:
                continue  # never give a server its own backup to keep
            if _relayed.get((peer_url, owner_url), -1) >= epoch:
                continue  # that peer already got this (or a newer) copy from us
            result = await s2s_client.backup_relay(peer_url, blob)
            if result is True:
                _relayed[(peer_url, owner_url)] = epoch
    if len(_relayed) > 100_000:
        _relayed.clear()
# endregion backup


# region restore
async def restore_from_peers(only_if_fresh=True):
    """Fetches the newest own backup from the connected trusted servers and restores it."""
    if not available():
        return Exceptions.FAILED
    if only_if_fresh and not is_fresh():
        result = {"restored": False, "reason": "server already has data"}
        state["last_restore"] = result
        return result
    found = []
    unanswered = []
    for peer in _connected_peers():
        blob = None
        for attempt in range(3):
            blob = await s2s_client.backup_fetch(peer["url"])
            if not is_exception(blob):
                break
            await asyncio.sleep(1)
        if is_exception(blob):
            # Not the same as "no backup there": the peer may hold our newest backup
            unanswered.append(peer["url"])
        elif isinstance(blob, dict) and blob.get("server_url") == url_env.base_root and isinstance(blob.get("created_at"), str):
            found.append((peer["url"], blob))
    if not found:
        if unanswered:
            # Do not overwrite a backup we could not see with an empty server - an admin decides
            state["paused"] = f"could not ask {', '.join(unanswered)} for our backup - /admin/backup/now resumes backups"
            result = {"restored": False, "reason": state["paused"]}
            errors.handle_error(Exceptions.FAILED, state["paused"])
        else:
            result = {"restored": False, "reason": "no backup found"}
        state["last_restore"] = result
        return result
    # Newest first (by epoch, then date) - if one cannot be read (broken, other password, a peer lying about the
    # date/epoch), the next one is tried.
    found.sort(key=lambda item: (int(item[1].get("epoch", 0)), item[1]["created_at"]), reverse=True)
    newest, snapshot = None, None
    for peer_url, blob in found:
        candidate = await asyncio.to_thread(decrypt, blob)
        if not is_exception(candidate) and isinstance(candidate, dict):
            newest, snapshot = (peer_url, blob), candidate
            break
    if snapshot is None:
        # Do not overwrite these backups with an empty server - an admin decides (/admin/backup/now resumes)
        state["paused"] = "own backups were found at the peers but none could be read (password changed?)"
        state["last_restore"] = {"restored": False, "reason": state["paused"]}
        errors.handle_error(Exceptions.FAILED, state["paused"])
        return Exceptions.FAILED
    counts = restore_snapshot(snapshot)
    if is_exception(counts):
        return counts
    result = {"restored": True, "from": newest[0], "backup_created_at": snapshot["created_at"], **counts}
    state["last_restore"] = result
    errors.debug_print(f"Restored backup from {newest[0]}: {counts}")
    return result
# endregion restore


async def run():
    """Started with the server: restore once, then back up regularly."""
    try:
        if protocol.backup_mode == "peers" and available() and trust_store.list_servers():
            loop = asyncio.get_running_loop()
            deadline = loop.time() + protocol.backup_restore_wait_seconds
            # Wait for all trusted servers (any of them may hold the newest backup), at most the wait time
            while loop.time() < deadline and len(_connected_peers()) < len(trust_store.list_servers()):
                await asyncio.sleep(0.5)
            if _connected_peers():
                await restore_from_peers(only_if_fresh=True)
    except Exception as error:
        state["last_error"] = f"restore: {error!r}"
        errors.handle_error(Exceptions.FAILED, f"Restore at start failed: {error!r}")
    finally:
        # Only now regular backups may start - otherwise an empty fresh server could overwrite its own backup
        state["restore_done"] = True
    while True:
        await asyncio.sleep(protocol.backup_interval_seconds)
        if protocol.backup_mode == "peers":
            try:
                await backup_now()
                await relay_held_backups()
            except Exception as error:
                state["last_error"] = f"backup: {error!r}"
                errors.handle_error(Exceptions.FAILED, f"Backup failed: {error!r}")


async def final_backup():
    """Last backup when the server shuts down normally."""
    if protocol.backup_mode == "peers" and state["restore_done"] and available() and not state.get("paused"):
        try:
            await asyncio.wait_for(backup_now(), 10)
            # Hand the backups we keep for others on to another peer before we go, so they are not lost with us
            await asyncio.wait_for(relay_held_backups(), 10)
        except Exception as error:
            errors.handle_error(Exceptions.FAILED, f"Final backup failed: {error!r}")


def update_ready():
    """Is it safe to restart this server for a code update right now? Only when a connected trusted peer already
    holds our current data, so the restart (RAM is wiped) loses nothing. The auto-updater checks this before it
    pulls a new commit and restarts the process."""
    if not is_ready():
        return {"ready": False, "reason": "server is still starting / restoring"}
    if state.get("paused"):
        return {"ready": False, "reason": state["paused"]}
    has_data = bool(client_key_store.client_key_storage) or len(realm_store.realm_storage) > 1
    peers = {peer["url"] for peer in _connected_peers()}
    if not has_data:
        return {"ready": True, "reason": "no data to lose", "connected_peers": sorted(peers)}
    if not peers:
        return {"ready": False, "reason": "data present but no connected trusted peer to hold it"}
    holding = sorted(peers.intersection(_sent_to.keys()))
    if not holding:
        return {"ready": False, "reason": "data not backed up to a connected peer yet - call /admin/backup/now first"}
    return {"ready": True, "connected_peers": sorted(peers), "holding_backup": holding}


def status():
    from bridge.banker import backup_store
    return {
        "mode": protocol.backup_mode,
        "available": available(),
        "interval_seconds": protocol.backup_interval_seconds,
        **state,
        "stored_for_other_servers": backup_store.overview(),
    }
