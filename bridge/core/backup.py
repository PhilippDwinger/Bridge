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
from bridge.banker import (client_key_store, ip_store, mailbox_store, realm_store, session_store, task_store,
                           trust_store)
from bridge.core import protocol
from bridge.errors.exceptions import Exceptions, is_exception
from bridge.server import s2s_client, url_env

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # backup is optional - Bridge runs without it
    AESGCM = None

BACKUP_VERSION = 1
KEY_ITERATIONS = 300_000

_key = None
# What happened - shown by /admin/backup/status
state = {
    "restore_done": False,
    "last_backup_at": None,
    "last_backup_size": None,
    "last_backup_peers": [],
    "last_restore": None,
    "last_error": None,
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
# endregion key


# region snapshot
def create_snapshot():
    """Everything in RAM as JSON-ready data."""
    clients = {}
    for client_key, entry in client_key_store.client_key_storage.items():
        clients[client_key] = {key: _iso(value) for key, value in entry.items()}
    mailboxes = {}
    for client_key, mailbox in mailbox_store.mailbox_storage.items():
        pools = {}
        for pool_name in mailbox.POLL_ORDER:
            pools[str(pool_name)] = [message.to_dict() for message in mailbox._get_pool(pool_name)]
        # Pending messages go back into their pool on restore (the client fetches them again)
        for entry in mailbox.pending_messages.values():
            pools.setdefault(str(entry["pool_name"]), []).insert(0, entry["message"].to_dict())
        mailboxes[client_key] = pools
    return {
        "version": BACKUP_VERSION,
        "server_url": url_env.base_root,
        "created_at": _now().isoformat(),
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
    associated = f"{snapshot['server_url']}|{created_at}".encode("utf-8")
    encrypted = AESGCM(_key).encrypt(nonce, data, associated)
    return {
        "version": BACKUP_VERSION,
        "server_url": snapshot["server_url"],
        "created_at": created_at,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "data": base64.b64encode(encrypted).decode("ascii"),
    }


def decrypt(blob):
    if AESGCM is None or _key is None:
        return Exceptions.FAILED
    try:
        associated = f"{blob['server_url']}|{blob['created_at']}".encode("utf-8")
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
async def backup_now(force=False):
    """Sends the current snapshot to every connected trusted server that does not have it yet."""
    if not available():
        state["last_error"] = "cryptography is not installed (pip install cryptography)"
        return Exceptions.FAILED
    peers = _connected_peers()
    if not peers:
        return {"sent_to": [], "size_bytes": 0}
    snapshot = create_snapshot()
    digest = hashlib.sha256(json.dumps({key: value for key, value in snapshot.items() if key != "created_at"},
                                       sort_keys=True, default=str).encode("utf-8")).hexdigest()
    targets = [peer for peer in peers
               if force or _sent_to.get(peer["url"]) != (digest, peer["connected_at"])]
    if not targets:
        return {"sent_to": [], "size_bytes": state["last_backup_size"] or 0, "unchanged": True}
    blob = encrypt(snapshot)
    if is_exception(blob):
        return blob
    size = blob_size(blob)
    if size > protocol.max_backup_mb * 1024 * 1024:
        state["last_error"] = f"Backup too large ({size} bytes)"
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
    newest = None
    for peer in _connected_peers():
        blob = await s2s_client.backup_fetch(peer["url"])
        if isinstance(blob, dict) and blob.get("server_url") == url_env.base_root:
            if newest is None or blob.get("created_at", "") > newest[1].get("created_at", ""):
                newest = (peer["url"], blob)
    if newest is None:
        result = {"restored": False, "reason": "no backup found"}
        state["last_restore"] = result
        return result
    snapshot = decrypt(newest[1])
    if is_exception(snapshot):
        state["last_restore"] = {"restored": False, "reason": "backup could not be decrypted"}
        return snapshot
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
            while loop.time() < deadline and not _connected_peers():
                await asyncio.sleep(0.5)
            if _connected_peers():
                await asyncio.sleep(1.5)  # give the other trusted servers a moment to connect too
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
            except Exception as error:
                state["last_error"] = f"backup: {error!r}"
                errors.handle_error(Exceptions.FAILED, f"Backup failed: {error!r}")


async def final_backup():
    """Last backup when the server shuts down normally."""
    if protocol.backup_mode == "peers" and state["restore_done"] and available():
        try:
            await asyncio.wait_for(backup_now(), 10)
        except Exception as error:
            errors.handle_error(Exceptions.FAILED, f"Final backup failed: {error!r}")


def status():
    from bridge.banker import backup_store
    return {
        "mode": protocol.backup_mode,
        "available": available(),
        "interval_seconds": protocol.backup_interval_seconds,
        **state,
        "stored_for_other_servers": backup_store.overview(),
    }
