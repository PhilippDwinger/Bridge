"""Invitations of BridgeFriends ("doors").

A door is either
- a **name** (memorable, e.g. "paddy-home"): lives until it is deleted, a password is required, or
- a **code** (random, 8 characters like realm codes): expires (default 60 min), used once, password optional.
Its address is "<name or code>@<server>" - e.g. paddy-home@bridge.example.com.

The password never leaves the server of the client that typed it:
  The server of the door keeps only K0 = argon2id(password, salt). Who wants to come in first gets a challenge
  (nonce + salt). Its own server computes K0 from the typed password, picks its own random client_nonce and computes
      K1    = argon2id(K0, salt2)   salt2 = sha256("bridge-friends-k1|<door server>|<door>|<asking client>|<client_nonce>")
      proof = HMAC-SHA256(K1, "bridge-friends-v2|<door server>|<door>|<asking client>|<nonce>|<client_nonce>")
  The door server computes K1 from its K0 and compares in constant time - once per challenge.
  A wrong server (typo in the address) only gets a proof it can check password guesses against with TWO argon2 per
  guess, and the second one depends on the asking server's random value - so it cannot precompute a dictionary.

Guessing is stopped per door key (also for keys that do not exist, so the answers look the same):
friend_attempts_per_client wrong proofs per asking client, friend_attempts_per_server per asking server
(other servers only - our own clients are counted one by one), friend_attempts_total_per_hour in total.
An unknown door answers like a wrong password (fake salt, same work, same lock), so nobody can find out which names exist.
"""
import asyncio
import datetime
import hashlib
import hmac
import re
import secrets
import time

from argon2.low_level import Type, hash_secret_raw

from bridge import errors
from bridge.banker import friend_store
from bridge.core import address, protocol
from bridge.core.jsoncheck import json_problem
from bridge.errors.exceptions import Exceptions
from bridge.security.generator import generate_key
from bridge.server import url_env

NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
# Sent with every challenge, so a later version can change it. "second": the step with the asking server's nonce.
KDF = {"name": "argon2id", "time_cost": 2, "memory_kib": 19456, "parallelism": 1, "length": 32, "version": 2,
       "second": {"time_cost": 1, "memory_kib": 8192}}
CHALLENGE_SECONDS = 60
MIN_PASSWORD = 6
MAX_PASSWORD = 128
MAX_LABEL = 64
MAX_DOOR_DAYS = 365
ACCEPT_MODES = ("auto", "manual")

# For fake salts / keys of unknown doors (new on every start - nobody can compare them over time)
_server_secret = secrets.token_bytes(32)
_challenges = {}
_hellos = {}
# door key -> [(monotonic, asking client, asking server)] and door key -> locked until (monotonic).
# Kept per key - also for keys without a door, so a lock does not tell that a name exists.
_fails = {}
_locked_until = {}
# argon2 needs CPU and memory: at most a few at the same time, the rest waits
_argon_slots = asyncio.Semaphore(4)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)

def _fail(error, problem):
    errors.handle_error(error, problem)
    errors.set_client_details(problems=[problem])
    return error


# region keys
def derive_key(password, salt_hex):
    """K0 = argon2id(password, salt). Takes ~30-60 ms - use derive_key_async."""
    return hash_secret_raw(password.encode("utf-8"), bytes.fromhex(salt_hex), time_cost=KDF["time_cost"],
                           memory_cost=KDF["memory_kib"], parallelism=KDF["parallelism"], hash_len=KDF["length"],
                           type=Type.ID)

def second_key(first_key, door_server, door_key, requester_ip, client_nonce):
    """K1 = argon2id(K0, salt2) - salt2 depends on the asking server's random client_nonce."""
    salt = hashlib.sha256(f"bridge-friends-k1|{door_server}|{door_key}|{requester_ip}|{client_nonce}"
                          .encode("utf-8")).digest()[:16]
    return hash_secret_raw(first_key, salt, time_cost=KDF["second"]["time_cost"], memory_cost=KDF["second"]["memory_kib"],
                           parallelism=KDF["parallelism"], hash_len=KDF["length"], type=Type.ID)

async def derive_key_async(password, salt_hex):
    async with _argon_slots:
        return await asyncio.to_thread(derive_key, password, salt_hex)

async def second_key_async(first_key, door_server, door_key, requester_ip, client_nonce):
    async with _argon_slots:
        return await asyncio.to_thread(second_key, first_key, door_server, door_key, requester_ip, client_nonce)

def proof_for(key, door_server, door_key, requester_ip, nonce, client_nonce):
    context = f"bridge-friends-v2|{door_server}|{door_key}|{requester_ip}|{nonce}|{client_nonce}".encode("utf-8")
    return hmac.new(key, context, hashlib.sha256).hexdigest()

def check_password(password, required):
    if password is None:
        password = ""
    if not isinstance(password, str) or len(password) > MAX_PASSWORD or json_problem(password):
        return _fail(Exceptions.ARGUMENT_ERROR, f"'password' must be a text with up to {MAX_PASSWORD} characters")
    if (required or password) and len(password) < MIN_PASSWORD:
        return _fail(Exceptions.ARGUMENT_ERROR, f"'password' needs at least {MIN_PASSWORD} characters")
    return password
# endregion keys


# region doors
def _looks_like_code(compact):
    alphabet = protocol.code_alphabet.lower()
    return len(compact) == protocol.code_length and all(char in alphabet for char in compact)

def typed_key(text):
    """The door text as typed (trimmed, lower case) - used in the challenge and the proof. It is the same whether the
    door exists or not, so the answer tells nothing."""
    if not isinstance(text, str) or json_problem(text):
        return None
    key = text.strip().lower()
    return key if 0 < len(key) <= 64 else None

def canonical(key):
    """Key for counting wrong passwords: codes typed with '-' or spaces (K7M3-XQ9P) count as the same door.
    Depends only on the text, never on whether a door exists."""
    compact = key.replace("-", "").replace(" ", "")
    return compact if _looks_like_code(compact) else key

def _usable(door):
    if door is None:
        return False
    if door["expires_at"] is not None and _now() >= door["expires_at"]:
        friend_store.remove_door(door["key"])
        return False
    return True

def find(text):
    """The door for a typed text: a name exactly, or a code also typed with '-' / spaces / small letters."""
    key = typed_key(text)
    if key is None:
        return None
    door = friend_store.doors.get(key)
    if not _usable(door):
        compact = key.replace("-", "").replace(" ", "")
        door = friend_store.doors.get(compact) if compact != key else None
        if door is not None and door["kind"] != "code":
            door = None
    return door if _usable(door) else None

def _new_code():
    alphabet = protocol.code_alphabet.lower()
    for _ in range(100):
        code = "".join(secrets.choice(alphabet) for _ in range(protocol.code_length))
        if code not in friend_store.doors:
            return code
    return None

def prepare(owner_ip, name=None, password=None, expires_at=None, max_uses=None, accept="auto", label=None):
    """Checks everything and returns (door without key material, password) or an exception.
    The caller computes the verifier (argon2) and stores it with add()."""
    if len(friend_store.doors_of(owner_ip)) >= protocol.max_friend_invites_per_client:
        return _fail(Exceptions.NOT_ALLOWED, f"a client can have at most {protocol.max_friend_invites_per_client} invitations")
    if accept not in ACCEPT_MODES:
        return _fail(Exceptions.ARGUMENT_ERROR, f"'accept' must be one of {', '.join(ACCEPT_MODES)}")
    if label is not None and (not isinstance(label, str) or len(label) > MAX_LABEL or json_problem(label)):
        return _fail(Exceptions.ARGUMENT_ERROR, f"'label' must be a text with up to {MAX_LABEL} characters")
    if max_uses is not None and (isinstance(max_uses, bool) or not isinstance(max_uses, int) or not 1 <= max_uses <= 1000):
        return _fail(Exceptions.ARGUMENT_ERROR, "'max_uses' must be a whole number between 1 and 1000")
    now = _now()
    if expires_at is not None:
        if expires_at <= now:
            return _fail(Exceptions.ALREADY_EXPIRED, "the invitation would already be expired")
        if expires_at > now + datetime.timedelta(days=MAX_DOOR_DAYS):
            return _fail(Exceptions.ARGUMENT_ERROR, f"an invitation can live at most {MAX_DOOR_DAYS} days")
    if name is not None:
        key = name.strip().lower() if isinstance(name, str) else ""
        if not NAME_PATTERN.match(key):
            return _fail(Exceptions.ARGUMENT_ERROR,
                         "'name' must have 3-32 characters: a-z, 0-9, '.', '_', '-' (starting with a letter or digit)")
        if key in friend_store.doors and _usable(friend_store.doors[key]):
            return _fail(Exceptions.ALREADY_EXISTS, f"the friend name {key!r} is already taken on this server")
        kind = "name"
    else:
        key = _new_code()
        if key is None:
            return Exceptions.FAILED
        kind = "code"
        if expires_at is None:
            expires_at = now + datetime.timedelta(minutes=protocol.friend_code_default_minutes)
        if max_uses is None:
            max_uses = 1
    password = check_password(password, required=kind == "name")
    if not isinstance(password, str):
        return password
    return {
        "invite_id": generate_key(12),
        "key": key,
        "kind": kind,
        "owner_ip": owner_ip,
        "label": label,
        "salt": secrets.token_hex(16),
        "verifier": None,
        "has_password": bool(password),
        "expires_at": expires_at,
        "max_uses": max_uses,
        "uses": 0,
        "accept": accept,
        "created_at": now,
    }, password

def add(door):
    # Checked again: while the key was computed, other requests of the same client may have added doors
    if len(friend_store.doors_of(door["owner_ip"])) >= protocol.max_friend_invites_per_client:
        return _fail(Exceptions.NOT_ALLOWED, f"a client can have at most {protocol.max_friend_invites_per_client} invitations")
    if door["key"] in friend_store.doors and _usable(friend_store.doors[door["key"]]):
        return _fail(Exceptions.ALREADY_EXISTS, f"the friend name {door['key']!r} is already taken on this server")
    friend_store.doors[door["key"]] = door
    # A (re)created door starts clean: the wrong-password counters live per name (module level), not in the door,
    # so without this a deleted-and-recreated invitation would stay locked for its owner and real friends.
    forget_key(door["key"])
    return door

def forget_key(door_key):
    """Drops the wrong-password counters/lock for a door name or code (used when a door is (re)created)."""
    counted = canonical(door_key)
    _fails.pop(counted, None)
    _locked_until.pop(counted, None)

def address_of(door):
    return f"{door['key'].upper() if door['kind'] == 'code' else door['key']}@{url_env.base_root}"

def describe(door):
    return {
        "invite_id": door["invite_id"],
        "kind": door["kind"],
        "name": door["key"] if door["kind"] == "name" else None,
        "code": door["key"].upper() if door["kind"] == "code" else None,
        "address": address_of(door),
        "label": door["label"],
        "has_password": door["has_password"],
        "accept": door["accept"],
        "expires_at": door["expires_at"].isoformat() if door["expires_at"] else None,
        "max_uses": door["max_uses"],
        "uses": door["uses"],
        "locked": _locked_until.get(canonical(door["key"]), 0) > time.monotonic(),
        "created_at": door["created_at"].isoformat(),
    }

def used(door):
    door["uses"] += 1
    if door["max_uses"] is not None and door["uses"] >= door["max_uses"]:
        friend_store.remove_door(door["key"])
# endregion doors


# region challenge / proof
def _fake(key, purpose):
    return hmac.new(_server_secret, f"{purpose}|{key}".encode("utf-8"), hashlib.sha256).hexdigest()

def _limit_key(requester_server, requester_ip):
    """Hellos are limited per other server - our own clients one by one (one client must not block all)."""
    return requester_ip if requester_server == url_env.base_root else address.server_key(requester_server)

def _hello_allowed(requester_server, requester_ip):
    key = _limit_key(requester_server, requester_ip)
    now = time.monotonic()
    times = [stamp for stamp in _hellos.get(key, []) if now - stamp < 60]
    if len(times) >= 60:
        _hellos[key] = times
        return False
    times.append(now)
    if len(_hellos) > 5000:
        _hellos.clear()
    _hellos[key] = times
    return True

def start(door_text, requester_server, requester_ip):
    """Challenge for somebody who wants to come in. Looks exactly the same for unknown doors."""
    key = typed_key(door_text)
    if key is None:
        return _fail(Exceptions.ARGUMENT_ERROR, "invalid friend address")
    if not _hello_allowed(requester_server, requester_ip):
        return _fail(Exceptions.TOO_MANY_ATTEMPTS, "too many friend requests - try again in a minute")
    door = find(key)
    now = time.monotonic()
    if len(_challenges) > 10000:
        for challenge_id in [cid for cid, entry in _challenges.items() if entry["expires"] < now]:
            del _challenges[challenge_id]
        if len(_challenges) > 10000:
            _challenges.clear()
    challenge_id = generate_key(16)
    nonce = generate_key(16)
    _challenges[challenge_id] = {"key": key, "door_key": door["key"] if door is not None else None, "nonce": nonce,
                                 "requester_server": requester_server, "requester_ip": requester_ip,
                                 "expires": now + CHALLENGE_SECONDS}
    return {"challenge_id": challenge_id, "door": key, "nonce": nonce,
            "salt": door["salt"] if door is not None else _fake(key, "salt")[:32], "kdf": dict(KDF)}

def _recent_fails(key, seconds):
    now = time.monotonic()
    fails = [fail for fail in _fails.get(key, []) if now - fail[0] < 3600]
    if fails:
        _fails[key] = fails
    else:
        _fails.pop(key, None)
    return [fail for fail in fails if now - fail[0] < seconds]

def _record_fail(key, requester_ip, requester_server):
    if len(_fails) > 20000:
        _fails.clear()
    _fails.setdefault(key, []).append((time.monotonic(), requester_ip, requester_server))
    if len(_recent_fails(key, 3600)) >= protocol.friend_attempts_total_per_hour:
        _locked_until[key] = time.monotonic() + 3600
        errors.debug_print(f"Friend door {key} locked for an hour (too many wrong passwords)")
    if len(_locked_until) > 20000:
        now = time.monotonic()
        for locked_key in [name for name, until in _locked_until.items() if until <= now]:
            del _locked_until[locked_key]
        if len(_locked_until) > 20000:
            _locked_until.clear()

def _guessing_stopped(key, requester_ip, requester_server):
    if _locked_until.get(key, 0) > time.monotonic():
        return True
    recent = _recent_fails(key, protocol.friend_attempt_window_minutes * 60)
    if sum(1 for fail in recent if fail[1] == requester_ip) >= protocol.friend_attempts_per_client:
        return True
    if requester_server != url_env.base_root:
        server = address.server_key(requester_server)
        if sum(1 for fail in recent if address.server_key(fail[2]) == server) >= protocol.friend_attempts_per_server:
            return True
    return False

async def finish(challenge_id, proof, client_nonce, requester_ip, requester_server):
    """The door, if the proof fits the challenge - else FRIEND_INVITE_INVALID or TOO_MANY_ATTEMPTS.
    Unknown doors do the same work and count the same failures (nothing in the answer or its time tells)."""
    challenge = _challenges.pop(challenge_id, None) if isinstance(challenge_id, str) else None
    if (challenge is None or challenge["expires"] < time.monotonic() or challenge["requester_server"] != requester_server
            or challenge["requester_ip"] != requester_ip or not isinstance(proof, str) or len(proof) > 128
            or not isinstance(client_nonce, str) or not 16 <= len(client_nonce) <= 128 or json_problem(client_nonce)):
        return _fail(Exceptions.FRIEND_INVITE_INVALID, "the challenge is unknown or expired - start again")
    key = challenge["key"]
    counted = canonical(key)
    if _guessing_stopped(counted, requester_ip, requester_server):
        return _fail(Exceptions.TOO_MANY_ATTEMPTS, "too many wrong passwords - try again later")
    door = friend_store.doors.get(challenge["door_key"]) if challenge["door_key"] else None
    door = door if _usable(door) else None
    first_key = bytes.fromhex(door["verifier"]) if door is not None else bytes.fromhex(_fake(key, "key"))
    second = await second_key_async(first_key, url_env.base_root, key, requester_ip, client_nonce)
    if door is not None and friend_store.doors.get(door["key"]) is not door:
        door = None  # deleted (or used up) while the key was computed
    expected = proof_for(second, url_env.base_root, key, requester_ip, challenge["nonce"], client_nonce)
    if door is None or not hmac.compare_digest(expected.encode("ascii"), proof.encode("utf-8", "replace")):
        _record_fail(counted, requester_ip, requester_server)
        return _fail(Exceptions.FRIEND_INVITE_INVALID, "unknown friend address or wrong password")
    return door
# endregion challenge / proof
