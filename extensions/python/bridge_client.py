"""Bridge for Python - one file, standard library only (Python 3.10+).

One ``BridgeClient`` is one Bridge client (one client IP). It does everything around the connection by itself:
register / login, renew the session before it runs out, log in again on SESSION_INVALID, register again after a
Bridge restart without backup (and join the realms, subscribe the topics, host the commands again), poll messages in
the background (many per request), check safe messages with SHA-256, unpack compressed ones, clean up on close().

    from bridge_client import BridgeClient

    client = BridgeClient("https://my-pc.tailnet.ts.net", name="My program")
    client.subscribe("chat", lambda data, event: print(event.sender_ip, data))
    client.publish("chat", {"text": "Hello"})
    client.publish_latest("position", {"x": 1})        # only the newest counts, does not wait
    client.host_command("add", lambda args, task: args["a"] + args["b"])
    three = client.call("add", {"a": 1, "b": 2})
    client.close()

Thread model: all methods are thread safe and block until Bridge answered (the ``..._async`` variants return a
``concurrent.futures.Future``). Listeners and topic handlers run one after the other on the client's callback thread
(in the order the messages arrived); command handlers run on their own threads. Bridge stays pull-only: the client
always asks (long polling), Bridge never pushes.
"""
from __future__ import annotations

import atexit
import base64
import gzip
import hashlib
import http.client
import json
import logging
import queue
import secrets
import select
import socket
import ssl
import threading
import time
import urllib.parse
import weakref
import zlib
from collections import OrderedDict
from concurrent.futures import Future, InvalidStateError
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

__version__ = "1.0.0"
__all__ = [
    "ADDRESS_SPLIT", "BridgeClient", "BridgeError", "Event", "HostedCommand", "Message", "Progress", "Response",
    "State", "Subscription", "Task", "normalize_server", "sha256",
]

ADDRESS_SPLIT = "<|BRIDGE_IP_SPLIT|>"
_FATAL = frozenset({"INVALID_CREDENTIALS", "ALREADY_EXISTS", "ARGUMENT_ERROR", "DESTROYED", "BRIDGE_URL_MISSING"})
_BRIDGE_ROUTES = frozenset({"admin", "server", "s2s", "client", "message", "command", "realm", "express", "agent",
                            "conversation", "friends", "site"})
_PUBLIC = "public"
_FOREVER = 10.0 ** 9
_log = logging.getLogger("bridge_client")


# region errors + helpers
class BridgeError(Exception):
    """An error of Bridge or of the connection. ``id`` is the Bridge error ID ("SESSION_INVALID",
    "RECIPIENT_NOT_FOUND", ...) or one of the extension's own: UNREACHABLE, NOT_CONNECTED, TIMEOUT, COMMAND_FAILED,
    DESTROYED, HASH_MISMATCH, ALREADY_ANSWERED, HANDLER_ERROR, SCRIPT_ERROR, HTTP_<status>."""

    def __init__(self, id: str, message: str = "", status: int = 0, path: Optional[str] = None,
                 details: Optional[dict] = None):
        where = ""
        if path is not None:
            where = " (" + path + (" -> " + str(status) if status else "") + ")"
        super().__init__("[Bridge] " + str(id) + ": " + str(message) + where)
        self.id = id
        self.message = message
        self.status = status
        self.path = path
        self.details = details

    def __reduce__(self):
        return BridgeError, (self.id, self.message, self.status, self.path, self.details)


def sha256(text: str) -> str:
    """SHA-256 (hex) of the UTF-8 bytes of a text - the hash Bridge uses for safe messages."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_server(url: str) -> str:
    """"my-pc.ts.net/admin/" -> "https://my-pc.ts.net" (scheme added, default port dropped, host in lower case,
    the path cut at the first Bridge route segment like /admin or /site, no trailing /). Other path segments stay:
    "https://pc.ts.net:10000/momentum/admin" -> "https://pc.ts.net:10000/momentum" (several servers on one port)."""
    text = url.strip()
    if not text.startswith("http://") and not text.startswith("https://"):
        text = "https://" + text
    scheme_end = text.index("://") + 3
    scheme = text[:scheme_end]
    rest = text[scheme_end:]
    cut = len(rest)
    for stop in "/?#":
        index = rest.find(stop)
        if 0 <= index < cut:
            cut = index
    host = rest[:cut].lower()
    if scheme == "https://" and host.endswith(":443"):
        host = host[:-4]
    elif scheme == "http://" and host.endswith(":80"):
        host = host[:-3]
    path = rest[cut:].split("?", 1)[0].split("#", 1)[0]
    kept = []
    for segment in path.split("/"):
        if not segment:
            continue
        if segment.lower() in _BRIDGE_ROUTES:
            break
        kept.append("/" + segment)
    return scheme + host + "".join(kept)


def _dumps(value: Any) -> str:
    # The same encoding as the Bridge server (sizes for "auto" are measured the same way)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _as_dict(value: Any) -> Optional[dict]:
    return value if isinstance(value, dict) else None


def _text(value: Any) -> Optional[str]:
    return value if isinstance(value, str) else None


def _number(value: Any, default: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return value


def _realm_ref_of(realm: Optional[str]) -> str:
    # None / "public" -> "public" (the public realm of the server, looked up again after every connect)
    if realm is None or realm == _PUBLIC:
        return _PUBLIC
    if not isinstance(realm, str):
        raise TypeError("realm must be a realm address (text) or None for the public realm")
    return realm


def _is_connection_problem(error: BaseException) -> bool:
    return isinstance(error, BridgeError) and error.id in ("NOT_CONNECTED", "UNREACHABLE")


def _put(body: dict, **values: Any) -> dict:
    for key, value in values.items():
        if value is not None:
            body[key] = value
    return body


def _resolve(future: Future, value: Any) -> None:
    try:
        future.set_result(value)
    except InvalidStateError:
        pass


def _reject(future: Future, error: BaseException) -> None:
    try:
        future.set_exception(error)
    except InvalidStateError:
        pass


def _inflate(text: str) -> str:
    try:
        return zlib.decompress(base64.b64decode(text)).decode("utf-8")
    except (ValueError, zlib.error) as error:
        raise BridgeError("HASH_MISMATCH", "compressed data is broken: " + str(error)) from None


def _daemon(target: Callable, name: str, *args: Any) -> threading.Thread:
    thread = threading.Thread(target=target, args=args, name=name, daemon=True)
    thread.start()
    return thread
# endregion


# region HTTP (keep-alive connections, standard library only)
def _dropped(conn: http.client.HTTPConnection) -> bool:
    """True if the server closed a kept-alive connection (it is readable = EOF while no request is open)."""
    sock = conn.sock
    if sock is None:
        return True
    try:
        readable, _, _ = select.select([sock], [], [], 0)
    except (OSError, ValueError):
        return True
    return bool(readable)


class _Http:
    """A few open connections to one server: no new TCP/TLS handshake for every request (Tailscale Funnel is HTTPS).
    Ignores HTTP proxies from the environment - Bridge is reached directly."""
    MAX_IDLE = 8
    IDLE_SECONDS = 4.0  # uvicorn closes idle keep-alive connections after 5 s - never reuse one that old

    def __init__(self, base_url: str, connect_timeout: float = 10.0):
        parts = urllib.parse.urlsplit(base_url)
        port = parts.port  # ValueError for a broken port
        if not parts.hostname:
            raise ValueError("No host in the server URL " + repr(base_url))
        self._https = parts.scheme == "https"
        self._host = parts.hostname
        self._port = port
        self._prefix = parts.path.rstrip("/")
        self._connect_timeout = connect_timeout
        self._context = ssl.create_default_context() if self._https else None
        self._lock = threading.Lock()
        self._idle: List[tuple] = []
        self._busy: set = set()
        self._closed = False
        self.opened = 0  # connections opened so far (tests)

    def _take(self):
        now = time.monotonic()
        with self._lock:
            if self._closed:
                raise BridgeError("DESTROYED", "The client was closed")
            while self._idle:
                conn, since = self._idle.pop()
                if now - since < self.IDLE_SECONDS and not _dropped(conn):
                    self._busy.add(conn)
                    return conn, True
                conn.close()
            if self._https:
                conn = http.client.HTTPSConnection(self._host, self._port, timeout=self._connect_timeout,
                                                   context=self._context)
            else:
                conn = http.client.HTTPConnection(self._host, self._port, timeout=self._connect_timeout)
            self._busy.add(conn)
            self.opened += 1
            return conn, False

    def _give_back(self, conn) -> None:
        with self._lock:
            self._busy.discard(conn)
            if not self._closed and len(self._idle) < self.MAX_IDLE:
                self._idle.append((conn, time.monotonic()))
                return
        conn.close()

    def _drop(self, conn) -> None:
        with self._lock:
            self._busy.discard(conn)
        try:
            conn.close()
        except Exception:
            pass

    def _failure(self, error: BaseException, path: str) -> BridgeError:
        if self._closed:
            return BridgeError("DESTROYED", "The client was closed", 0, path)
        return BridgeError("UNREACHABLE", type(error).__name__ + ": " + str(error), 0, path)

    def request(self, method: str, path: str, body: Optional[bytes], timeout: float):
        headers = {"Accept": "application/json", "Accept-Encoding": "gzip",
                   "User-Agent": "bridge-python/" + __version__}
        if body is not None:
            headers["Content-Type"] = "application/json"
        for attempt in range(2):
            conn, reused = self._take()
            answered = False
            try:
                if conn.sock is None:
                    conn.connect()  # with the connect timeout
                conn.sock.settimeout(timeout)
                conn.request(method, self._prefix + path, body=body, headers=headers)
                response = conn.getresponse()
                answered = True
                data = response.read()
                status = response.status
                encoding = (response.getheader("Content-Encoding") or "").lower()
                will_close = response.will_close
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as error:
                # (http.client.RemoteDisconnected is a ConnectionResetError)
                self._drop(conn)
                if reused and not answered and attempt == 0 and not self._closed:
                    continue  # the server closed the kept-alive connection right now: once more on a fresh one
                raise self._failure(error, path) from None
            except BridgeError:
                self._drop(conn)
                raise
            except Exception as error:  # OSError, timeouts, http.client.HTTPException, ssl errors
                self._drop(conn)
                raise self._failure(error, path) from None
            if will_close:
                self._drop(conn)
            else:
                self._give_back(conn)
            try:
                if encoding == "gzip":
                    data = gzip.decompress(data)
                elif encoding == "deflate":
                    data = zlib.decompress(data)
            except (OSError, EOFError, zlib.error) as error:
                raise BridgeError("UNREACHABLE", "broken compressed answer: " + str(error), status, path) from None
            return status, data.decode("utf-8", errors="replace")
        raise BridgeError("UNREACHABLE", "no connection", 0, path)  # not reached

    def close(self) -> None:
        """Closes the idle connections and aborts running requests (the long poll)."""
        with self._lock:
            self._closed = True
            idle = [conn for conn, _ in self._idle]
            self._idle.clear()
            busy = list(self._busy)
        for conn in idle:
            conn.close()
        for conn in busy:
            sock = conn.sock
            if sock is not None:
                try:
                    socket.socket.shutdown(sock, socket.SHUT_RDWR)  # the reading thread gets EOF at once
                except (OSError, ValueError, TypeError):
                    pass
# endregion


# region public types
class State(str, Enum):
    IDLE = "idle"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"
    CLOSED = "closed"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Message:
    """A direct message (or another plain message type)."""
    id: Optional[str]
    type: Optional[str]
    sender_ip: Optional[str]
    content: Any
    mode: Optional[str]
    conversation_id: Optional[str]
    verified: bool
    meta: dict
    client: "BridgeClient" = field(repr=False, compare=False)

    def reply(self, content: Any, **options: Any) -> dict:
        """Answers in the same conversation (options like send: mode, expires_in_seconds, ...)."""
        options.setdefault("conversation_id", self.conversation_id)
        options.setdefault("causation_id", self.id)
        return self.client.send(self.sender_ip, content, **options)


@dataclass(frozen=True)
class Event:
    """A topic event. ``data`` is what the publisher published."""
    realm: Optional[str]
    topic: Optional[str]
    data: Any
    sender_ip: Optional[str]
    meta: dict


@dataclass(frozen=True)
class Response:
    task_id: Optional[str]
    content: Any
    sender_ip: Optional[str]
    meta: dict


@dataclass(frozen=True)
class Progress:
    task_id: Optional[str]
    content: Any
    sender_ip: Optional[str]
    meta: dict


class Task:
    """A task (a call of a command this client hosts)."""

    def __init__(self, client: "BridgeClient", meta: dict, content: dict):
        self._client = client
        self._lock = threading.Lock()
        self._answered = False
        self.meta = meta
        self.id = _text(meta.get("message_id"))
        self.caller_ip = _text(meta.get("sender_ip"))
        self.command = _text(content.get("command_name"))
        self.args = content.get("command_args")
        self.realm = _text(content.get("realm_address"))
        self.accepts_progress = content.get("accepts_progress") is True

    @property
    def answered(self) -> bool:
        return self._answered

    def respond(self, content: Any) -> dict:
        """Answers the task (only once)."""
        with self._lock:
            if self._answered:
                raise BridgeError("ALREADY_ANSWERED", "This task was answered already")
            self._answered = True
        body = {"task_id": self.id, "content": content, "mode": self._client._pick_mode(content, None)}
        try:
            return _as_dict(self._client._request("/command/respond", body)) or {}
        except BridgeError as error:
            if error.id == "ARGUMENT_ERROR" and error.status == 0:
                self._answered = False  # not JSON - nothing went out, the task can still be answered
            raise

    def fail(self, message: str) -> dict:
        """Answers with an error - the caller's call() raises COMMAND_FAILED with this text."""
        return self.respond({"bridge_error": message})

    def progress(self, percent: Optional[float] = None, content: Any = None) -> dict:
        """Progress for the caller (only delivered if the caller asked for it)."""
        if not self.accepts_progress:
            return {"delivered": False, "reason": "caller_does_not_accept_progress"}
        body = _put({"task_id": self.id, "content": content}, percent=percent)
        return _as_dict(self._client._request("/command/progress", body)) or {}

    def __repr__(self) -> str:
        return f"<Task {self.command!r} {self.id} from {self.caller_ip}>"


class _Closer:
    def __init__(self, closer: Callable[[], None]):
        self._closer = closer
        self._closed = False
        self._closed_lock = threading.Lock()

    def close(self) -> None:
        with self._closed_lock:
            if self._closed:
                return
            self._closed = True
        self._closer()

    def __enter__(self):
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


class Subscription(_Closer):
    """Returned by subscribe: close() removes the handler (and unsubscribes on the server if it was the last)."""

    def __init__(self, closer, topic: str, realm: str):
        super().__init__(closer)
        self.topic = topic
        self.realm = realm

    unsubscribe = _Closer.close


class HostedCommand(_Closer):
    """Returned by host_command: close() removes the command on the server."""

    def __init__(self, closer, command: str, realm: str):
        super().__init__(closer)
        self.command = command
        self.realm = realm

    remove = _Closer.close


@dataclass(eq=False)
class _TopicEntry:
    realm_ref: str
    topic: str
    handlers: list = field(default_factory=list)
    latest: list = field(default_factory=list)  # handlers that only want the newest event


@dataclass(eq=False)
class _CommandEntry:
    realm_ref: str
    name: str
    handler: Callable
    extra: dict


@dataclass(frozen=True)
class _HttpResult:
    status: int
    data: Any
    body: str
# endregion


_live_clients: "weakref.WeakSet[BridgeClient]" = weakref.WeakSet()


def _close_all_at_exit() -> None:
    for client in list(_live_clients):
        try:
            client.close()
        except Exception:
            pass


atexit.register(_close_all_at_exit)


class BridgeClient:
    """One Bridge client (one client IP). Only ``server`` is required; everything else has a default.

    Without ``password``, ``identity_secret`` and ``client_ip`` the client is *ephemeral*: random password, new IP on
    every start, deleted on the server again by close().
    """
    ADDRESS_SPLIT = ADDRESS_SPLIT
    normalize_server = staticmethod(normalize_server)
    sha256 = staticmethod(sha256)

    def __init__(self, server: str, name: str = "Python client", password: Optional[str] = None,
                 identity_secret: Optional[str] = None, client_ip: Optional[str] = None,
                 ephemeral: Optional[bool] = None, poll_wait_seconds: float = 20, poll_interval: float = 0.05,
                 max_messages: int = 50, connect_timeout: float = 30, session_margin_seconds: float = 120,
                 ignore_own_events: bool = True, auto_start: bool = True, receive: bool = True,
                 debug: Optional[Callable[[str], Any]] = None,
                 warn: Optional[Callable[[str], Any]] = _log.warning, close_on_exit: bool = True):
        """
        server: URL of the Bridge server (https:// is added, /admin etc. is cut, a server path like /momentum stays)
        name: name of the client on the server
        password: password of the client (see ephemeral above)
        identity_secret: 32+ characters: always the SAME client IP on this server, also after a Bridge restart. The
            password is derived from it when none is given. Keep it secret.
        client_ip: log in to an existing client (with password)
        ephemeral: overrides the automatic choice (True = delete the client on close())
        poll_wait_seconds: how long a poll waits for something to arrive (long polling, Bridge allows up to 25)
        poll_interval: at least this many seconds between two polls
        max_messages: messages per poll (Bridge allows up to 100)
        connect_timeout: seconds a call waits for the connection before it raises NOT_CONNECTED
        session_margin_seconds: renew the session this long before it runs out
        ignore_own_events: do not hand out events this client published itself (include_self)
        auto_start: False = connect only with connect() or the first call
        receive: False = no background polling (call() then lets the server wait for the answer)
        debug / warn: where debug output / warnings go (None = nowhere; warnings default to logging)
        close_on_exit: close() this client when the Python program ends (an ephemeral client deletes itself)
        """
        if not isinstance(server, str):
            raise TypeError("server must be the URL of a Bridge server (text)")
        if identity_secret is not None and len(identity_secret) < 32:
            raise ValueError("identity_secret must have at least 32 characters")
        self._name = name
        self._server = normalize_server(server)
        self._http = _Http(self._server)
        self._identity = identity_secret
        if password is not None:
            self._password = password
        elif identity_secret is not None:
            self._password = sha256("bridge-python-password|" + identity_secret)
        else:
            self._password = secrets.token_hex(24)
        self._ephemeral = ephemeral if ephemeral is not None else (
            password is None and identity_secret is None and client_ip is None)
        self._client_ip = client_ip
        self._poll_wait = poll_wait_seconds
        self._poll_interval = poll_interval
        self._max_messages = max_messages
        self._connect_timeout = connect_timeout
        self._session_margin = session_margin_seconds
        self._margin = session_margin_seconds
        self._ignore_own_events = ignore_own_events
        self._receiving = receive
        self._debug_out = debug
        self._warn_out = warn

        self._server_url: Optional[str] = None
        self._public_realm: Optional[str] = None
        self._limits: dict = {}
        self._token: Optional[str] = None
        self._token_expires_at = 0.0  # time.monotonic()
        self._state = State.IDLE
        self._online = False
        self._fatal: Optional[BridgeError] = None
        self._ever_connected = False
        self._closing = False
        self._restoring = False

        self._cond = threading.Condition()
        self._connect_lock = threading.Lock()
        self._connecting = False
        self._poll_lock = threading.Lock()
        self._polling = False
        self._renew_lock = threading.Lock()
        self._count_lock = threading.Lock()
        self._requests = 0
        self._sync_calls = 0
        self._online_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._close_started = False
        self._stop = threading.Event()

        self._topics: List[_TopicEntry] = []
        self._topics_lock = threading.Lock()
        self._commands: List[_CommandEntry] = []
        self._commands_lock = threading.Lock()
        self._realms: Dict[str, dict] = {}
        self._response_lock = threading.Lock()
        self._waiters: Dict[str, Future] = {}
        self._unclaimed: Dict[str, Response] = {}
        self._close_handlers: List[Callable[[], Any]] = []
        # publish_latest: "realmRef|topic" -> the newest value that did not go out yet (an older one is replaced)
        self._latest: "OrderedDict[str, tuple]" = OrderedDict()
        self._latest_lock = threading.Lock()
        self._latest_sending = False
        # "sender|realm|topic" -> created_at of the newest event the latest_only subscriptions got
        self._newest_event: Dict[str, str] = {}
        self._listeners: Dict[str, List[Callable]] = {kind: [] for kind in (
            "connected", "disconnected", "ip_changed", "message", "event", "task", "response", "progress", "error")}

        self._callbacks: "queue.SimpleQueue" = queue.SimpleQueue()
        self._callbacks_open = True
        _daemon(self._callback_loop, "bridge-callbacks-" + str(name))
        if close_on_exit:
            _live_clients.add(self)
        if auto_start:
            self._start_connect_loop()

    # region getters + listeners
    @property
    def client_ip(self) -> Optional[str]:
        return self._client_ip

    @property
    def name(self) -> str:
        return self._name

    @property
    def server(self) -> str:
        """The normalized URL this client talks to."""
        return self._server

    @property
    def server_url(self) -> Optional[str]:
        """The URL the server gives itself (part of every address)."""
        return self._server_url

    @property
    def public_realm(self) -> Optional[str]:
        return self._public_realm

    @property
    def state(self) -> State:
        return self._state

    @property
    def online(self) -> bool:
        return self._online

    @property
    def request_count(self) -> int:
        return self._requests

    @property
    def limits(self) -> dict:
        return self._limits

    def __repr__(self) -> str:
        return f"<BridgeClient {self._name!r} {self._state.value} {self._client_ip}>"

    def __enter__(self) -> "BridgeClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def _add(self, kind: str, listener: Callable) -> Callable:
        if not callable(listener):
            raise TypeError("listener must be callable")
        self._listeners[kind].append(listener)
        return listener

    # Every on_... returns the listener, so it also works as a decorator: @client.on_message
    def on_connected(self, listener: Callable[[str], Any]) -> Callable:
        """listener(client_ip) - connected (again)."""
        return self._add("connected", listener)

    def on_disconnected(self, listener: Callable[[str], Any]) -> Callable:
        """listener(reason) - the connection is lost (the client keeps trying)."""
        return self._add("disconnected", listener)

    def on_client_ip_changed(self, listener: Callable[[str, str], Any]) -> Callable:
        """listener(new_ip, old_ip) after a re-registration (Bridge restart without backup)."""
        return self._add("ip_changed", listener)

    def on_message(self, listener: Callable[[Message], Any]) -> Callable:
        return self._add("message", listener)

    def on_event(self, listener: Callable[[Event], Any]) -> Callable:
        """Every topic event (also the ones a subscribe handler gets)."""
        return self._add("event", listener)

    def on_task(self, listener: Callable[[Task], Any]) -> Callable:
        """Tasks for commands without a handler - answer them with task.respond(...)."""
        return self._add("task", listener)

    def on_response(self, listener: Callable[[Response], Any]) -> Callable:
        """Responses no call() waits for (call_no_wait, late answers)."""
        return self._add("response", listener)

    def on_progress(self, listener: Callable[[Progress], Any]) -> Callable:
        return self._add("progress", listener)

    def on_error(self, listener: Callable[[BridgeError], Any]) -> Callable:
        """Errors in the background (polling, reconnecting, handlers, publish_async / publish_latest)."""
        return self._add("error", listener)

    def on_close(self, handler: Callable[[], Any]) -> Callable:
        """Runs at the start of close() while the client is still connected (e.g. a last "bye")."""
        if not callable(handler):
            raise TypeError("handler must be callable")
        self._close_handlers.append(handler)
        return handler

    def _callback_loop(self) -> None:
        while True:
            item = self._callbacks.get()
            if item is None:
                return
            function, args, on_failure = item
            try:
                function(*args)
            except Exception as error:
                try:
                    on_failure(error)
                except Exception:
                    pass

    def _enqueue(self, function: Callable, args: tuple, on_failure: Callable[[BaseException], Any]) -> None:
        if self._callbacks_open:
            self._callbacks.put((function, args, on_failure))

    def _listener_failed(self, error: BaseException) -> None:
        self._warn("listener failed: " + repr(error))

    def _fire(self, kind: str, *args: Any) -> None:
        for listener in tuple(self._listeners[kind]):
            self._enqueue(listener, args, self._listener_failed)

    def _debug(self, message: str) -> None:
        if self._debug_out is not None:
            try:
                self._debug_out("[Bridge:" + str(self._name) + "] " + message)
            except Exception:
                pass

    def _warn(self, message: str) -> None:
        if self._warn_out is not None:
            try:
                self._warn_out("[Bridge:" + str(self._name) + "] " + message)
            except Exception:
                pass

    def _report(self, error: BaseException) -> None:
        if not isinstance(error, BridgeError):
            error = BridgeError("SCRIPT_ERROR", type(error).__name__ + ": " + str(error))
        self._debug("error: " + str(error))
        self._fire("error", error)

    def _set_online(self, value: bool, reason: Optional[str] = None) -> None:
        with self._online_lock:
            if self._online == value:
                return
            self._online = value
        if value:
            self._fire("connected", self._client_ip)
        else:
            self._warn("connection lost: " + str(reason))
            self._fire("disconnected", reason)
    # endregion

    # region HTTP
    def _raw(self, method: str, path: str, body: Optional[dict], wait_seconds: float) -> _HttpResult:
        data = None
        if body is not None:
            try:
                data = _dumps(body).encode("utf-8")
            except (TypeError, ValueError, RecursionError) as error:
                raise BridgeError("ARGUMENT_ERROR", "Content cannot be sent as JSON: " + str(error), 0, path) from None
        with self._count_lock:
            self._requests += 1
        status, text = self._http.request(method, path, data, wait_seconds + 20)
        parsed = None
        if text:
            try:
                parsed = json.loads(text)
            except ValueError:
                pass  # not JSON (e.g. a proxy error page)
        return _HttpResult(status, parsed, text)

    @staticmethod
    def _error_from(result: _HttpResult, path: str) -> BridgeError:
        answer = _as_dict(result.data)
        detail = _as_dict(answer.get("detail")) if answer is not None else None
        if detail is not None:
            message = str(detail.get("message", ""))
            details = _as_dict(detail.get("details"))
            problems = details.get("problems") if details is not None else None
            if isinstance(problems, list) and problems:
                message += " -> " + "; ".join(str(problem) for problem in problems)
            error_id = detail.get("error")
            return BridgeError(str(error_id) if error_id is not None else "UNKNOWN_ERROR", message, result.status,
                               path, details)
        if answer is not None and answer.get("detail") is not None:
            text = str(answer.get("detail"))
        else:
            text = (result.body or "")[:300]
        return BridgeError("HTTP_" + str(result.status), text, result.status, path)

    def _request(self, path: str, body: Optional[dict] = None, *, auth: bool = True, internal: bool = False,
                 connect_wait: Optional[float] = None, realm_ref: Optional[str] = None) -> Any:
        """One request: waits for the connection, renews the session in time, logs in again on SESSION_INVALID,
        waits while the server starts. internal: the client's own restore requests (before it counts as ready)."""
        payload = dict(body) if body else {}
        starting_tries = 20
        renewed = False
        wait = _number(payload.get("wait_seconds"), 0)
        while True:
            used_token = None
            if auth:
                self._ensure_connected(self._connect_timeout if connect_wait is None else connect_wait, internal)
                if time.monotonic() >= self._token_expires_at - self._margin:
                    self._renew_session(self._token)
                used_token = self._token
                payload["session_token"] = used_token
                if realm_ref is not None:
                    payload["realm_address"] = self._resolve_realm(realm_ref)
            result = self._raw("POST", path, payload, wait)
            if result.status == 200:
                return result.data
            error = self._error_from(result, path)
            if error.id == "SERVER_STARTING" and starting_tries > 0:
                starting_tries -= 1
                time.sleep(0.5)
            elif (error.id == "SESSION_INVALID" and auth and not renewed and not self._closing
                  and self._state is not State.CLOSED):
                renewed = True
                self._renew_session(used_token)
            else:
                raise error
    # endregion

    # region connection
    def connect(self, timeout: Optional[float] = None) -> Optional[str]:
        """Waits until connected (starts connecting if needed). Returns the client IP."""
        self._ensure_connected(self._connect_timeout if timeout is None else timeout)
        return self._client_ip

    def wait_for_connection(self, timeout: Optional[float] = None) -> bool:
        """True if connected within the time."""
        try:
            self._ensure_connected(self._connect_timeout if timeout is None else timeout)
            return True
        except BridgeError:
            return False

    def _set_state(self, value: State) -> None:
        with self._cond:
            self._state = value
            self._cond.notify_all()

    def _start_connect_loop(self) -> None:
        with self._connect_lock:
            if self._connecting:
                return
            self._connecting = True
            self._fatal = None
        _daemon(self._connect_loop, "bridge-connect-" + str(self._name))

    def _connect_loop(self) -> None:
        delay = 1.0
        try:
            while self._state is not State.CLOSED and not self._closing:
                try:
                    self._do_connect()
                    return
                except BridgeError as error:
                    if error.id in _FATAL:
                        if error.id != "DESTROYED":
                            self._fatal = error
                            self._warn(str(error))
                            self._report(error)
                            self._set_state(State.FAILED)
                        return
                    self._report(error)
                except Exception as error:
                    self._report(error)
                if self._stop.wait(delay):
                    return
                delay = min(delay * 2, 15.0)
        finally:
            with self._connect_lock:
                self._connecting = False
            with self._cond:
                self._cond.notify_all()

    def _ready(self, internal: bool) -> bool:
        # After a (re)connect the client first sets up its realms / topics / commands again - only then it is ready
        return self._state is State.CONNECTED and (internal or not self._restoring)

    def _ensure_connected(self, timeout: float, internal: bool = False) -> None:
        if self._ready(internal):
            return  # also while closing: the cleanup requests of close() still go out
        if self._state is State.CLOSED or self._closing:
            raise BridgeError("DESTROYED", "The client was closed")
        self._start_connect_loop()
        deadline = time.monotonic() + timeout
        with self._cond:
            while not self._ready(internal):
                if self._state is State.CLOSED or self._closing:
                    raise BridgeError("DESTROYED", "The client was closed")
                fatal = self._fatal
                if fatal is not None and not self._connecting:
                    raise BridgeError(fatal.id, fatal.message, fatal.status, fatal.path, fatal.details)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BridgeError("NOT_CONNECTED", "No connection to " + self._server + " (yet)")
                self._cond.wait(min(remaining, 0.2))

    def _wait_for_server(self) -> dict:
        delay = 1.0
        warned = False
        while True:
            if self._state is State.CLOSED or self._closing:
                raise BridgeError("DESTROYED", "The client was closed")
            try:
                result = self._raw("GET", "/server/status", None, 0)
                data = _as_dict(result.data)
                if result.status == 200 and data is not None and "status" in data:
                    if not isinstance(data.get("url"), str):
                        raise BridgeError("BRIDGE_URL_MISSING", "The Bridge server has no public URL set", 200,
                                          "/server/status")
                    if data.get("ready") is not False:
                        return data
                    if self._stop.wait(0.5):
                        raise BridgeError("DESTROYED", "The client was closed")
                    continue
                reason = "answer " + str(result.status)
            except BridgeError as error:
                if error.id in _FATAL:
                    raise
                reason = str(error)
            if not warned:
                warned = True
                self._warn(self._server + " not reachable (" + reason + ") - trying again")
            self._set_online(False, reason)
            if self._stop.wait(delay):
                raise BridgeError("DESTROYED", "The client was closed")
            delay = min(delay * 2, 15.0)

    def _login(self) -> None:
        data = _as_dict(self._request("/client/login", {"client_ip": self._client_ip, "password": self._password},
                                      auth=False)) or {}
        self._token = _text(data.get("session_token"))
        lifetime = _number(data.get("remaining_minutes"), 60) * 60
        self._token_expires_at = time.monotonic() + lifetime
        # A short session (test servers) must not make every request log in again
        self._margin = min(self._session_margin, lifetime / 2)
        self._debug("logged in, session for " + str(data.get("remaining_minutes")) + " minutes")

    def _register(self) -> None:
        body = {"name": self._name, "password": self._password}
        if self._identity is not None:
            body["identity_secret"] = self._identity
        try:
            data = _as_dict(self._request("/client/register", body, auth=False)) or {}
        except BridgeError as error:
            if error.id == "ALREADY_EXISTS":
                raise BridgeError("ALREADY_EXISTS", "This identity_secret is already used by a client with another "
                                  "password", error.status, error.path) from None
            raise
        self._client_ip = _text(data.get("client_ip"))
        self._debug("registered as " + str(self._client_ip))

    def _do_connect(self) -> None:
        self._set_state(State.RECONNECTING if self._ever_connected else State.CONNECTING)
        status = self._wait_for_server()
        self._server_url = _text(status.get("url"))
        self._public_realm = _text(status.get("public_realm_address"))
        self._limits = _as_dict(status.get("limits")) or {}

        old_ip = self._client_ip
        if self._identity is not None:
            # Same formula as the server: the IP of a stable identity is known before registering
            self._client_ip = (self._server_url + ADDRESS_SPLIT
                               + sha256("bridge-identity|" + self._server_url + "|" + self._identity)[:32])
        if self._client_ip is not None:
            try:
                self._login()
            except BridgeError as error:
                gone = error.id == "INVALID_CREDENTIALS"
                if not (gone and (self._identity is not None or self._ephemeral)):
                    raise
                self._debug("client unknown on the server - registering again")
                self._register()
                self._login()
        else:
            self._register()
            self._login()

        # Realms / topics / commands this client should have (after a re-registration, or wished for before the
        # first connection was there): set them up (again) before anybody else uses the connection.
        with self._cond:
            self._restoring = bool(self._realms or self._topics or self._commands)
            self._state = State.CONNECTED
            self._cond.notify_all()
        if self._restoring:
            try:
                self._restore()
            finally:
                with self._cond:
                    self._restoring = False
                    self._cond.notify_all()
        self._ever_connected = True
        if old_ip is not None and old_ip != self._client_ip:
            self._fire("ip_changed", self._client_ip, old_ip)
        self._set_online(True)
        if self._receiving:
            self._start_poll_loop()

    def _renew_session(self, old_token: Optional[str]) -> None:
        if self._closing:
            raise BridgeError("DESTROYED", "The client is closing")
        reconnect = False
        with self._renew_lock:
            if self._token != old_token:
                return  # another thread renewed it already
            try:
                self._login()
            except BridgeError as error:
                if error.id == "INVALID_CREDENTIALS" and (self._identity is not None or self._ephemeral):
                    # The client is gone on the server: connect again from the start (register + restore)
                    self._token = None
                    if self._state is State.CONNECTED:
                        self._set_state(State.RECONNECTING)
                    reconnect = True
                else:
                    raise
        if reconnect:
            self._ensure_connected(self._connect_timeout)

    def _restore(self) -> None:
        for join_body in list(self._realms.values()):
            try:
                self._request("/realm/join", join_body, internal=True)
            except BridgeError as error:
                if error.id != "ALREADY_EXISTS":
                    self._report(error)
        with self._topics_lock:
            topics = list(self._topics)
        for entry in topics:
            try:
                self._request("/realm/topic/subscribe", {"topic": entry.topic}, internal=True,
                              realm_ref=entry.realm_ref)
            except BridgeError as error:
                self._report(error)
        with self._commands_lock:
            commands = list(self._commands)
        for command in commands:
            try:
                self._create_command(command, internal=True)
            except BridgeError as error:
                if error.id != "ALREADY_EXISTS":
                    self._report(error)
        self._debug(f"restored {len(topics)} topics, {len(commands)} commands")
    # endregion

    # region receiving
    def _start_poll_loop(self) -> None:
        with self._poll_lock:
            if self._polling:
                return
            self._polling = True
        _daemon(self._poll_loop, "bridge-poll-" + str(self._name))

    def _poll_loop(self) -> None:
        failures = 0
        try:
            while (self._state is not State.CLOSED and not self._closing and self._receiving
                   and self._fatal is None):
                started = time.monotonic()
                max_wait = _number(self._limits.get("max_wait_seconds"), 25)
                max_poll = _number(self._limits.get("max_poll_messages"), 100)
                try:
                    data = self._request("/message/poll", {
                        "wait_seconds": min(self._poll_wait, max_wait),
                        "max_messages": int(min(self._max_messages, max_poll)),
                    }, connect_wait=_FOREVER)
                    if failures > 0:
                        failures = 0
                        self._set_online(True)
                    items = _items_of(data)
                    # latest_only subscriptions only get the newest event per sender and topic of this batch
                    newest: Dict[str, int] = {}
                    for index, item in enumerate(items):
                        key = _event_key(item)
                        if key is not None:
                            newest[key] = index
                    for index, item in enumerate(items):
                        key = _event_key(item)
                        try:
                            self._handle_item(item, key is not None and newest[key] != index)
                        except Exception as error:
                            self._report(error)
                except Exception as error:
                    if self._closing or self._state is State.CLOSED:
                        break
                    failures += 1
                    if isinstance(error, BridgeError) and (error.id == "UNREACHABLE" or error.id.startswith("HTTP_")):
                        self._set_online(False, str(error))
                    if not (isinstance(error, BridgeError) and error.id == "DESTROYED"):
                        self._report(error)
                    if self._stop.wait(min(2 ** min(failures, 4), 15)):
                        break
                rest = self._poll_interval - (time.monotonic() - started)
                if rest > 0 and self._stop.wait(rest):
                    break
        finally:
            with self._poll_lock:
                self._polling = False

    def _fetch_chunked(self, item: dict) -> Any:
        meta = _as_dict(item.get("message")) or {}
        pending = _text(item.get("pending_id"))
        try:
            parts = []
            for index in range(int(_number(meta.get("chunk_count"), 1))):
                chunk = _as_dict(self._request("/message/chunk", {"pending_id": pending, "chunk_index": index})) or {}
                parts.append(_text(chunk.get("chunk")) or "")
            text = "".join(parts)
            if meta.get("encoding") == "zlib+base64":
                text = _inflate(text)
            digest = sha256(text)
            if digest != meta.get("sha256"):
                raise BridgeError("HASH_MISMATCH", "Local SHA-256 check failed", 0, "/message/chunk")
            self._request("/message/complete", {"pending_id": pending, "sha256": digest})
            return json.loads(text)
        except Exception:
            try:
                self._request("/message/cancel", {"pending_id": pending})  # give it back, it comes again
            except Exception:
                pass
            raise

    def _handle_item(self, item: dict, superseded: bool) -> None:
        """superseded: a newer event of the same sender and topic came in the same batch (latest_only skips it)."""
        meta = _as_dict(item.get("message")) or {}
        content = self._fetch_chunked(item) if item.get("pending_id") is not None else item.get("content")
        kind = _text(meta.get("content_type"))
        sender = _text(meta.get("sender_ip"))
        if kind == "event":
            if self._ignore_own_events and sender == self._client_ip:
                return
            body = _as_dict(content) or {}
            event = Event(_text(body.get("realm_address")), _text(body.get("topic")), body.get("data"), sender, meta)
            # latest_only subscriptions: nothing older than what they already got (requests can overtake each other)
            key = f"{sender}|{event.realm}|{event.topic}"
            created_at = _text(meta.get("created_at"))
            newest_so_far = self._newest_event.get(key)
            stale = superseded or (created_at is not None and newest_so_far is not None and created_at < newest_so_far)
            with self._topics_lock:
                topics = [(entry, list(entry.handlers), list(entry.latest)) for entry in self._topics]
            for entry, handlers, latest in topics:
                if entry.topic == event.topic and self._resolve_realm(entry.realm_ref) == event.realm:
                    if latest and not stale and created_at is not None:
                        self._newest_event[key] = created_at
                    for handler in handlers:
                        if stale and handler in latest:
                            continue
                        self._enqueue(handler, (event.data, event), self._topic_handler_failed(event.topic))
            self._fire("event", event)
        elif kind == "task":
            self._handle_task(meta, _as_dict(content) or {})
        elif kind == "response":
            task_id = _text(meta.get("causation_id"))
            response = Response(task_id, content, sender, meta)
            with self._response_lock:
                waiter = self._waiters.pop(task_id, None) if task_id is not None else None
                if waiter is None and task_id is not None:
                    self._unclaimed[task_id] = response  # a fast host can answer before call() knows the task id
            if waiter is not None:
                _resolve(waiter, response)
            elif task_id is not None:
                def hand_out() -> None:
                    with self._response_lock:
                        claimed = self._unclaimed.pop(task_id, None)
                    if claimed is not None:
                        self._fire("response", claimed)
                if self._sync_calls > 0:
                    timer = threading.Timer(1.0, hand_out)  # probably the answer of a running call(): a moment
                    timer.daemon = True
                    timer.start()
                else:
                    hand_out()
            else:
                self._fire("response", response)
        elif kind == "progress":
            self._fire("progress", Progress(_text(meta.get("causation_id")), content, sender, meta))
        else:
            self._fire("message", Message(_text(meta.get("message_id")), kind, sender, content, _text(meta.get("mode")),
                                          _text(meta.get("conversation_id")), meta.get("verified") is True, meta,
                                          self))

    def _topic_handler_failed(self, topic: Optional[str]) -> Callable[[BaseException], None]:
        def failed(error: BaseException) -> None:
            self._report(BridgeError("HANDLER_ERROR", f"topic '{topic}': {error!r}"))
        return failed

    def _handle_task(self, meta: dict, content: dict) -> None:
        task = Task(self, meta, content)
        entry = self._find_command(task.realm, task.command)
        if entry is None:
            self._fire("task", task)
            return

        def run() -> None:
            try:
                result = entry.handler(task.args, task)
            except Exception as error:
                if not task.answered:
                    try:
                        task.fail(str(error) or type(error).__name__)
                    except Exception as failed:
                        self._report(failed)
                return
            if not task.answered:
                try:
                    task.respond(result)
                except Exception as failed:
                    self._report(failed)
                    if not task.answered:  # the answer was not JSON: the caller gets COMMAND_FAILED instead
                        try:
                            task.fail("The answer cannot be sent as JSON: " + str(failed))
                        except Exception:
                            pass
        _daemon(run, "bridge-command-" + str(task.command))

    def _find_command(self, realm_address: Optional[str], name: Optional[str]) -> Optional[_CommandEntry]:
        by_name = None
        with self._commands_lock:
            commands = list(self._commands)
        for entry in commands:
            if entry.name == name:
                if self._resolve_realm(entry.realm_ref) == realm_address:
                    return entry
                if by_name is None:
                    by_name = entry
        return by_name
    # endregion

    # region helpers
    def _resolve_realm(self, realm_ref: str) -> Optional[str]:
        return self._public_realm if realm_ref == _PUBLIC else realm_ref

    def _pick_mode(self, content: Any, mode: Optional[str]) -> str:
        if mode is not None and mode != "auto":
            return mode
        limit = _number(self._limits.get("max_fast_message_kib"), 64) * 1024 - 1024
        try:
            size = len(_dumps(content).encode("utf-8"))
        except (TypeError, ValueError, RecursionError):
            return "fast"  # the send reports the real problem
        return "fast" if size <= limit else "safe"

    def _create_command(self, entry: _CommandEntry, internal: bool = False) -> None:
        body = dict(entry.extra)
        body["command_name"] = entry.name
        self._request("/realm/command/create", body, internal=internal, realm_ref=entry.realm_ref)

    def _run_realm_request(self, path: str, body: dict, realm: Optional[str]) -> dict:
        return _as_dict(self._request(path, body, realm_ref=_realm_ref_of(realm))) or {}

    def _run_async(self, function: Callable, *args: Any, report_errors: bool = False, **kwargs: Any) -> Future:
        future: Future = Future()

        def run() -> None:
            if not future.set_running_or_notify_cancel():
                return
            try:
                result = function(*args, **kwargs)
            except BaseException as error:
                if report_errors:
                    self._report(error)
                _reject(future, error)
            else:
                _resolve(future, result)
        _daemon(run, "bridge-async-" + str(self._name))
        return future

    @staticmethod
    def _times(body: dict, expires_in_seconds, expires_at, send_in_seconds, send_at, timezone, if_past) -> dict:
        return _put(body, expires_in_seconds=expires_in_seconds, expires_at=expires_at,
                    send_in_seconds=send_in_seconds, send_at=send_at, timezone=timezone, if_past=if_past)
    # endregion

    # region public API: messages + topics
    def send(self, recipient_ip: str, content: Any, *, mode: Optional[str] = "auto",
             conversation_id: Optional[str] = None, causation_id: Optional[str] = None,
             expires_in_seconds: Optional[float] = None, expires_at: Optional[str] = None,
             send_in_seconds: Optional[float] = None, send_at: Optional[str] = None,
             timezone: Optional[str] = None, if_past: Optional[str] = None) -> dict:
        """Sends a direct message. mode: auto (fast if small, else safe) | fast | safe | compressed | temporary.
        Returns {message_id, conversation_id, state, ...}."""
        if not isinstance(recipient_ip, str):
            raise TypeError("recipient_ip must be a client IP (text)")
        chosen = self._pick_mode(content, mode)
        if chosen == "temporary" and expires_in_seconds is None and expires_at is None:
            expires_in_seconds = 60
        body = _put({"recipient_ip": recipient_ip, "content": content, "mode": chosen},
                    conversation_id=conversation_id, causation_id=causation_id)
        self._times(body, expires_in_seconds, expires_at, send_in_seconds, send_at, timezone, if_past)
        return _as_dict(self._request("/message/send", body)) or {}

    def send_async(self, recipient_ip: str, content: Any, **options: Any) -> Future:
        return self._run_async(self.send, recipient_ip, content, **options)

    def broadcast(self, recipients: List[str], content: Any, *, mode: Optional[str] = "auto",
                  conversation_id: Optional[str] = None, expires_in_seconds: Optional[float] = None,
                  expires_at: Optional[str] = None, send_in_seconds: Optional[float] = None,
                  send_at: Optional[str] = None, timezone: Optional[str] = None,
                  if_past: Optional[str] = None) -> dict:
        """The same direct message to many clients at once (up to 100)."""
        chosen = self._pick_mode(content, mode)
        if chosen == "temporary" and expires_in_seconds is None and expires_at is None:
            expires_in_seconds = 60
        body = _put({"recipients": list(recipients), "content": content, "mode": chosen},
                    conversation_id=conversation_id)
        self._times(body, expires_in_seconds, expires_at, send_in_seconds, send_at, timezone, if_past)
        return _as_dict(self._request("/message/broadcast", body)) or {}

    def subscribe(self, topic: str, handler: Callable[[Any, Event], Any], *, realm: Optional[str] = None,
                  latest_only: bool = False) -> Subscription:
        """Subscribes a topic of a realm (None = public realm of the server). handler(data, event) gets every event.
        latest_only=True: only the newest event per sender - older ones that are still waiting are skipped (for
        states like positions: never work through old ones, show the current one)."""
        if not isinstance(topic, str):
            raise TypeError("topic must be a text")
        if not callable(handler):
            raise TypeError("handler must be callable(data, event)")
        realm_ref = _realm_ref_of(realm)
        added = False
        with self._topics_lock:
            entry = next((existing for existing in self._topics
                          if existing.topic == topic and existing.realm_ref == realm_ref), None)
            if entry is None:
                entry = _TopicEntry(realm_ref, topic)
                self._topics.append(entry)
                added = True
            entry.handlers.append(handler)
            if latest_only and handler not in entry.latest:
                entry.latest.append(handler)
        if added:
            try:
                self._request("/realm/topic/subscribe", {"topic": topic}, realm_ref=realm_ref)
            except BridgeError as error:
                if _is_connection_problem(error):
                    self._warn(f"subscribe '{topic}' happens as soon as the server is reachable")
                else:
                    with self._topics_lock:
                        if entry in self._topics:
                            self._topics.remove(entry)
                    raise

        def unsubscribe() -> None:
            with self._topics_lock:
                if handler in entry.handlers:
                    entry.handlers.remove(handler)
                if handler not in entry.handlers and handler in entry.latest:
                    entry.latest.remove(handler)
                last = not entry.handlers and entry in self._topics
                if last:
                    self._topics.remove(entry)
            if last:
                try:
                    self._request("/realm/topic/unsubscribe", {"topic": topic}, realm_ref=realm_ref)
                except Exception:
                    pass  # gone anyway
        return Subscription(unsubscribe, topic, realm_ref)

    def publish(self, topic: str, data: Any, *, realm: Optional[str] = None, mode: Optional[str] = "auto",
                include_self: bool = False) -> dict:
        """Publishes data to everybody who subscribed the topic (not back to yourself unless include_self).
        Returns {subscribers, delivered, failed}."""
        body = {"topic": topic, "content": data, "mode": self._pick_mode(data, mode),
                "include_self": bool(include_self)}
        return self._run_realm_request("/realm/topic/publish", body, realm)

    def publish_async(self, topic: str, data: Any, **options: Any) -> Future:
        """Publish without waiting (for game loops). Errors also go to on_error listeners."""
        return self._run_async(self.publish, topic, data, report_errors=True, **options)

    def publish_latest(self, topic: str, data: Any, *, realm: Optional[str] = None, mode: Optional[str] = None,
                       include_self: bool = False) -> None:
        """Publishes only the NEWEST value - for states that change all the time (positions, ...). Does not wait: the
        value replaces an older one of the same topic that has not gone out yet, a sender thread publishes the newest
        one as soon as the last request is done. Errors go to on_error listeners."""
        if not isinstance(topic, str):
            raise TypeError("topic must be a text")
        if data is None:
            raise ValueError("data must not be None")
        if self._closing or self._state is State.CLOSED:
            return
        try:
            _dumps(data)  # not JSON? The error comes here, not later in the sender thread
        except (TypeError, ValueError, RecursionError) as error:
            raise BridgeError("ARGUMENT_ERROR", "Content cannot be sent as JSON: " + str(error), 0,
                              "/realm/topic/publish") from None
        realm_ref = _realm_ref_of(realm)
        key = realm_ref + "|" + topic
        with self._latest_lock:
            self._latest.pop(key, None)  # re-insert: the topic that waited longest goes first
            self._latest[key] = (realm_ref, topic, data, mode, include_self)
            if not self._latest_sending:
                self._latest_sending = True
                _daemon(self._latest_loop, "bridge-latest-" + str(self._name))

    def _latest_loop(self) -> None:
        while True:
            with self._latest_lock:
                if not self._latest or self._closing or self._state is State.CLOSED:
                    self._latest.clear()
                    self._latest_sending = False
                    return
                key, value = self._latest.popitem(last=False)
            realm_ref, topic, data, mode, include_self = value
            try:
                self.publish(topic, data, realm=realm_ref, mode=mode, include_self=include_self)
            except Exception as error:
                if self._closing or self._state is State.CLOSED:
                    continue
                self._report(error)
                if _is_connection_problem(error):
                    with self._latest_lock:
                        if key not in self._latest:  # unless a newer one waits
                            self._latest[key] = value
                    self._stop.wait(1.0)
    # endregion

    # region public API: commands
    def host_command(self, command_name: str, handler: Callable[[Any, Task], Any], *, realm: Optional[str] = None,
                     description: Optional[str] = None, signature: Optional[dict] = None,
                     allowed_roles: Optional[List[str]] = None, extra: Optional[dict] = None) -> HostedCommand:
        """Hosts a command in a realm (None = public realm). handler(args, task) returns the answer (any JSON value);
        raising answers with an error (the caller gets COMMAND_FAILED). signature: BridgeExpress."""
        if not isinstance(command_name, str):
            raise TypeError("command_name must be a text")
        if not callable(handler):
            raise TypeError("handler must be callable(args, task)")
        options = _put(dict(extra or {}), description=description, signature=signature, allowed_roles=allowed_roles)
        realm_ref = _realm_ref_of(realm)
        entry = _CommandEntry(realm_ref, command_name, handler, options)
        with self._commands_lock:
            self._commands.append(entry)
        try:
            self._create_command(entry)
        except BridgeError as error:
            if _is_connection_problem(error):
                self._warn(f"command '{command_name}' is hosted as soon as the server is reachable")
            elif error.id != "ALREADY_EXISTS":
                with self._commands_lock:
                    if entry in self._commands:
                        self._commands.remove(entry)
                raise

        def remove() -> None:
            with self._commands_lock:
                present = entry in self._commands
                if present:
                    self._commands.remove(entry)
            if present:
                try:
                    self._request("/realm/command/remove", {"command_name": command_name}, realm_ref=realm_ref)
                except Exception:
                    pass  # gone anyway
        return HostedCommand(remove, command_name, realm_ref)

    def call(self, command_name: str, args: Any = None, *, realm: Optional[str] = None, timeout: float = 20,
             mode: Optional[str] = None, strategy: str = "least_busy", progress: str = "off",
             server_wait_seconds: Optional[float] = None) -> Any:
        """Calls a command and waits for the answer (returns it). realm: address (None = all realms of this client,
        "public" = the public realm of the server). strategy: least_busy | random | fastest. progress: off | latest
        | all (progress comes as on_progress). Raises TIMEOUT, COMMAND_FAILED (handler error), ..."""
        with self._count_lock:
            self._sync_calls += 1
        try:
            timeout = float(timeout)
            max_wait = _number(self._limits.get("max_wait_seconds"), 25)
            # With the background poll the answer comes with the next poll (the server must not hold the call: the
            # poll would take the answer away from it). Without polling the server waits for the answer.
            if server_wait_seconds is not None:
                server_wait = min(timeout, server_wait_seconds)
            elif self._receiving:
                server_wait = 0
            else:
                server_wait = min(timeout, max_wait)
            started = time.monotonic()
            result = self._start_call(command_name, args, realm, mode, strategy, progress, server_wait)
            task_id = _text(result.get("task_id"))
            response = _as_dict(result.get("response"))
            if response is not None:
                content = response.get("content")
            else:
                waiter: Future = Future()
                with self._response_lock:
                    early = self._unclaimed.pop(task_id, None)
                    if early is None:
                        self._waiters[task_id] = waiter
                if early is not None:
                    content = early.content
                else:
                    remaining = timeout - (time.monotonic() - started)
                    try:
                        if remaining <= 0 or not self._receiving:
                            raise FutureTimeoutError()
                        content = waiter.result(remaining).content
                    except FutureTimeoutError:
                        with self._response_lock:
                            mine = self._waiters.pop(task_id, None) is not None
                        if mine or not waiter.done() or waiter.exception() is not None:
                            raise BridgeError("TIMEOUT", f"'{command_name}' did not answer within {timeout:g} s", 0,
                                              "/command/call") from None
                        content = waiter.result().content  # came in at the very last moment
            answer = _as_dict(content)
            if answer is not None and "bridge_error" in answer:
                raise BridgeError("COMMAND_FAILED", str(answer.get("bridge_error")), 0, "/command/call")
            return content
        finally:
            with self._count_lock:
                self._sync_calls -= 1

    def call_async(self, command_name: str, args: Any = None, **options: Any) -> Future:
        """Like call, returns a Future for the answer."""
        return self._run_async(self.call, command_name, args, **options)

    def call_no_wait(self, command_name: str, args: Any = None, *, realm: Optional[str] = None,
                     mode: Optional[str] = None, strategy: str = "least_busy", progress: str = "off") -> Optional[str]:
        """Starts a call without waiting - returns the task id, the answer comes as on_response."""
        return _text(self._start_call(command_name, args, realm, mode, strategy, progress, 0).get("task_id"))

    def _start_call(self, command_name, args, realm, mode, strategy, progress, server_wait) -> dict:
        if not isinstance(command_name, str):
            raise TypeError("command_name must be a text")
        body = {
            "command_name": command_name,
            "command_args": args,
            "mode": self._pick_mode(args, mode),
            "strategy": strategy,
            "wait_seconds": server_wait,
            "progress": progress,
        }
        realm_ref = _realm_ref_of(realm) if realm is not None else None
        return _as_dict(self._request("/command/call", body, realm_ref=realm_ref)) or {}

    def get_commands(self, realm: Optional[str] = None) -> dict:
        """The commands of a realm you may use (None = public realm)."""
        return _as_dict(self._run_realm_request("/realm/commands", {}, realm).get("commands")) or {}
    # endregion

    # region public API: realms + client
    def create_realm(self, realm_type: str, realm_name: str, *, access_key: Optional[str] = None,
                     restricted_to_owner: bool = False) -> Optional[str]:
        """Creates a realm (public | protected | private). Returns its address."""
        body = _put({"realm_type": realm_type, "realm_name": realm_name, "restricted_to_owner": restricted_to_owner},
                    access_key=access_key)
        return _text((_as_dict(self._request("/realm/create", body)) or {}).get("realm_address"))

    def join_realm(self, realm_address: Optional[str] = None, *, access_key: Optional[str] = None,
                   code: Optional[str] = None, server_url: Optional[str] = None) -> Optional[str]:
        """Joins a realm by address (+ access key) or by invitation code (+ server URL). Returns the address.
        Joined realms are joined again after a re-registration."""
        body = _put({}, realm_address=realm_address, access_key=access_key, code=code, server_url=server_url)
        address = _text((_as_dict(self._request("/realm/join", body)) or {}).get("realm_address"))
        if address is not None:
            # An invitation code works once - joining again uses address + access key
            self._realms[address] = _put({"realm_address": address}, access_key=access_key)
        return address

    def leave_realm(self, realm: str) -> dict:
        self._realms.pop(realm, None)
        return _as_dict(self._request("/realm/leave", {"realm_address": realm})) or {}

    def get_realm_info(self, realm: Optional[str] = None) -> dict:
        return self._run_realm_request("/realm/info", {}, realm)

    def create_code(self, realm: str, *, expires_in_minutes: Optional[float] = None, max_uses: Optional[int] = None,
                    roles: Optional[List[str]] = None, preferred_code: Optional[str] = None) -> Optional[str]:
        """Invitation code (8 characters) for a realm you own."""
        body = _put({"realm_address": realm}, expires_in_minutes=expires_in_minutes, max_uses=max_uses, roles=roles,
                    preferred_code=preferred_code)
        return _text((_as_dict(self._request("/realm/code/create", body)) or {}).get("code"))

    def get_me(self) -> dict:
        """Information about this client (client_ip, name, realms, direct_policy, ...)."""
        return _as_dict(self._request("/client/me", {})) or {}

    def set_direct_policy(self, mode: Optional[str] = None, *, allow: Optional[List[str]] = None,
                          block: Optional[List[str]] = None) -> dict:
        """Who may send this client direct messages: mode everyone | allowlist | nobody; allow / block: client IPs or
        server URLs (block always wins)."""
        return _as_dict(self._request("/client/direct", _put({}, mode=mode, allow=allow, block=block))) or {}

    def raw(self, path: str, body: Optional[dict] = None) -> Any:
        """Any other Bridge endpoint: client.raw("/message/status", {"message_id": id}). The session is added."""
        if not path.startswith("/"):
            path = "/" + path
        return self._request(path, body or {})

    def wait_closed(self, timeout: Optional[float] = None) -> bool:
        """Blocks until close() was called (e.g. by a handler) - for programs that only react to messages. Ctrl+C
        works meanwhile. Returns True if the client is closed."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self._stop.is_set():
            step = 0.5 if deadline is None else min(0.5, deadline - time.monotonic())
            if step <= 0:
                break
            self._stop.wait(step)
        return self._stop.is_set()

    def close(self) -> None:
        """Stops the client and cleans up on the server: ephemeral clients are deleted, the others unsubscribe their
        topics, remove their commands and log out."""
        with self._close_lock:
            if self._close_started or self._state is State.CLOSED:
                return
            self._close_started = True
        with self._latest_lock:
            self._latest.clear()  # values that did not go out are not sent any more
        for handler in tuple(self._close_handlers):
            try:
                handler()
            except Exception as error:
                self._warn("on_close: " + repr(error))
        # From here on nothing may log in or register again (a running poll would otherwise bring the client back)
        self._closing = True
        self._receiving = False
        if self._state is State.CONNECTED and self._token is not None:
            deleted = False
            if self._ephemeral:
                try:
                    self._request("/client/delete", {"password": self._password}, connect_wait=0)
                    deleted = True
                except Exception:
                    pass  # older server: clean up by hand below
            if not deleted:
                with self._topics_lock:
                    topics = list(self._topics)
                for entry in topics:
                    try:
                        self._request("/realm/topic/unsubscribe", {"topic": entry.topic}, connect_wait=0,
                                      realm_ref=entry.realm_ref)
                    except Exception:
                        pass  # best effort
                with self._commands_lock:
                    commands = list(self._commands)
                for command in commands:
                    try:
                        self._request("/realm/command/remove", {"command_name": command.name}, connect_wait=0,
                                      realm_ref=command.realm_ref)
                    except Exception:
                        pass  # best effort
                try:
                    self._request("/client/logout", {}, connect_wait=0)
                except Exception:
                    pass  # best effort
        self._online = False
        self._token = None
        self._set_state(State.CLOSED)
        self._stop.set()
        self._http.close()  # aborts the running long poll
        with self._response_lock:
            waiters = list(self._waiters.values())
            self._waiters.clear()
        for waiter in waiters:
            _reject(waiter, BridgeError("DESTROYED", "The client was closed"))
        self._callbacks_open = False
        self._callbacks.put(None)  # the callback thread ends after what is already queued
        _live_clients.discard(self)
    # endregion


def _items_of(data: Any) -> List[dict]:
    answer = _as_dict(data)
    if answer is None:
        return []
    messages = answer.get("messages")
    if isinstance(messages, list):
        return [item for item in messages if isinstance(item, dict)]
    if answer.get("message") is not None:
        return [answer]  # older Bridge servers answer with a single message
    return []


def _event_key(item: dict) -> Optional[str]:
    """"sender|realm|topic" of a one-piece event, None for everything else."""
    meta = _as_dict(item.get("message"))
    content = _as_dict(item.get("content"))
    if meta is None or content is None or meta.get("content_type") != "event":
        return None
    return f"{_text(meta.get('sender_ip'))}|{_text(content.get('realm_address'))}|{_text(content.get('topic'))}"
