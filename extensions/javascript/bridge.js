/**
 * Bridge for JavaScript - one Bridge client per BridgeClient (one client IP). Runs unchanged in modern browsers and
 * in Node 18+ (global fetch, AbortController, crypto.subtle, DecompressionStream). One file, ES module, no
 * dependencies.
 *
 *   import { BridgeClient } from "./bridge.js";
 *   const client = new BridgeClient({ server: "https://my-pc.tailnet.ts.net", name: "My page" });
 *   await client.subscribe(null, "chat", (data, event) => console.log(event.senderIp, data));
 *   await client.publish(null, "chat", { text: "Hello" });
 *   client.publishLatest(null, "position", { x: 1 });            // only the newest counts, does not wait
 *   await client.hostCommand(null, "add", (args) => args.a + args.b);
 *   const three = await client.call("add", { a: 1, b: 2 });
 *
 * On a website that a host app (BridgeControll) serves under <server url>/site/:
 *   new BridgeClient({ server: BridgeClient.serverFromPage(), name: "My page" })
 *
 * Does everything around the connection by itself (like the Java and Roblox extensions): register / login in the
 * background, renew the session 2 minutes before it runs out, log in again on SESSION_INVALID, register again after a
 * Bridge restart without backup (and join the realms, subscribe the topics, host the commands again), poll in the
 * background (many messages per request), check safe messages with SHA-256, unpack compressed ones, clean up on
 * close() - in a browser also when the page goes away (pagehide, fetch keepalive).
 *
 * Every method returns a Promise. Listeners and topic handlers run one after the other, in the order the messages
 * arrived (a handler that returns a Promise is awaited before the next one runs); command handlers run on their own.
 * Bridge stays pull-only: the client always asks (long polling), Bridge never pushes.
 */

const ADDRESS_SPLIT = "<|BRIDGE_IP_SPLIT|>";
const FATAL = new Set(["INVALID_CREDENTIALS", "ALREADY_EXISTS", "ARGUMENT_ERROR", "DESTROYED", "BRIDGE_URL_MISSING"]);
const BRIDGE_ROUTES = new Set(["admin", "server", "s2s", "client", "message", "command", "realm", "express", "agent",
  "conversation", "friends", "site"]);
const PUBLIC = "public";
const PASSWORD_PREFIX = "bridge-js-password|";

// region errors
/**
 * An error of Bridge or of the connection. `id` is the Bridge error ID ("SESSION_INVALID", "RECIPIENT_NOT_FOUND", ...)
 * or one of the extension's own: UNREACHABLE, NOT_CONNECTED, TIMEOUT, COMMAND_FAILED, DESTROYED, HASH_MISMATCH,
 * INTERRUPTED, HANDLER_ERROR, SCRIPT_ERROR, COMPRESSION_UNSUPPORTED, ALREADY_ANSWERED, ARGUMENT_ERROR.
 */
export class BridgeError extends Error {
  constructor(id, message, { status = 0, path = null, details = null, cause } = {}) {
    super(`[Bridge] ${id}: ${message}${path != null ? ` (${path}${status ? ` -> ${status}` : ""})` : ""}`,
      cause !== undefined ? { cause } : undefined);
    this.name = "BridgeError";
    this.id = id;
    this.text = message;
    this.status = status;
    this.path = path;
    this.details = details;
  }
}

const destroyed = (text = "The client was closed") => new BridgeError("DESTROYED", text);
const argumentError = (text) => new BridgeError("ARGUMENT_ERROR", text);

function asBridgeError(error) {
  if (error instanceof BridgeError) {
    return error;
  }
  const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  return new BridgeError("SCRIPT_ERROR", text, { cause: error });
}

function isConnectionProblem(error) {
  return error instanceof BridgeError && (error.id === "NOT_CONNECTED" || error.id === "UNREACHABLE");
}
// endregion

// region small helpers
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const obj = (value) => (isObject(value) ? value : {});
const str = (value) => (value == null ? null : String(value));
const num = (value, fallback) => (typeof value === "number" && Number.isFinite(value) ? value : fallback);
const orNull = (value) => (value === undefined ? null : value);

/** JSON text of a value; NaN / Infinity / BigInt are refused (JSON.stringify would silently send null). */
function toJson(value) {
  return JSON.stringify(orNull(value), (key, item) => {
    if (typeof item === "number" && !Number.isFinite(item)) {
      throw argumentError(`${item} is not a JSON number${key ? ` ("${key}")` : ""}`);
    }
    if (typeof item === "bigint") {
      throw argumentError(`BigInt cannot be sent as JSON${key ? ` ("${key}")` : ""}`);
    }
    return item;
  });
}

/** UTF-8 byte length of a text; stops counting once it is above `stop`. */
function utf8Length(text, stop = Infinity) {
  let bytes = 0;
  for (let index = 0; index < text.length && bytes <= stop; index++) {
    const code = text.charCodeAt(index);
    if (code < 0x80) {
      bytes += 1;
    } else if (code < 0x800) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff && index + 1 < text.length
        && (text.charCodeAt(index + 1) & 0xfc00) === 0xdc00) {
      bytes += 4;
      index++;
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

const toHex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

function describe(error) {
  if (!error) {
    return "unknown error";
  }
  const cause = error.cause ? ` (${error.cause.code || error.cause.message || error.cause})` : "";
  return `${error.name || "Error"}: ${error.message || error}${cause}`;
}

function isNode() {
  return typeof process !== "undefined" && process.versions != null && process.versions.node != null;
}

let webCryptoPromise = null;

/** globalThis.crypto - or, on Node 18 (no global crypto there by default), node:crypto's webcrypto. */
function webCrypto() {
  if (!webCryptoPromise) {
    webCryptoPromise = (async () => {
      if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === "function") {
        return globalThis.crypto;
      }
      if (isNode()) {
        try {
          const name = "node:crypto"; // not a static import: the file must load in browsers too
          return (await import(name)).webcrypto || null;
        } catch {
          return null;
        }
      }
      return null;
    })();
  }
  return webCryptoPromise;
}

// SHA-256 in plain JavaScript: crypto.subtle only exists in secure contexts (https, localhost) - a page over plain
// http in the LAN has none, and compressed / safe messages must still be checked there.
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function sha256Fallback(data) {
  const length = data.length;
  const padded = new Uint8Array(Math.ceil((length + 9) / 64) * 64);
  padded.set(data);
  padded[length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(length / 0x20000000));
  view.setUint32(padded.length - 4, (length * 8) >>> 0);
  const hash = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19]);
  const w = new Uint32Array(64);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4);
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15];
      const y = w[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let a = hash[0], b = hash[1], c = hash[2], d = hash[3], e = hash[4], f = hash[5], g = hash[6], h = hash[7];
    for (let i = 0; i < 64; i++) {
      const s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const t1 = (h + s1 + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
      const s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
  }
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) {
    outView.setUint32(i * 4, hash[i]);
  }
  return out;
}

/** SHA-256 (hex) of the UTF-8 bytes of a text - crypto.subtle if there is one, else the plain JS version. */
async function sha256(text) {
  const bytes = new TextEncoder().encode(text);
  const crypto = await webCrypto();
  if (crypto && crypto.subtle) {
    try {
      return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
    } catch {
      // e.g. a browser that has subtle but refuses it here - fall back
    }
  }
  return toHex(sha256Fallback(bytes));
}

async function randomSecret() {
  const bytes = new Uint8Array(24);
  const crypto = await webCrypto();
  if (crypto) {
    crypto.getRandomValues(bytes);
  } else {
    for (let index = 0; index < bytes.length; index++) {
      bytes[index] = Math.floor(Math.random() * 256); // no crypto at all - only very old runtimes
    }
  }
  return toHex(bytes);
}

function base64ToBytes(text) {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

/** Base64 + zlib (what Bridge sends for mode compressed, "zlib+base64") -> the original text. */
async function inflate(base64) {
  if (typeof DecompressionStream !== "function") {
    throw new BridgeError("COMPRESSION_UNSUPPORTED", "This runtime has no DecompressionStream - compressed messages "
      + "cannot be unpacked here (needs Node 18+, Chrome 80+, Firefox 113+ or Safari 16.4+)");
  }
  let bytes;
  try {
    bytes = base64ToBytes(base64);
  } catch (error) {
    throw new BridgeError("HASH_MISMATCH", "compressed data is broken (base64): " + describe(error));
  }
  try {
    // "deflate" = the zlib format (RFC 1950) that Python's zlib.compress makes
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate"));
    return await new Response(stream).text();
  } catch (error) {
    throw new BridgeError("HASH_MISMATCH", "compressed data is broken: " + describe(error));
  }
}

/** "my-pc.ts.net/admin/" -> "https://my-pc.ts.net" (scheme added, Bridge paths like /admin cut, no trailing /).
 *  A server path in front is kept: "https://pc.ts.net:10000/momentum/site/" -> "https://pc.ts.net:10000/momentum". */
export function normalizeServer(url) {
  if (typeof url !== "string" || !url.trim()) {
    throw argumentError("server URL is required");
  }
  let text = url.trim();
  if (!text.startsWith("http://") && !text.startsWith("https://")) {
    text = "https://" + text;
  }
  const schemeEnd = text.indexOf("://") + 3;
  const scheme = text.slice(0, schemeEnd);
  const rest = text.slice(schemeEnd);
  let cut = rest.length;
  for (const stop of ["/", "?", "#"]) {
    const index = rest.indexOf(stop);
    if (index >= 0 && index < cut) {
      cut = index;
    }
  }
  let host = rest.slice(0, cut).toLowerCase();
  if (scheme === "https://" && host.endsWith(":443")) {
    host = host.slice(0, -4);
  } else if (scheme === "http://" && host.endsWith(":80")) {
    host = host.slice(0, -3);
  }
  let path = rest.slice(cut);
  const query = path.indexOf("?");
  if (query >= 0) {
    path = path.slice(0, query);
  }
  const hash = path.indexOf("#");
  if (hash >= 0) {
    path = path.slice(0, hash);
  }
  let kept = "";
  for (const segment of path.split("/")) {
    if (!segment) {
      continue;
    }
    if (BRIDGE_ROUTES.has(segment.toLowerCase())) {
      break;
    }
    kept += "/" + segment;
  }
  return scheme + host + kept;
}

/** The server URL of a page under <server url>/site/: everything before the first "/site" segment. */
export function serverFromPage(pageUrl) {
  const candidates = pageUrl != null ? [String(pageUrl)]
    : [globalThis.document && globalThis.document.baseURI, globalThis.location && globalThis.location.href]
      .filter((value) => typeof value === "string" && value);
  if (candidates.length === 0) {
    throw argumentError("serverFromPage() only works on a web page (no document / location here) - give the server URL");
  }
  for (const candidate of candidates) {
    let url;
    try {
      url = new URL(candidate);
    } catch {
      continue;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      continue;
    }
    const segments = url.pathname.split("/");
    const index = segments.findIndex((segment) => segment.toLowerCase() === "site");
    if (index > 0) {
      return normalizeServer(url.origin + segments.slice(0, index).join("/"));
    }
  }
  throw argumentError(`The page ${candidates[0]} is not under <server url>/site/ - give the server URL instead`);
}
// endregion

// region public types
/** A task: a call of a command this client hosts. Answer it once with respond() (or fail()). */
export class Task {
  #client;
  #answered = false;

  constructor(client, meta, content) {
    this.#client = client;
    this.meta = meta;
    this.id = str(meta.message_id);
    this.callerIp = str(meta.sender_ip);
    this.command = str(content.command_name);
    this.args = orNull(content.command_args);
    this.realm = str(content.realm_address);
    this.acceptsProgress = content.accepts_progress === true;
  }

  get answered() {
    return this.#answered;
  }

  /** Answers the call (any JSON value). */
  async respond(content) {
    if (this.#answered) {
      throw new BridgeError("ALREADY_ANSWERED", "This task was answered already");
    }
    this.#answered = true;
    return obj(await this.#client._request("/command/respond", {
      task_id: this.id, content: orNull(content), mode: this.#client._pickMode(content, null),
    }));
  }

  /** Answers with an error - the caller's call() throws COMMAND_FAILED with this text. */
  fail(message) {
    return this.respond({ bridge_error: String(message) });
  }

  /** Progress for the caller (only delivered if the caller asked for it with progress "latest" / "all"). */
  async progress(percent, content) {
    if (!this.acceptsProgress) {
      return { delivered: false, reason: "caller_does_not_accept_progress" };
    }
    const body = { task_id: this.id, content: orNull(content) };
    if (percent != null) {
      body.percent = percent;
    }
    return obj(await this.#client._request("/command/progress", body));
  }
}
// endregion

/** One Bridge client (one client IP). See the top of this file. */
export class BridgeClient {
  static ADDRESS_SPLIT = ADDRESS_SPLIT;

  static State = Object.freeze({
    IDLE: "idle", CONNECTING: "connecting", CONNECTED: "connected", RECONNECTING: "reconnecting", FAILED: "failed",
    CLOSED: "closed",
  });

  /** "my-pc.ts.net/admin/" -> "https://my-pc.ts.net" (see normalizeServer). */
  static normalizeServer(url) {
    return normalizeServer(url);
  }

  /** The server URL for a page under <server url>/site/ (from document.baseURI / location, or the given URL). */
  static serverFromPage(pageUrl) {
    return serverFromPage(pageUrl);
  }

  /** SHA-256 (hex) of the UTF-8 bytes of a text. */
  static sha256(text) {
    return sha256(text);
  }

  /**
   * new BridgeClient({ server, name, password, identitySecret, clientIp, ephemeral, pollWaitSeconds: 20,
   *   pollIntervalMs: 50, maxMessages: 50, connectTimeout: 30000, sessionMarginSeconds: 120, ignoreOwnEvents: true,
   *   autoStart: true, receive: true, closeOnPageHide: true, debug, warn })
   * or new BridgeClient(server, { ...the rest }).
   */
  constructor(serverOrOptions, moreOptions) {
    const given = typeof serverOrOptions === "string"
      ? { ...(moreOptions || {}), server: serverOrOptions } : { ...(serverOrOptions || {}) };
    const options = {
      name: "JavaScript client",
      password: null,
      identitySecret: null,
      clientIp: null,
      ephemeral: null,
      pollWaitSeconds: 20,
      pollIntervalMs: 50,
      maxMessages: 50,
      connectTimeout: 30000,
      sessionMarginSeconds: 120,
      ignoreOwnEvents: true,
      autoStart: true,
      receive: true,
      closeOnPageHide: true,
      debug: null,
      warn: (message) => console.warn(message),
    };
    for (const [key, value] of Object.entries(given)) {
      if (value !== undefined) {
        options[key] = value;
      }
    }
    if (options.identitySecret != null && String(options.identitySecret).length < 32) {
      throw argumentError("identitySecret must have at least 32 characters");
    }
    if (options.debug === true) {
      options.debug = (message) => console.debug(message);
    }
    this._options = options;
    this._server = normalizeServer(options.server);
    this._identity = options.identitySecret != null ? String(options.identitySecret) : null;
    this._password = options.password != null ? String(options.password) : null; // else made when connecting
    this._ephemeral = options.ephemeral != null ? !!options.ephemeral
      : options.password == null && options.identitySecret == null && options.clientIp == null;
    this._clientIp = options.clientIp != null ? String(options.clientIp) : null;
    this._receiving = !!options.receive;

    this._serverUrl = null;
    this._publicRealm = null;
    this._limits = {};
    this._token = null;
    this._tokenExpiresAt = 0;
    this._state = "idle";
    this._online = false;
    this._fatal = null;
    this._everConnected = false;
    this._closing = false;
    this._closePromise = null;
    this._restoring = false;
    this._connecting = false;
    this._polling = false;
    this._renewing = null;
    this._requests = 0;
    this._syncCalls = 0;
    this._generation = 0; // a page that comes back from the back/forward cache starts a new one (see pagehide)
    this._life = new AbortController(); // aborts every open request on close()
    this._pollController = null;
    this._stateWaiters = new Set();
    this._sleeps = new Set();
    this._timers = new Set();
    this._queue = Promise.resolve();
    this._suspended = false;
    this._ipBeforeSuspend = null; // ephemeral client deleted on pagehide: its IP, for onClientIpChanged

    this._topics = []; // { realmRef, topic, handlers: [{ handler, latestOnly }], ready }
    this._commands = []; // { realmRef, name, handler, extra }
    this._realms = new Map(); // address -> join body
    this._waiters = new Map(); // task id -> { resolve, reject }
    this._unclaimed = new Map(); // task id -> response that came before call() knew the task id
    this._closeHandlers = [];
    this._latest = new Map(); // publishLatest: "realmRef|topic" -> newest value that did not go out yet
    this._latestSending = false;
    this._newestEvent = new Map(); // "sender|realm|topic" -> created_at of the newest event latest handlers got
    this._listeners = {
      connected: [], disconnected: [], ipChanged: [], message: [], event: [], task: [], response: [], progress: [],
      error: [],
    };

    if (options.closeOnPageHide && typeof window !== "undefined" && typeof window.addEventListener === "function") {
      this._onPageHide = () => this._pageHide();
      this._onPageShow = (event) => {
        if (event && event.persisted) {
          this._pageShow();
        }
      };
      window.addEventListener("pagehide", this._onPageHide);
      window.addEventListener("pageshow", this._onPageShow);
    }
    if (options.autoStart) {
      this._startConnectLoop();
    }
  }

  // region getters + listeners
  get clientIp() { return this._clientIp; }
  /** The normalized URL this client talks to. */
  get server() { return this._server; }
  /** The URL the server gives itself (part of every address). */
  get serverUrl() { return this._serverUrl; }
  get publicRealm() { return this._publicRealm; }
  get state() { return this._state; }
  get online() { return this._online; }
  get ephemeral() { return this._ephemeral; }
  get requestCount() { return this._requests; }
  get limits() { return this._limits; }
  get name() { return this._options.name; }

  /** (clientIp) once connected (again). */
  onConnected(listener) { return this._on("connected", listener); }
  /** (reason) when the connection is lost. */
  onDisconnected(listener) { return this._on("disconnected", listener); }
  /** (newIp, oldIp) after a re-registration. */
  onClientIpChanged(listener) { return this._on("ipChanged", listener); }
  /** (message) direct messages and other plain message types. */
  onMessage(listener) { return this._on("message", listener); }
  /** (event) every topic event (also for topics with handlers). */
  onEvent(listener) { return this._on("event", listener); }
  /** (task) tasks for commands without a handler - answer them with task.respond(...). */
  onTask(listener) { return this._on("task", listener); }
  /** (response) responses no call() waits for (callNoWait, late answers). */
  onResponse(listener) { return this._on("response", listener); }
  /** (progress) progress of a call that asked for it. */
  onProgress(listener) { return this._on("progress", listener); }
  /** (error: BridgeError) problems in the background. */
  onError(listener) { return this._on("error", listener); }

  /** Runs at the start of close() while the client is still connected (e.g. a last "bye"). May return a Promise. */
  onClose(handler) {
    if (typeof handler !== "function") {
      throw argumentError("onClose needs a function");
    }
    this._closeHandlers.push(handler);
    return this;
  }

  _on(kind, listener) {
    if (typeof listener !== "function") {
      throw argumentError(`on${kind[0].toUpperCase()}${kind.slice(1)} needs a function`);
    }
    this._listeners[kind].push(listener);
    return this;
  }

  /** Runs a callback after all earlier ones (arrival order); a returned Promise is awaited first. */
  _enqueue(callback, onError) {
    if (this._state === "closed") {
      return;
    }
    this._queue = this._queue.then(async () => {
      try {
        await callback();
      } catch (error) {
        onError(error);
      }
    });
  }

  _fire(listeners, ...args) {
    for (const listener of listeners) {
      this._enqueue(() => listener(...args), (error) => this._warn("listener failed: " + describe(error)));
    }
  }

  _debug(message) {
    if (typeof this._options.debug === "function") {
      try {
        this._options.debug(`[Bridge:${this._options.name}] ${message}`);
      } catch {
        // never break the client because of the log
      }
    }
  }

  _warn(message) {
    if (typeof this._options.warn === "function") {
      try {
        this._options.warn(`[Bridge:${this._options.name}] ${message}`);
      } catch {
        // never break the client because of the log
      }
    }
  }

  _report(error) {
    const bridgeError = asBridgeError(error);
    this._debug("error: " + bridgeError.message);
    this._fire(this._listeners.error, bridgeError);
  }

  _setOnline(value, reason) {
    if (this._online === value) {
      return;
    }
    this._online = value;
    if (value) {
      this._fire(this._listeners.connected, this._clientIp);
    } else {
      this._warn("connection lost: " + reason);
      this._fire(this._listeners.disconnected, reason);
    }
  }
  // endregion

  // region timers (all of them end on close(), so a Node program can exit)
  _sleep(millis) {
    return new Promise((resolve, reject) => {
      if (this._state === "closed") {
        reject(destroyed());
        return;
      }
      const entry = {
        reject,
        timer: setTimeout(() => {
          this._sleeps.delete(entry);
          resolve();
        }, Math.max(0, millis)),
      };
      this._sleeps.add(entry);
    });
  }

  _later(callback, millis) {
    const timer = setTimeout(() => {
      this._timers.delete(timer);
      callback();
    }, millis);
    this._timers.add(timer);
  }

  /** Waits until the state changes (or at most `millis`). */
  _waitChange(millis) {
    return new Promise((resolve) => {
      const done = () => {
        clearTimeout(timer);
        this._stateWaiters.delete(done);
        resolve();
      };
      const timer = setTimeout(done, Math.max(1, millis));
      this._stateWaiters.add(done);
    });
  }

  _notify() {
    for (const done of [...this._stateWaiters]) {
      done();
    }
  }

  _setState(value) {
    this._state = value;
    this._notify();
  }
  // endregion

  // region HTTP
  async _raw(method, path, body, waitSeconds, signal) {
    let text;
    if (body != null) {
      try {
        text = toJson(body);
      } catch (error) {
        throw new BridgeError("ARGUMENT_ERROR", "Content cannot be sent as JSON: "
          + (error instanceof BridgeError ? error.text : describe(error)), { path });
      }
    }
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, (waitSeconds + 20) * 1000);
    const abort = () => controller.abort();
    const signals = [this._life.signal, signal].filter(Boolean);
    for (const item of signals) {
      if (item.aborted) {
        controller.abort();
      } else {
        item.addEventListener("abort", abort, { once: true });
      }
    }
    this._requests++;
    let response;
    let answer;
    try {
      response = await fetch(this._server + path, {
        method,
        headers: body != null ? { "Content-Type": "application/json" } : undefined,
        body: text,
        signal: controller.signal,
      });
      answer = await response.text();
    } catch (error) {
      if (!timedOut && signals.some((item) => item.aborted)) {
        throw new BridgeError("INTERRUPTED", "interrupted", { path });
      }
      throw new BridgeError("UNREACHABLE", timedOut ? `no answer within ${waitSeconds + 20} s` : describe(error),
        { path, cause: error });
    } finally {
      clearTimeout(timer);
      for (const item of signals) {
        item.removeEventListener("abort", abort);
      }
    }
    let data = null;
    if (answer) {
      try {
        data = JSON.parse(answer);
      } catch {
        // not JSON (e.g. a proxy error page)
      }
    }
    return { status: response.status, data, body: answer };
  }

  /**
   * One authenticated request: waits for the connection, renews the session in time, logs in again on
   * SESSION_INVALID, waits while the server starts. options: { auth, internal, connectWait, realmRef, signal }
   */
  async _request(path, body, options = {}) {
    const auth = options.auth !== false;
    const payload = { ...(body || {}) };
    let startingTries = 20;
    let renewed = false;
    const wait = num(payload.wait_seconds, 0);
    for (;;) {
      let usedToken = null;
      if (auth) {
        await this._ensureConnected(options.connectWait != null ? options.connectWait : this._options.connectTimeout,
          options.internal);
        if (Date.now() / 1000 >= this._tokenExpiresAt - this._options.sessionMarginSeconds) {
          await this._renewSession(this._token);
        }
        usedToken = this._token;
        payload.session_token = usedToken;
        if (options.realmRef != null) {
          payload.realm_address = this._resolveRealm(options.realmRef);
        }
      }
      const result = await this._raw("POST", path, payload, wait, options.signal);
      if (result.status === 200) {
        return result.data;
      }
      const error = errorFrom(result, path);
      if (error.id === "SERVER_STARTING" && startingTries-- > 0) {
        await this._sleep(500);
      } else if (error.id === "SESSION_INVALID" && auth && !renewed && !this._closing && this._state !== "closed") {
        renewed = true;
        await this._renewSession(usedToken);
      } else {
        throw error;
      }
    }
  }
  // endregion

  // region connection
  /** Waits until connected (starts connecting if needed). Resolves with the client IP. */
  async connect(timeout = this._options.connectTimeout) {
    await this._ensureConnected(timeout);
    return this._clientIp;
  }

  /** true if connected within the time (milliseconds). */
  async waitForConnection(timeout = this._options.connectTimeout) {
    try {
      await this._ensureConnected(timeout);
      return true;
    } catch {
      return false;
    }
  }

  _startConnectLoop() {
    if (this._connecting) {
      return;
    }
    this._connecting = true;
    this._fatal = null;
    const generation = this._generation;
    this._connectLoop(generation).catch(() => {}).finally(() => {
      if (generation === this._generation) {
        this._connecting = false;
      }
      this._notify();
    });
  }

  async _connectLoop(generation) {
    let delay = 1000;
    try {
      while (this._state !== "closed" && !this._closing && generation === this._generation) {
        try {
          await this._doConnect(generation);
          return;
        } catch (error) {
          const bridgeError = asBridgeError(error);
          if (bridgeError.id === "INTERRUPTED" || generation !== this._generation) {
            return;
          }
          if (FATAL.has(bridgeError.id)) {
            if (bridgeError.id !== "DESTROYED") {
              this._fatal = bridgeError;
              this._warn(bridgeError.message);
              this._report(bridgeError);
              this._setState("failed");
            }
            return;
          }
          this._report(bridgeError);
        }
        await this._sleep(delay);
        delay = Math.min(delay * 2, 15000);
      }
    } catch {
      // closed while waiting
    }
  }

  _ready(internal) {
    // After a (re)connect the client first sets up its realms / topics / commands again - only then it is ready
    return this._state === "connected" && (internal || !this._restoring);
  }

  async _ensureConnected(timeout, internal = false) {
    if (this._ready(internal)) {
      return; // also while closing: the cleanup requests of close() still go out
    }
    if (this._state === "closed" || this._closing) {
      throw destroyed();
    }
    this._startConnectLoop();
    const deadline = Date.now() + num(timeout, Infinity);
    while (!this._ready(internal)) {
      if (this._state === "closed" || this._closing) {
        throw destroyed();
      }
      if (this._fatal && !this._connecting) {
        throw this._fatal;
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new BridgeError("NOT_CONNECTED", `No connection to ${this._server} (yet)`);
      }
      await this._waitChange(Math.min(remaining, 1000));
    }
  }

  async _waitForServer() {
    let delay = 1000;
    let warned = false;
    for (;;) {
      if (this._state === "closed" || this._closing) {
        throw destroyed();
      }
      let reason;
      try {
        const result = await this._raw("GET", "/server/status", null, 0);
        const data = isObject(result.data) ? result.data : null;
        if (result.status === 200 && data && "status" in data) {
          if (typeof data.url !== "string") {
            throw new BridgeError("BRIDGE_URL_MISSING", "The Bridge server has no public URL set",
              { status: 200, path: "/server/status" });
          }
          if (data.ready !== false) {
            return data;
          }
          await this._sleep(500);
          continue;
        }
        reason = "answer " + result.status;
      } catch (error) {
        const bridgeError = asBridgeError(error);
        if (FATAL.has(bridgeError.id) || bridgeError.id === "INTERRUPTED") {
          throw bridgeError;
        }
        reason = bridgeError.message;
      }
      if (!warned) {
        warned = true;
        this._warn(`${this._server} not reachable (${reason}) - trying again`);
      }
      this._setOnline(false, reason);
      await this._sleep(delay);
      delay = Math.min(delay * 2, 15000);
    }
  }

  async _getPassword() {
    if (this._password == null) {
      this._password = this._identity != null ? await sha256(PASSWORD_PREFIX + this._identity) : await randomSecret();
    }
    return this._password;
  }

  async _login() {
    const data = obj(await this._request("/client/login",
      { client_ip: this._clientIp, password: await this._getPassword() }, { auth: false }));
    this._token = str(data.session_token);
    this._tokenExpiresAt = Date.now() / 1000 + num(data.remaining_minutes, 60) * 60;
    this._debug(`logged in, session for ${data.remaining_minutes} minutes`);
  }

  async _register() {
    const body = { name: this._options.name, password: await this._getPassword() };
    if (this._identity != null) {
      body.identity_secret = this._identity;
    }
    try {
      const data = obj(await this._request("/client/register", body, { auth: false }));
      this._clientIp = str(data.client_ip);
      this._debug("registered as " + this._clientIp);
    } catch (error) {
      if (error instanceof BridgeError && error.id === "ALREADY_EXISTS") {
        throw new BridgeError("ALREADY_EXISTS", "This identitySecret is already used by a client with another password",
          { status: error.status, path: error.path });
      }
      throw error;
    }
  }

  async _doConnect(generation) {
    this._setState(this._everConnected ? "reconnecting" : "connecting");
    const status = await this._waitForServer();
    this._serverUrl = str(status.url);
    this._publicRealm = str(status.public_realm_address);
    this._limits = obj(status.limits);

    const oldIp = this._clientIp != null ? this._clientIp : this._ipBeforeSuspend;
    this._ipBeforeSuspend = null;
    if (this._identity != null) {
      // Same formula as the server: the IP of a stable identity is known before registering
      this._clientIp = this._serverUrl + ADDRESS_SPLIT
        + (await sha256("bridge-identity|" + this._serverUrl + "|" + this._identity)).slice(0, 32);
    }
    if (this._clientIp != null) {
      try {
        await this._login();
      } catch (error) {
        const gone = error instanceof BridgeError && error.id === "INVALID_CREDENTIALS";
        if (!(gone && (this._identity != null || this._ephemeral))) {
          throw error;
        }
        this._debug("client unknown on the server - registering again");
        await this._register();
        await this._login();
      }
    } else {
      await this._register();
      await this._login();
    }
    if (this._closing || this._state === "closed" || generation !== this._generation) {
      this._forgetLateLogin();
      throw destroyed();
    }

    // Realms / topics / commands this client should have (after a re-registration, or wished for before the first
    // connection was there): set them up (again) before anybody else uses the connection. Twice does no harm.
    this._restoring = this._realms.size > 0 || this._topics.length > 0 || this._commands.length > 0;
    this._setState("connected");
    if (this._restoring) {
      try {
        await this._restore();
      } finally {
        this._restoring = false;
        this._notify();
      }
    }
    this._everConnected = true;
    if (oldIp != null && oldIp !== this._clientIp) {
      const newIp = this._clientIp;
      for (const listener of this._listeners.ipChanged) {
        this._enqueue(() => listener(newIp, oldIp), (error) => this._warn("listener failed: " + describe(error)));
      }
    }
    this._setOnline(true, null);
    if (this._receiving) {
      this._startPollLoop();
    }
  }

  /** close() came while the login was on its way: do not leave a session (or an ephemeral client) behind. */
  _forgetLateLogin() {
    const token = this._token;
    this._token = null;
    if (!token) {
      return;
    }
    const body = this._ephemeral ? { session_token: token, password: this._password } : { session_token: token };
    sendOnUnload(this._server + (this._ephemeral ? "/client/delete" : "/client/logout"), body);
  }

  async _renewSession(oldToken) {
    if (this._closing) {
      throw destroyed("The client is closing");
    }
    while (this._renewing) {
      await this._renewing.catch(() => {});
    }
    if (this._token !== oldToken) {
      return; // renewed by another request already
    }
    let reconnect = false;
    const job = (async () => {
      try {
        await this._login();
      } catch (error) {
        if (error instanceof BridgeError && error.id === "INVALID_CREDENTIALS"
            && (this._identity != null || this._ephemeral)) {
          // The client is gone on the server: connect again from the start (register + restore)
          this._token = null;
          if (this._state === "connected") {
            this._setState("reconnecting");
          }
          reconnect = true;
        } else {
          throw error;
        }
      }
    })();
    this._renewing = job;
    try {
      await job;
    } finally {
      if (this._renewing === job) {
        this._renewing = null;
      }
    }
    if (reconnect) {
      await this._ensureConnected(this._options.connectTimeout);
    }
  }

  async _restore() {
    for (const joinBody of [...this._realms.values()]) {
      try {
        await this._request("/realm/join", joinBody, { internal: true });
      } catch (error) {
        if (!(error instanceof BridgeError && error.id === "ALREADY_EXISTS")) {
          this._report(error);
        }
      }
    }
    for (const entry of [...this._topics]) {
      try {
        await this._request("/realm/topic/subscribe", { topic: entry.topic }, { realmRef: entry.realmRef, internal: true });
      } catch (error) {
        this._report(error);
      }
    }
    for (const entry of [...this._commands]) {
      try {
        await this._createCommand(entry, true);
      } catch (error) {
        if (!(error instanceof BridgeError && error.id === "ALREADY_EXISTS")) {
          this._report(error);
        }
      }
    }
    this._debug(`restored ${this._topics.length} topics, ${this._commands.length} commands`);
  }
  // endregion

  // region receiving
  _startPollLoop() {
    if (this._polling) {
      return;
    }
    this._polling = true;
    const generation = this._generation;
    this._pollLoop(generation).catch(() => {}).finally(() => {
      if (generation === this._generation) {
        this._polling = false;
      }
    });
  }

  async _pollLoop(generation) {
    let failures = 0;
    const alive = () => generation === this._generation && this._state !== "closed" && !this._closing
      && this._receiving && !this._fatal;
    try {
      while (alive()) {
        const started = Date.now();
        const maxWait = num(this._limits.max_wait_seconds, 25);
        const maxPoll = num(this._limits.max_poll_messages, 100);
        try {
          const controller = new AbortController();
          this._pollController = controller;
          const data = await this._request("/message/poll", {
            wait_seconds: Math.min(this._options.pollWaitSeconds, maxWait),
            max_messages: Math.min(this._options.maxMessages, maxPoll),
          }, { connectWait: Infinity, signal: controller.signal });
          if (!alive()) {
            break;
          }
          if (failures > 0) {
            failures = 0;
            this._setOnline(true, null);
          }
          const items = itemsOf(data);
          // latest subscriptions only get the newest event per sender and topic of this batch
          const newest = new Map();
          items.forEach((item, index) => {
            const key = eventKey(item);
            if (key != null) {
              newest.set(key, index);
            }
          });
          for (let index = 0; index < items.length; index++) {
            const key = eventKey(items[index]);
            try {
              await this._handleItem(items[index], key != null && newest.get(key) !== index);
            } catch (error) {
              this._report(error);
            }
          }
        } catch (error) {
          const bridgeError = asBridgeError(error);
          if (this._closing || this._state === "closed" || bridgeError.id === "INTERRUPTED"
              || generation !== this._generation) {
            break;
          }
          failures++;
          if (bridgeError.id === "UNREACHABLE" || bridgeError.id.startsWith("HTTP_")) {
            this._setOnline(false, bridgeError.message);
          }
          if (bridgeError.id !== "DESTROYED") {
            this._report(bridgeError);
          }
          await this._sleep(Math.min(1000 * 2 ** Math.min(failures, 4), 15000));
        }
        const rest = this._options.pollIntervalMs - (Date.now() - started);
        if (rest > 0) {
          await this._sleep(rest);
        }
      }
    } catch {
      // closed while waiting
    }
  }

  async _fetchChunked(item) {
    const meta = obj(item.message);
    const pending = str(item.pending_id);
    try {
      const parts = [];
      const count = num(meta.chunk_count, 1);
      for (let index = 0; index < count; index++) {
        const chunk = obj(await this._request("/message/chunk", { pending_id: pending, chunk_index: index }));
        parts.push(str(chunk.chunk) ?? "");
      }
      let text = parts.join("");
      if (meta.encoding === "zlib+base64") {
        text = await inflate(text);
      }
      const digest = await sha256(text);
      if (digest !== meta.sha256) {
        throw new BridgeError("HASH_MISMATCH", "Local SHA-256 check failed", { path: "/message/chunk" });
      }
      await this._request("/message/complete", { pending_id: pending, sha256: digest });
      return JSON.parse(text);
    } catch (error) {
      if (error instanceof BridgeError && error.id === "COMPRESSION_UNSUPPORTED") {
        // Not given back: it would come again at once and fail again forever. Bridge puts it back by itself
        // after 15 minutes (or it expires).
        throw error;
      }
      try {
        await this._request("/message/cancel", { pending_id: pending }); // give it back, it comes again
      } catch {
        // nothing more to do
      }
      throw error;
    }
  }

  /** superseded: a newer event of the same sender and topic came in the same batch (latest subscriptions skip it). */
  async _handleItem(item, superseded) {
    const meta = obj(item.message);
    const content = item.pending_id != null ? await this._fetchChunked(item) : orNull(item.content);
    const kind = str(meta.content_type);
    const sender = str(meta.sender_ip);
    if (kind === "event") {
      if (this._options.ignoreOwnEvents && sender === this._clientIp) {
        return;
      }
      const body = obj(content);
      const event = Object.freeze({
        realm: str(body.realm_address), topic: str(body.topic), data: orNull(body.data), senderIp: sender, meta,
      });
      // latest subscriptions: nothing older than what they already got (two requests can overtake each other)
      const key = `${sender}|${event.realm}|${event.topic}`;
      const createdAt = str(meta.created_at);
      const newestSoFar = this._newestEvent.get(key);
      const stale = superseded || (createdAt != null && newestSoFar != null && createdAt < newestSoFar);
      for (const entry of this._topics) {
        if (entry.topic === event.topic && this._resolveRealm(entry.realmRef) === event.realm) {
          if (entry.handlers.some((registration) => registration.latestOnly) && !stale && createdAt != null) {
            this._newestEvent.set(key, createdAt);
          }
          for (const registration of [...entry.handlers]) {
            if (stale && registration.latestOnly) {
              continue;
            }
            this._enqueue(() => registration.handler(event.data, event), (error) => this._report(
              new BridgeError("HANDLER_ERROR", `topic '${event.topic}': ${describe(error)}`, { cause: error })));
          }
        }
      }
      this._fire(this._listeners.event, event);
    } else if (kind === "task") {
      this._handleTask(meta, obj(content));
    } else if (kind === "response") {
      const taskId = str(meta.causation_id);
      const response = Object.freeze({ taskId, content, senderIp: sender, meta });
      const waiter = taskId != null ? this._waiters.get(taskId) : undefined;
      if (waiter) {
        this._waiters.delete(taskId);
        waiter.resolve(response);
      } else if (taskId != null) {
        this._unclaimed.set(taskId, response); // a fast host can answer before call() knows the task id
        this._later(() => {
          if (this._unclaimed.delete(taskId)) {
            this._fire(this._listeners.response, response);
          }
        }, this._syncCalls > 0 ? 1000 : 0);
      } else {
        this._fire(this._listeners.response, response);
      }
    } else if (kind === "progress") {
      this._fire(this._listeners.progress,
        Object.freeze({ taskId: str(meta.causation_id), content, senderIp: sender, meta }));
    } else {
      this._fire(this._listeners.message, this._message(meta, kind, sender, content));
    }
  }

  _message(meta, kind, sender, content) {
    const client = this;
    const conversationId = str(meta.conversation_id);
    const id = str(meta.message_id);
    return Object.freeze({
      id, type: kind, senderIp: sender, content, mode: str(meta.mode), conversationId,
      verified: meta.verified === true, meta,
      /** Answers in the same conversation. */
      reply(replyContent, options = {}) {
        return client.send(sender, replyContent, { ...options, conversationId, causationId: id });
      },
    });
  }

  _handleTask(meta, content) {
    const task = new Task(this, meta, content);
    const entry = this._findCommand(task.realm, task.command);
    if (!entry) {
      this._fire(this._listeners.task, task);
      return;
    }
    (async () => {
      let result;
      try {
        result = await entry.handler(task.args, task);
      } catch (error) {
        if (!task.answered) {
          try {
            await task.fail(error instanceof Error ? error.message || String(error) : String(error));
          } catch (failed) {
            this._report(failed);
          }
        }
        return;
      }
      if (!task.answered) {
        try {
          await task.respond(result);
        } catch (failed) {
          this._report(failed);
        }
      }
    })();
  }

  _findCommand(realmAddress, name) {
    let byName = null;
    for (const entry of this._commands) {
      if (entry.name === name) {
        if (this._resolveRealm(entry.realmRef) === realmAddress) {
          return entry;
        }
        if (byName == null) {
          byName = entry;
        }
      }
    }
    return byName;
  }
  // endregion

  // region helpers
  _resolveRealm(realmRef) {
    return realmRef === PUBLIC ? this._publicRealm : realmRef;
  }

  _pickMode(content, mode) {
    if (mode != null && mode !== "auto") {
      return mode;
    }
    const limit = num(this._limits.max_fast_message_kib, 64) * 1024 - 1024;
    try {
      return utf8Length(toJson(content), limit) <= limit ? "fast" : "safe";
    } catch {
      return "fast"; // the send reports the real problem
    }
  }

  _createCommand(entry, internal) {
    return this._request("/realm/command/create", { ...entry.extra, command_name: entry.name },
      { realmRef: entry.realmRef, internal });
  }

  async _realmRequest(path, body, realm) {
    return obj(await this._request(path, body, { realmRef: realmRefOf(realm) }));
  }
  // endregion

  // region public API
  /** Sends a direct message. options: { mode (auto | fast | safe | compressed | temporary), conversationId,
   *  causationId, expiresInSeconds }. auto (default) = fast if small, else safe. */
  async send(recipientIp, content, options = {}) {
    options = options || {};
    if (typeof recipientIp !== "string" || !recipientIp) {
      throw argumentError("send needs a recipient IP");
    }
    const mode = this._pickMode(content, options.mode);
    const body = { recipient_ip: recipientIp, content: orNull(content), mode };
    if (options.conversationId != null) {
      body.conversation_id = options.conversationId;
    }
    if (options.causationId != null) {
      body.causation_id = options.causationId;
    }
    if (options.expiresInSeconds != null) {
      body.expires_in_seconds = options.expiresInSeconds;
    } else if (mode === "temporary") {
      body.expires_in_seconds = 60;
    }
    return obj(await this._request("/message/send", body));
  }

  /** The same message to up to 100 clients. options: { mode, conversationId }. */
  async broadcast(recipients, content, options = {}) {
    options = options || {};
    if (!Array.isArray(recipients)) {
      throw argumentError("broadcast needs a list of client IPs");
    }
    const body = { recipients, content: orNull(content), mode: this._pickMode(content, options.mode) };
    if (options.conversationId != null) {
      body.conversation_id = options.conversationId;
    }
    return obj(await this._request("/message/broadcast", body));
  }

  /**
   * Subscribes a topic of a realm (null = public realm of the server). The handler gets (data, event) for every event.
   * options.latestOnly: only the newest event per sender - older ones that are still waiting are skipped (for states
   * like positions: never work through old ones, show the current one). Resolves with { close() }.
   */
  async subscribe(realm, topic, handler, options = {}) {
    if (typeof topic !== "string" || !topic) {
      throw argumentError("subscribe needs a topic");
    }
    if (typeof handler !== "function") {
      throw argumentError("subscribe needs a handler function");
    }
    const latestOnly = options === true || (isObject(options) && options.latestOnly === true);
    const realmRef = realmRefOf(realm);
    let entry = this._topics.find((existing) => existing.topic === topic && existing.realmRef === realmRef);
    if (!entry) {
      entry = { realmRef, topic, handlers: [], ready: null };
      this._topics.push(entry);
      const created = entry;
      // Resolves with null or the error (never rejects, everybody who subscribed meanwhile waits for it)
      entry.ready = this._request("/realm/topic/subscribe", { topic }, { realmRef }).then(() => null, (error) => {
        if (isConnectionProblem(error)) {
          this._warn(`subscribe '${topic}' happens as soon as the server is reachable`);
          return null;
        }
        const index = this._topics.indexOf(created);
        if (index >= 0) {
          this._topics.splice(index, 1);
        }
        return error;
      });
    }
    const registration = { handler, latestOnly };
    entry.handlers.push(registration);
    const failed = await entry.ready;
    if (failed) {
      const index = entry.handlers.indexOf(registration);
      if (index >= 0) {
        entry.handlers.splice(index, 1);
      }
      throw failed;
    }
    const current = entry;
    return {
      realm: realm == null ? PUBLIC : realm,
      topic,
      latestOnly,
      /** Removes the handler (and unsubscribes on the server if it was the last one). */
      close: async () => {
        const index = current.handlers.indexOf(registration);
        if (index < 0) {
          return;
        }
        current.handlers.splice(index, 1);
        const topicIndex = this._topics.indexOf(current);
        if (current.handlers.length === 0 && topicIndex >= 0) {
          this._topics.splice(topicIndex, 1);
          try {
            await this._request("/realm/topic/unsubscribe", { topic }, { realmRef });
          } catch {
            // gone anyway
          }
        }
      },
    };
  }

  /** Publishes data to everybody who subscribed the topic (not back to yourself unless options.includeSelf).
   *  options: { mode, includeSelf }. */
  async publish(realm, topic, data, options = {}) {
    options = options || {};
    if (typeof topic !== "string" || !topic) {
      throw argumentError("publish needs a topic");
    }
    return this._realmRequest("/realm/topic/publish", {
      topic, content: orNull(data), mode: this._pickMode(data, options.mode), include_self: options.includeSelf === true,
    }, realm);
  }

  /** Publish without waiting for anything (game loops): errors go to onError, the Promise never rejects. */
  publishAsync(realm, topic, data, options = {}) {
    return this.publish(realm, topic, data, options).catch((error) => {
      this._report(error);
      return null;
    });
  }

  /**
   * Publishes only the NEWEST value - for states that change all the time (positions, ...). Does not wait: the value
   * replaces an older one of the same topic that has not gone out yet, the newest one is published as soon as the
   * last request is done. Errors go to onError.
   */
  publishLatest(realm, topic, data, options = {}) {
    if (typeof topic !== "string" || !topic) {
      throw argumentError("publishLatest needs a topic");
    }
    if (data === undefined || data === null) {
      throw argumentError("publishLatest needs data");
    }
    if (this._closing || this._state === "closed") {
      return;
    }
    const realmRef = realmRefOf(realm);
    const key = realmRef + "|" + topic;
    this._latest.delete(key); // re-insert: the oldest waiting topic goes first
    this._latest.set(key, { realmRef, topic, data, options });
    if (!this._latestSending) {
      this._latestSending = true;
      this._latestLoop(this._generation).catch(() => {});
    }
  }

  async _latestLoop(generation) {
    for (;;) {
      if (generation !== this._generation) {
        return;
      }
      if (this._latest.size === 0 || this._closing || this._state === "closed") {
        this._latest.clear();
        this._latestSending = false;
        return;
      }
      const [key, value] = this._latest.entries().next().value;
      this._latest.delete(key);
      try {
        await this.publish(value.realmRef, value.topic, value.data, value.options);
      } catch (error) {
        if (this._closing || this._state === "closed") {
          continue;
        }
        this._report(error);
        if (isConnectionProblem(error)) {
          if (!this._latest.has(key)) {
            this._latest.set(key, value); // unless a newer one waits
          }
          try {
            await this._sleep(1000);
          } catch {
            // closing
          }
        }
      }
    }
  }

  /**
   * Hosts a command in a realm (null = public realm). The handler gets (args, task); its return value (or the value
   * of its Promise) is the answer, a thrown error answers with COMMAND_FAILED. extra: { description, signature
   * (BridgeExpress), allowedRoles }. Resolves with { close() }.
   */
  async hostCommand(realm, commandName, handler, extra = {}) {
    if (typeof commandName !== "string" || !commandName) {
      throw argumentError("hostCommand needs a command name");
    }
    if (typeof handler !== "function") {
      throw argumentError("hostCommand needs a handler function");
    }
    const fields = { ...(extra || {}) };
    if (fields.allowedRoles !== undefined) {
      fields.allowed_roles = fields.allowedRoles;
      delete fields.allowedRoles;
    }
    const entry = { realmRef: realmRefOf(realm), name: commandName, handler, extra: fields };
    this._commands.push(entry);
    const remove = () => {
      const index = this._commands.indexOf(entry);
      if (index >= 0) {
        this._commands.splice(index, 1);
        return true;
      }
      return false;
    };
    try {
      await this._createCommand(entry, false);
    } catch (error) {
      if (isConnectionProblem(error)) {
        this._warn(`command '${commandName}' is hosted as soon as the server is reachable`);
      } else if (!(error instanceof BridgeError && error.id === "ALREADY_EXISTS")) {
        remove();
        throw error;
      }
    }
    return {
      realm: realm == null ? PUBLIC : realm,
      name: commandName,
      /** Stops hosting the command. */
      close: async () => {
        if (remove()) {
          try {
            await this._request("/realm/command/remove", { command_name: commandName }, { realmRef: entry.realmRef });
          } catch {
            // gone anyway
          }
        }
      },
    };
  }

  /**
   * Calls a command and waits for the answer. options: { realm (null = all realms of this client, "public" = the
   * public realm), timeout (ms, default 20000), mode, strategy (least_busy | random | fastest), progress
   * (off | latest | all), serverWaitSeconds }.
   */
  async call(commandName, args, options = {}) {
    const opts = { timeout: 20000, ...(options || {}) };
    this._syncCalls++;
    try {
      const timeoutMillis = num(opts.timeout, 20000);
      const maxWait = num(this._limits.max_wait_seconds, 25);
      // With the background poll the answer comes with the next poll (the server must not hold the call: the poll
      // would take the answer away from it). Without polling the server waits for the answer.
      const serverWait = opts.serverWaitSeconds != null ? Math.min(timeoutMillis / 1000, opts.serverWaitSeconds)
        : this._receiving ? 0 : Math.min(timeoutMillis / 1000, maxWait);
      const started = Date.now();
      const result = await this._startCall(commandName, args, opts, serverWait);
      const taskId = str(result.task_id);
      const timeoutError = () => new BridgeError("TIMEOUT",
        `'${commandName}' did not answer within ${timeoutMillis / 1000} s`, { path: "/command/call" });
      let content;
      if (isObject(result.response)) {
        content = orNull(result.response.content);
      } else if (this._unclaimed.has(taskId)) {
        content = this._unclaimed.get(taskId).content;
        this._unclaimed.delete(taskId);
      } else {
        const remaining = timeoutMillis - (Date.now() - started);
        if (remaining <= 0 || !this._receiving) {
          throw timeoutError();
        }
        content = (await new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            this._waiters.delete(taskId);
            reject(timeoutError());
          }, remaining);
          this._waiters.set(taskId, {
            resolve: (response) => {
              clearTimeout(timer);
              resolve(response);
            },
            reject: (error) => {
              clearTimeout(timer);
              reject(error);
            },
          });
        })).content;
      }
      if (isObject(content) && "bridge_error" in content) {
        throw new BridgeError("COMMAND_FAILED", String(content.bridge_error), { path: "/command/call" });
      }
      return content;
    } finally {
      this._syncCalls--;
    }
  }

  /** Starts a call without waiting - resolves with the task id, the answer comes as onResponse. */
  async callNoWait(commandName, args, options = {}) {
    return str((await this._startCall(commandName, args, options || {}, 0)).task_id);
  }

  async _startCall(commandName, args, options, serverWait) {
    if (typeof commandName !== "string" || !commandName) {
      throw argumentError("call needs a command name");
    }
    const body = {
      command_name: commandName,
      command_args: orNull(args),
      mode: this._pickMode(args, options.mode),
      strategy: options.strategy || "least_busy",
      wait_seconds: serverWait,
      progress: options.progress || "off",
    };
    return obj(await this._request("/command/call", body,
      options.realm != null ? { realmRef: realmRefOf(options.realm) } : {}));
  }

  /** The command catalog of a realm (null = public realm). */
  async getCommands(realm) {
    return obj((await this._realmRequest("/realm/commands", {}, realm)).commands);
  }

  /** Creates a realm (public | protected | private). options: { accessKey, restrictedToOwner }. Resolves with its address. */
  async createRealm(realmType, realmName, options = {}) {
    options = options || {};
    const body = { realm_type: realmType, realm_name: realmName, restricted_to_owner: options.restrictedToOwner === true };
    if (options.accessKey != null) {
      body.access_key = options.accessKey;
    }
    return str(obj(await this._request("/realm/create", body)).realm_address);
  }

  /** Joins a realm: joinRealm(address, { accessKey }) or joinRealm({ realmAddress, accessKey, code, serverUrl }).
   *  Joined again by itself after a re-registration. Resolves with the realm address. */
  async joinRealm(realmAddressOrOptions, options = {}) {
    const opts = typeof realmAddressOrOptions === "string"
      ? { ...options, realmAddress: realmAddressOrOptions } : { ...(realmAddressOrOptions || {}) };
    const body = {};
    if (opts.realmAddress != null) {
      body.realm_address = opts.realmAddress;
    }
    if (opts.accessKey != null) {
      body.access_key = opts.accessKey;
    }
    if (opts.code != null) {
      body.code = opts.code;
    }
    if (opts.serverUrl != null) {
      body.server_url = opts.serverUrl;
    }
    const address = str(obj(await this._request("/realm/join", body)).realm_address);
    const rejoin = { realm_address: address };
    if (opts.accessKey != null) {
      rejoin.access_key = opts.accessKey;
    }
    this._realms.set(address, rejoin);
    return address;
  }

  async leaveRealm(realm) {
    this._realms.delete(realm);
    return obj(await this._request("/realm/leave", { realm_address: realm }));
  }

  getRealmInfo(realm) {
    return this._realmRequest("/realm/info", {}, realm);
  }

  async getMe() {
    return obj(await this._request("/client/me", {}));
  }

  /** Any other Bridge endpoint - the session is added for you. */
  raw(path, body = {}) {
    const route = String(path).startsWith("/") ? String(path) : "/" + path;
    return this._request(route, body);
  }

  /** Stops the client and cleans up on the server: ephemeral clients are deleted, the others unsubscribe their
   *  topics, remove their commands and log out. */
  close() {
    if (this._closePromise) {
      return this._closePromise;
    }
    if (this._state === "closed") {
      this._suspended = false; // closed by pagehide before: now for good
      this._detachPage();
      return Promise.resolve();
    }
    this._closePromise = this._close();
    return this._closePromise;
  }

  async _close() {
    this._latest.clear(); // values that did not go out are not sent any more
    for (const handler of [...this._closeHandlers]) {
      try {
        await handler();
      } catch (error) {
        this._warn("onClose: " + describe(error));
      }
    }
    // From here on nothing may log in or register again (a running poll would otherwise bring the client back)
    this._closing = true;
    this._receiving = false;
    this._notify();
    if (this._state === "connected" && this._token) {
      const now = { connectWait: 0 };
      let deleted = false;
      if (this._ephemeral) {
        try {
          await this._request("/client/delete", { password: this._password }, now);
          deleted = true;
        } catch {
          // older server: clean up by hand below
        }
      }
      if (!deleted) {
        for (const entry of [...this._topics]) {
          try {
            await this._request("/realm/topic/unsubscribe", { topic: entry.topic }, { ...now, realmRef: entry.realmRef });
          } catch {
            // best effort
          }
        }
        for (const entry of [...this._commands]) {
          try {
            await this._request("/realm/command/remove", { command_name: entry.name }, { ...now, realmRef: entry.realmRef });
          } catch {
            // best effort
          }
        }
        try {
          await this._request("/client/logout", {}, now);
        } catch {
          // best effort
        }
      }
    }
    this._detachPage();
    this._finish();
  }

  /** The end of close() and of pagehide: everything stops, nothing waits any more. */
  _finish() {
    this._closing = true;
    this._receiving = false;
    this._online = false;
    this._token = null;
    this._setState("closed");
    this._life.abort();
    for (const waiter of this._waiters.values()) {
      waiter.reject(destroyed());
    }
    this._waiters.clear();
    this._unclaimed.clear();
    for (const entry of this._sleeps) {
      clearTimeout(entry.timer);
      entry.reject(destroyed());
    }
    this._sleeps.clear();
    for (const timer of this._timers) {
      clearTimeout(timer);
    }
    this._timers.clear();
    this._notify();
  }

  _detachPage() {
    if (this._onPageHide && typeof window !== "undefined") {
      window.removeEventListener("pagehide", this._onPageHide);
      window.removeEventListener("pageshow", this._onPageShow);
      this._onPageHide = null;
      this._onPageShow = null;
    }
  }

  /** Browser: the page goes away (tab closed, navigation, back/forward cache). The browser does not wait for
   *  answers, so the cleanup goes out with fetch keepalive: ephemeral clients delete themselves, the others
   *  unsubscribe their topics and remove their commands. onClose handlers do not run here. */
  _pageHide() {
    if (this._state === "closed" || this._closing) {
      return;
    }
    const token = this._token;
    const connected = this._state === "connected" && token;
    this._latest.clear();
    this._deletedOnHide = false;
    if (connected) {
      const send = (path, body) => sendOnUnload(this._server + path, { ...body, session_token: token });
      if (this._ephemeral && this._password) {
        send("/client/delete", { password: this._password });
        this._deletedOnHide = true;
      } else {
        for (const entry of this._topics) {
          send("/realm/topic/unsubscribe", { topic: entry.topic, realm_address: this._resolveRealm(entry.realmRef) });
        }
        for (const entry of this._commands) {
          send("/realm/command/remove", { command_name: entry.name, realm_address: this._resolveRealm(entry.realmRef) });
        }
      }
    }
    this._suspended = true;
    this._finish();
  }

  /** Browser: the page came back from the back/forward cache - connect again (an ephemeral client registers again
   *  with a new IP, onClientIpChanged) and set up realms, topics and commands again. */
  _pageShow() {
    if (!this._suspended) {
      return;
    }
    this._suspended = false;
    if (this._ephemeral && this._deletedOnHide && this._clientIp != null) {
      // deleted on pagehide: register again right away (a login with the old IP would only fail and count as a
      // wrong login on the server)
      this._ipBeforeSuspend = this._clientIp;
      this._clientIp = null;
    }
    this._deletedOnHide = false;
    this._generation++;
    this._life = new AbortController();
    this._closing = false;
    this._closePromise = null;
    this._receiving = !!this._options.receive;
    this._token = null;
    this._tokenExpiresAt = 0;
    this._fatal = null;
    this._connecting = false;
    this._polling = false;
    this._latestSending = false;
    this._restoring = false;
    this._renewing = null;
    this._queue = Promise.resolve();
    this._setState("idle");
    this._startConnectLoop();
  }
  // endregion
}

// region module helpers
/** A request that must go out even if the page goes away right now (no answer is read). fetch keepalive; browsers
 *  without it (Firefox before 133) use navigator.sendBeacon. Same origin only - Bridge sends no CORS headers. */
function sendOnUnload(url, body) {
  const text = JSON.stringify(body);
  try {
    const keepalive = typeof Request !== "function" || "keepalive" in Request.prototype;
    if (!keepalive && typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function"
        && navigator.sendBeacon(url, new Blob([text], { type: "application/json" }))) {
      return;
    }
    fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: text, keepalive: true })
      .catch(() => {});
  } catch {
    // best effort
  }
}

function realmRefOf(realm) {
  return realm == null || realm === PUBLIC ? PUBLIC : String(realm);
}

function errorFrom(result, path) {
  const answer = isObject(result.data) ? result.data : null;
  const detail = answer && isObject(answer.detail) ? answer.detail : null;
  if (detail) {
    let message = String(detail.message ?? "");
    const details = isObject(detail.details) ? detail.details : null;
    const problems = details && Array.isArray(details.problems) ? details.problems : null;
    if (problems && problems.length > 0) {
      message += " -> " + problems.map(String).join("; ");
    }
    return new BridgeError(detail.error != null ? String(detail.error) : "UNKNOWN_ERROR", message,
      { status: result.status, path, details });
  }
  const text = answer && answer.detail != null
    ? (typeof answer.detail === "string" ? answer.detail : JSON.stringify(answer.detail))
    : String(result.body || "").slice(0, 300);
  return new BridgeError("HTTP_" + result.status, text, { status: result.status, path });
}

function itemsOf(data) {
  if (!isObject(data)) {
    return [];
  }
  if (Array.isArray(data.messages)) {
    return data.messages.filter(isObject);
  }
  if (data.message != null) {
    return [data]; // older Bridge servers answer with a single message
  }
  return [];
}

/** "sender|realm|topic" of a one-piece event, null for everything else. */
function eventKey(item) {
  const meta = item.message;
  const content = item.content;
  if (!isObject(meta) || !isObject(content) || meta.content_type !== "event") {
    return null;
  }
  return `${meta.sender_ip}|${content.realm_address}|${content.topic}`;
}

/** Internals for the tests - not part of the API. */
export const _testing = Object.freeze({ sha256Fallback, inflate, toJson, utf8Length });

export default BridgeClient;
// endregion
