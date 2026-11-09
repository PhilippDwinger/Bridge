/**
 * Live test of the JavaScript extension against REAL Bridge servers (started by run_tests.py).
 *
 *   node tests/live_test.mjs <bridgeUrl> <adminPassword> <pathServerUrl> <pathAdminPassword>
 *
 * <pathServerUrl> is a second Bridge server whose public URL has a path (http://127.0.0.1:8512/alpha), behind
 * tests/path_proxy.py like Tailscale; the proxy also serves this folder under <pathServerUrl>/site/ for the
 * browser check (Playwright + chromium, found through NODE_PATH).
 */
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { deflateSync } from "node:zlib";

import { BridgeClient, BridgeError, normalizeServer, serverFromPage, _testing } from "../bridge.js";

const [url, admin, pathServer, pathAdmin] = process.argv.slice(2);
const SPLIT = BridgeClient.ADDRESS_SPLIT;
let ok = 0;
let fail = 0;
let skipped = 0;

const watchdog = setTimeout(() => {
  console.log("  CRASH the test hung (watchdog)");
  console.log(`\n${ok} ok, ${fail + 1} failed`);
  process.exit(1);
}, 270000);

function check(name, condition, info = "") {
  if (condition) {
    ok++;
    console.log(`  OK    ${name}`);
  } else {
    fail++;
    console.log(`  FAIL  ${name}  ${typeof info === "string" ? info : safeJson(info)}`);
  }
}

function skip(name, reason) {
  skipped++;
  console.log(`  SKIP  ${name}  (${reason})`);
}

function safeJson(value) {
  try {
    const text = JSON.stringify(value, (key, item) => (item instanceof Error ? item.message : item));
    return text && text.length > 400 ? text.slice(0, 400) + "..." : text;
  } catch {
    return String(value);
  }
}

const sleep = (millis) => new Promise((resolve) => setTimeout(resolve, millis));

async function waitFor(condition, seconds) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    if (await condition()) {
      return true;
    }
    await sleep(30);
  }
  return !!(await condition());
}

async function post(base, path, body) {
  const response = await fetch(base + path, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  let data = {};
  try {
    data = await response.json();
  } catch {
    // not JSON
  }
  return { ...data, _status: response.status };
}

async function catchBridge(action) {
  try {
    await action();
    return null;
  } catch (error) {
    return error;
  }
}

const throwsSync = (action) => {
  try {
    action();
    return null;
  } catch (error) {
    return error;
  }
};

const increasing = (values) => values.every((value, index) => index === 0 || value > values[index - 1]);
const nodeSha = (text) => createHash("sha256").update(text, "utf8").digest("hex");
const quiet = () => {};
const EXPECTED = ["SESSION_INVALID", "INVALID_CREDENTIALS", "DESTROYED", "CLIENT_NOT_FOUND", "INTERRUPTED"];
const unexpectedOf = (errors) => errors.filter((text) => !EXPECTED.some((id) => text.includes(id)));

function bigContent() {
  const rows = [];
  for (let i = 0; i < 3000; i++) {
    rows.push({ id: i, name: `Spieler ${i} äöü 🚀`, pos: [i * 0.5, 3, -i] });
  }
  return { rows };
}

async function offline() {
  console.log("== offline: URLs, hashes, JSON, zlib");
  check("normalizeServer: https, /admin cut, :443 dropped",
    normalizeServer(" Muttchen.ts.net:443/admin/ ") === "https://muttchen.ts.net", normalizeServer(" Muttchen.ts.net:443/admin/ "));
  check("normalizeServer: keeps a server id path, cuts /admin and /site",
    normalizeServer("https://pc.ts.net:10000/momentum/admin") === "https://pc.ts.net:10000/momentum"
      && normalizeServer("https://pc.ts.net/momentum/site/") === "https://pc.ts.net/momentum",
    normalizeServer("https://pc.ts.net/momentum/site/"));
  check("normalizeServer: http :80 dropped, query/hash gone, route names in any case cut",
    normalizeServer("http://Host.Example:80/a/b/Client/login?x=1#y") === "http://host.example/a/b"
      && normalizeServer("https://pc.ts.net:10000/momentum?x=/admin") === "https://pc.ts.net:10000/momentum"
      && normalizeServer("http://pc:8080/") === "http://pc:8080",
    normalizeServer("http://Host.Example:80/a/b/Client/login?x=1#y"));
  check("normalizeServer: other ports and deeper server paths stay",
    normalizeServer("pc.ts.net:8443/team/momentum/") === "https://pc.ts.net:8443/team/momentum"
      && BridgeClient.normalizeServer("https://pc.ts.net:10000/rika-ai/message/poll") === "https://pc.ts.net:10000/rika-ai");

  check("serverFromPage: the part before /site",
    serverFromPage("https://pc.ts.net:10000/momentum/site/") === "https://pc.ts.net:10000/momentum"
      && serverFromPage("https://pc.ts.net:10000/momentum/site/index.html") === "https://pc.ts.net:10000/momentum"
      && serverFromPage("https://PC.ts.net:443/momentum/site") === "https://pc.ts.net/momentum",
    serverFromPage("https://pc.ts.net:10000/momentum/site/index.html"));
  check("serverFromPage: sub folders (also one called site / admin), query and hash",
    serverFromPage("https://pc.ts.net:10000/momentum/site/game/site/admin/index.html?x=1#top") === "https://pc.ts.net:10000/momentum"
      && serverFromPage("http://127.0.0.1:8512/site/a.html") === "http://127.0.0.1:8512",
    serverFromPage("https://pc.ts.net:10000/momentum/site/game/site/admin/index.html?x=1#top"));
  const notSite = throwsSync(() => serverFromPage("https://pc.ts.net:10000/momentum/game/index.html"));
  const nowhere = throwsSync(() => serverFromPage());
  check("serverFromPage: a page outside /site/ and no page at all -> ARGUMENT_ERROR",
    notSite instanceof BridgeError && notSite.id === "ARGUMENT_ERROR" && nowhere instanceof BridgeError
      && nowhere.id === "ARGUMENT_ERROR", `${notSite} / ${nowhere}`);
  globalThis.document = { baseURI: "https://pc.ts.net:10000/momentum/site/spiel/index.html" };
  const fromDocument = BridgeClient.serverFromPage();
  globalThis.document = { baseURI: "https://cdn.example/x/" };
  globalThis.location = { href: "https://pc.ts.net:10000/beta/site/" };
  const fromLocation = BridgeClient.serverFromPage();
  delete globalThis.document;
  delete globalThis.location;
  check("serverFromPage: reads document.baseURI, then location", fromDocument === "https://pc.ts.net:10000/momentum"
    && fromLocation === "https://pc.ts.net:10000/beta", `${fromDocument} / ${fromLocation}`);

  const text = "Hallo äöü 🚀 " + "x".repeat(1000);
  check("sha256 (crypto.subtle) = node:crypto", (await BridgeClient.sha256(text)) === nodeSha(text));
  const sizes = [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000, 200000];
  const fallbackOk = sizes.every((size) => {
    const sample = "äb🚀".repeat(size).slice(0, size);
    const bytes = new TextEncoder().encode(sample);
    return Buffer.from(_testing.sha256Fallback(bytes)).toString("hex") === createHash("sha256").update(bytes).digest("hex");
  });
  check("sha256 plain-JS fallback (pages without crypto.subtle) = node:crypto for all lengths", fallbackOk);
  check("utf8Length = Buffer.byteLength", ["", "abc", "äöü", "🚀x", "\ud800", text].every(
    (sample) => _testing.utf8Length(sample) === Buffer.byteLength(sample, "utf8")));
  const nan = throwsSync(() => _testing.toJson({ a: [1, NaN] }));
  const big = throwsSync(() => _testing.toJson({ a: 10n }));
  check("JSON: NaN and BigInt are refused (not silently null)", nan instanceof BridgeError && nan.id === "ARGUMENT_ERROR"
    && big instanceof BridgeError && big.id === "ARGUMENT_ERROR", `${nan} / ${big}`);
  const original = JSON.stringify(bigContent());
  const packed = deflateSync(Buffer.from(original, "utf8"), { level: 6 }).toString("base64");
  check("zlib+base64 (what Bridge sends) unpacks with DecompressionStream", (await _testing.inflate(packed)) === original);
  const broken = await catchBridge(() => _testing.inflate(packed.slice(0, 200) + "AAAA" + packed.slice(204, 400)));
  check("broken zlib data -> HASH_MISMATCH", broken instanceof BridgeError && broken.id === "HASH_MISMATCH", String(broken));
  const shortSecret = throwsSync(() => new BridgeClient({ server: url, identitySecret: "too short", autoStart: false }));
  check("identitySecret under 32 characters -> ARGUMENT_ERROR", shortSecret instanceof BridgeError
    && shortSecret.id === "ARGUMENT_ERROR", String(shortSecret));
}

async function mainServer() {
  console.log("== live: Bridge server " + url);
  const errors = [];
  const a = new BridgeClient({ server: url + "/admin", name: "JS A", warn: quiet });
  const b = new BridgeClient(url, { name: "JS B", warn: quiet });
  a.onError((error) => errors.push("A " + error.message));
  b.onError((error) => errors.push("B " + error.message));
  check("two clients connect by themselves", (await a.waitForConnection(10000)) && (await b.waitForConnection(10000))
    && a.server === url, a.server);
  check("different client IPs, public realm known", a.clientIp !== b.clientIp && a.publicRealm != null
    && a.clientIp.startsWith(url + SPLIT), a.clientIp);

  // region topics
  let gotB = [];
  const gotA = [];
  const senders = [];
  const subB = await b.subscribe(null, "sync", (data, event) => {
    gotB.push(data);
    senders.push(event.senderIp);
  });
  await a.subscribe(null, "sync", (data) => gotA.push(data));
  for (let tick = 1; tick <= 20; tick++) {
    await a.publish(null, "sync", { tick });
  }
  check("20 events arrive at B in order", (await waitFor(() => gotB.length === 20, 5)) && gotB[19].tick === 20
    && gotB[0].tick === 1 && increasing(gotB.map((data) => data.tick)) && senders[0] === a.clientIp, gotB.length);
  await sleep(400);
  check("A does not get its own events", gotA.length === 0, gotA.length);
  const before = b.requestCount;
  gotB.length = 0;
  for (let tick = 1; tick <= 40; tick++) {
    a.publishAsync(null, "sync", { tick });
  }
  await waitFor(() => gotB.length >= 40, 8);
  check("40 events with few poll requests (batch poll)", gotB.length === 40 && b.requestCount - before <= 12,
    `${gotB.length} events, ${b.requestCount - before} requests`);
  const order = [];
  const subOrder = await b.subscribe(null, "order", async (data) => {
    await sleep(data.n % 2 === 0 ? 30 : 0); // a slow async handler must not let the next one overtake
    order.push(data.n);
  });
  for (let n = 1; n <= 8; n++) {
    a.publishAsync(null, "order", { n });
  }
  check("handlers run one after the other in arrival order (async ones are awaited)",
    (await waitFor(() => order.length === 8, 5)) && increasing(order), order);
  await subOrder.close();
  // endregion

  // region publishLatest + subscribe latest (only the newest state counts)
  const lazy = new BridgeClient({ server: url, name: "Slow poller", pollIntervalMs: 700, warn: quiet });
  check("slow poller connects", await lazy.waitForConnection(10000), lazy.state);
  const all = [];
  const newest = [];
  const subAll = await lazy.subscribe(null, "pos", (data) => all.push(data.n));
  const subNewest = await lazy.subscribe(null, "pos", (data) => newest.push(data.n), { latestOnly: true });
  await sleep(800);
  for (let n = 1; n <= 20; n++) {
    await a.publish(null, "pos", { n });
  }
  await waitFor(() => all.length >= 20, 5);
  await sleep(300);
  check("subscribe: a normal handler gets all 20 events", all.length === 20 && increasing(all), all);
  check("subscribe latest: only the newest of each poll (fewer, in order, ends with 20)", newest.length < 20
    && newest.length > 0 && newest[newest.length - 1] === 20 && increasing(newest), newest);
  await subAll.close();
  newest.length = 0;
  const requestsA = a.requestCount;
  for (let n = 1; n <= 300; n++) {
    a.publishLatest(null, "pos", { n });
  }
  check("publishLatest: the newest value arrives", await waitFor(() => newest.length > 0 && newest[newest.length - 1] === 300, 5), newest);
  await sleep(300);
  check("publishLatest: never an older value after a newer one", increasing(newest), newest);
  check("publishLatest: only the newest went out (far fewer requests than values)", a.requestCount - requestsA < 100,
    `${a.requestCount - requestsA} requests for 300 values`);
  const noData = throwsSync(() => a.publishLatest(null, "pos", null));
  check("publishLatest without data -> ARGUMENT_ERROR (thrown at once)", noData instanceof BridgeError
    && noData.id === "ARGUMENT_ERROR", String(noData));
  await subNewest.close();
  await lazy.close();
  // endregion

  // region direct messages
  const inbox = [];
  const replies = [];
  b.onMessage((message) => inbox.push(message));
  a.onMessage((message) => replies.push(message));
  await a.send(b.clientIp, { hello: "welt" });
  check("direct message (auto -> fast)", (await waitFor(() => inbox.length === 1, 5)) && inbox[0].content.hello === "welt"
    && inbox[0].mode === "fast" && inbox[0].senderIp === a.clientIp && inbox[0].verified === false, inbox);
  await inbox[0].reply({ thanks: true });
  check("reply in the same conversation", (await waitFor(() => replies.length === 1, 5))
    && replies[0].conversationId === inbox[0].conversationId && replies[0].content.thanks === true, replies);
  const big = bigContent();
  const bigText = JSON.stringify(big);
  for (const mode of ["safe", "compressed"]) {
    inbox.length = 0;
    await a.send(b.clientIp, big, { mode });
    check(`${mode} message (${Math.round(bigText.length / 1024)} KiB) arrives exactly`,
      (await waitFor(() => inbox.length === 1, 20)) && JSON.stringify(inbox[0].content) === bigText && inbox[0].mode === mode,
      inbox.length ? inbox[0].mode : "none");
    if (mode === "compressed") {
      check("compressed: Bridge really sent zlib+base64 (fewer bytes than the content)",
        inbox.length === 1 && inbox[0].meta.encoding === "zlib+base64"
          && inbox[0].meta.transport_size_bytes < inbox[0].meta.size_bytes / 2,
        inbox.length ? inbox[0].meta : "none");
    }
  }
  inbox.length = 0;
  await a.send(b.clientIp, big);
  check("auto mode: big content goes as safe", (await waitFor(() => inbox.length === 1, 20)) && inbox[0].mode === "safe",
    inbox.length ? inbox[0].mode : "none");
  inbox.length = 0;
  const temporary = await a.send(b.clientIp, { short: true }, { mode: "temporary", expiresInSeconds: 30 });
  check("temporary message with a lifetime", (await waitFor(() => inbox.length === 1, 5)) && inbox[0].mode === "temporary"
    && temporary.message_id != null, inbox.length ? inbox[0].mode : temporary);
  inbox.length = 0;
  const sent = await a.broadcast([b.clientIp, b.clientIp.slice(0, -4) + "nope"], { all: 1 });
  check("broadcast: one recipient gets it, a wrong one does not stop it", (await waitFor(() => inbox.length === 1, 5))
    && sent.sent === 1 && sent.failed === 1, sent);
  const missing = await catchBridge(() => a.send(a.serverUrl + SPLIT + "nobody", 1));
  check("errors carry the Bridge ID", missing instanceof BridgeError && missing.id === "RECIPIENT_NOT_FOUND"
    && missing.status >= 400 && missing.path === "/message/send", String(missing));
  const notJson = await catchBridge(() => a.send(b.clientIp, { bad: NaN }));
  check("content that is no JSON -> ARGUMENT_ERROR before sending", notJson instanceof BridgeError
    && notJson.id === "ARGUMENT_ERROR", String(notJson));
  // endregion

  // region commands
  await b.hostCommand(null, "add", (args) => args.a + args.b);
  await b.hostCommand(null, "boom", () => {
    throw new Error("kaputt");
  });
  await b.hostCommand(null, "slow", async (args) => {
    await sleep(args.seconds * 1000);
    return "done";
  });
  await b.hostCommand(null, "work", async (args, task) => {
    await task.progress(50, "halb");
    await sleep(100);
    await task.progress(100, "fertig");
    return "worked";
  }, { description: "reports progress" });
  check("call returns the host's answer", (await a.call("add", { a: 2, b: 3 })) === 5);
  const boom = await catchBridge(() => a.call("boom", {}));
  check("handler error -> COMMAND_FAILED with the text", boom instanceof BridgeError && boom.id === "COMMAND_FAILED"
    && boom.message.includes("kaputt"), String(boom));
  let t0 = Date.now();
  const slow = await a.call("slow", { seconds: 1.2 }, { serverWaitSeconds: 0.2, timeout: 10000 });
  check("late answer comes through the poll loop", slow === "done" && (Date.now() - t0) / 1000 > 1.0, slow);
  const timeout = await catchBridge(() => a.call("slow", { seconds: 2.5 }, { timeout: 1000 }));
  check("timeout -> TIMEOUT", timeout instanceof BridgeError && timeout.id === "TIMEOUT", String(timeout));
  await sleep(2500);
  const responses = [];
  a.onResponse((response) => responses.push(response));
  await sleep(1200);
  responses.length = 0;
  const taskId = await a.callNoWait("add", { a: 10, b: 5 });
  check("callNoWait: answer comes as onResponse", (await waitFor(() => responses.length > 0, 5))
    && responses[0].taskId === taskId && responses[0].content === 15, responses);
  const parallel = await Promise.all(Array.from({ length: 10 }, (_, n) => a.call("add", { a: n, b: 100 })));
  check("10 calls at the same time all get their own answer", parallel.length === 10
    && parallel.reduce((sum, value) => sum + value, 0) === 1045 && increasing(parallel), parallel);
  const commands = await a.getCommands(null);
  check("getCommands shows B's commands", "add" in commands && "work" in commands, Object.keys(commands));
  const progress = [];
  a.onProgress((item) => progress.push(item));
  const worked = await a.call("work", {}, { progress: "all" });
  await waitFor(() => progress.length >= 2, 3);
  check("progress: the caller gets the host's progress", worked === "worked" && progress.length === 2
    && progress[0].content.percent === 50 && progress[1].content.content === "fertig", progress.map((item) => item.content));
  await b.raw("/realm/command/create", { realm_address: b.publicRealm, command_name: "manual" });
  let doubled = null;
  b.onTask(async (task) => {
    await task.respond("by hand " + task.args.x);
    doubled = await catchBridge(() => task.respond("again"));
  });
  check("onTask: a command without handler is answered by hand", (await a.call("manual", { x: 7 })) === "by hand 7");
  check("a task can be answered only once (ALREADY_ANSWERED)", await waitFor(() => doubled != null, 3)
    && doubled.id === "ALREADY_ANSWERED", String(doubled));
  const deaf = new BridgeClient({ server: url, name: "JS no poll", receive: false, warn: quiet });
  check("receive: false - the server waits for the call's answer", (await deaf.call("add", { a: 20, b: 22 })) === 42);
  await deaf.close();
  // endregion

  // region realms
  const realm = await a.createRealm("protected", "js-test", { accessKey: "sesam-1234" });
  check("createRealm returns the address", typeof realm === "string" && realm.startsWith(url + SPLIT), realm);
  const joined = await b.joinRealm(realm, { accessKey: "sesam-1234" });
  const inRealm = [];
  await b.subscribe(realm, "news", (data, event) => inRealm.push([data, event.realm]));
  await a.publish(realm, "news", { headline: "hi" });
  check("joinRealm + topic in an own realm", joined === realm && (await waitFor(() => inRealm.length === 1, 5))
    && inRealm[0][0].headline === "hi" && inRealm[0][1] === realm, inRealm);
  const info = await b.getRealmInfo(realm);
  const me = await b.getMe();
  check("getRealmInfo / getMe know the realm", JSON.stringify(info).includes("js-test") && JSON.stringify(me).includes(realm),
    info);
  // endregion

  // region sessions
  const tokenBefore = a._token;
  a._tokenExpiresAt = Date.now() / 1000 + 60;
  await a.getMe();
  check("session renewed before it runs out", tokenBefore !== a._token);
  await post(url, "/client/logout", { session_token: a._token });
  check("SESSION_INVALID -> logs in again by itself", a.clientIp === (await a.getMe()).client_ip);
  // endregion

  // region identity + fixed password
  const secret = "js-identity-secret-0123456789-abcdef";
  const c = new BridgeClient({ server: url, name: "JS C", identitySecret: secret, warn: quiet });
  check("identity client connects", await c.waitForConnection(10000), c.state);
  const ipC = c.clientIp;
  await c.close();
  const c2 = new BridgeClient({ server: url, name: "JS C", identitySecret: secret, warn: quiet });
  check("same identitySecret -> same client IP", (await c2.waitForConnection(10000)) && ipC === c2.clientIp
    && !c2.ephemeral, c2.clientIp);
  const p = new BridgeClient({ server: url, name: "JS P", password: "fester-pass-123", warn: quiet });
  await p.connect(10000);
  await p.close();
  const p2 = new BridgeClient({ server: url, name: "JS P", clientIp: p.clientIp, password: "fester-pass-123", warn: quiet });
  check("clientIp + password logs into the existing client", (await p2.waitForConnection(10000)) && p2.clientIp === p.clientIp
    && !p2.ephemeral, p2.state);
  await p2.close();
  const wrong = new BridgeClient({ server: url, name: "JS P", clientIp: p.clientIp, password: "falsch-123", warn: quiet });
  const wrongError = await catchBridge(() => wrong.connect(10000));
  check("wrong password -> INVALID_CREDENTIALS, state failed (no endless retries)", wrongError instanceof BridgeError
    && wrongError.id === "INVALID_CREDENTIALS" && wrong.state === "failed", `${wrongError} ${wrong.state}`);
  await wrong.close();
  // endregion

  // region subscribe before connected
  const f = new BridgeClient({ server: url, name: "JS F", autoStart: false, connectTimeout: 0, warn: quiet });
  const gotF = [];
  const early = await catchBridge(() => f.subscribe(null, "sync", (data) => gotF.push(data)));
  check("subscribe before the connection does not throw", early === null && f.state !== "connected", String(early));
  await f.waitForConnection(10000);
  await a.publish(null, "sync", { tick: 555 });
  check("... and gets the event once connected", await waitFor(() => gotF.length > 0, 5), gotF);
  await f.close();
  // endregion

  // region Bridge reset (restart without backup)
  const oldA = a.clientIp;
  const oldB = b.clientIp;
  const oldRealm = a.publicRealm;
  const changed = [];
  a.onClientIpChanged((now, old) => changed.push(old));
  check("server reset", (await post(url, "/admin/reset", { password: admin }))._status === 200);
  gotB = []; // the handler of subB pushes into the new list
  await a.publish(null, "sync", { tick: 1000 });
  check("A registered again by itself, new IP, onClientIpChanged", oldA !== a.clientIp
    && (await waitFor(() => changed.length === 1 && changed[0] === oldA, 3)), a.clientIp);
  check("new public realm address is used", a.publicRealm != null && a.publicRealm !== oldRealm, a.publicRealm);
  check("B (only polling) came back by itself", await waitFor(() => oldB !== b.clientIp && b.state === "connected", 15), b.state);
  await waitFor(() => gotB.length > 0, 3);
  for (let tick = 1001; tick <= 1003; tick++) {
    await a.publish(null, "sync", { tick });
  }
  check("B's subscription restored", await waitFor(() => gotB.length > 0 && gotB[gotB.length - 1].tick === 1003, 8), gotB);
  check("B's commands restored", (await a.call("add", { a: 1, b: 1 })) === 2);
  check("a realm that is gone after the reset does not stop the restore", b.state === "connected" && b.online);
  await c2.getMe();
  check("identity client: same IP after the reset", ipC === c2.clientIp, c2.clientIp);
  // endregion

  // region close
  await subB.close();
  await sleep(300);
  const published = await a.publish(null, "sync", { tick: 2000 });
  check("closing the last handler unsubscribes", published.subscribers === 0, published);
  const lastIp = a.clientIp;
  const lastPassword = a._password;
  const bye = [];
  a.onClose(async () => {
    await a.publish(null, "sync", { bye: true });
    bye.push(true);
  });
  await a.close();
  const login = await post(url, "/client/login", { client_ip: lastIp, password: lastPassword });
  check("close: onClose ran first, the ephemeral client is deleted", bye.length === 1 && login._status === 401, login);
  const destroyedError = await catchBridge(() => a.send(b.clientIp, 1));
  check("a closed client throws DESTROYED", destroyedError instanceof BridgeError && destroyedError.id === "DESTROYED",
    String(destroyedError));
  const e = new BridgeClient({ server: "http://127.0.0.1:1", name: "nobody", warn: quiet });
  t0 = Date.now();
  const notConnected = await catchBridge(() => e.connect(2000));
  check("unreachable server -> NOT_CONNECTED after the timeout", notConnected instanceof BridgeError
    && notConnected.id === "NOT_CONNECTED" && (Date.now() - t0) / 1000 < 4, String(notConnected));
  t0 = Date.now();
  await e.close();
  await b.close();
  await c2.close();
  check("close() ends at once, also while still trying to connect", Date.now() - t0 < 2000, `${Date.now() - t0} ms`);
  if (process.env.SHOW_ERRORS) {
    console.log(errors); // expected: CLIENT_NOT_FOUND of the poll during the reset, the realm the reset removed
  }
  const unexpected = unexpectedOf(errors).filter((text) => !text.includes("REALM_NOT_FOUND"));
  check("no unexpected background errors", unexpected.length === 0, unexpected);
  // endregion
}

async function pathServerChecks() {
  console.log("== live: server with a path behind a proxy " + pathServer);
  const errors = [];
  const n = new BridgeClient({ server: pathServer + "/admin", name: "Node N", warn: quiet });
  const m = new BridgeClient({ server: pathServer + "/site/", name: "Node M", warn: quiet });
  n.onError((error) => errors.push("N " + error.message));
  m.onError((error) => errors.push("M " + error.message));
  check("path server: /admin and /site cut, the server path kept", n.server === pathServer && m.server === pathServer,
    `${n.server} ${m.server}`);
  check("path server: both connect through the proxy", (await n.waitForConnection(10000)) && (await m.waitForConnection(10000)),
    `${n.state} ${m.state}`);
  check("path server: the server URL (with path) is part of the client IP", n.serverUrl === pathServer
    && n.clientIp.startsWith(pathServer + SPLIT) && m.clientIp.startsWith(pathServer + SPLIT), n.clientIp);
  const events = [];
  await m.subscribe(null, "path", (data) => events.push(data));
  await n.publish(null, "path", { via: "proxy" });
  const inbox = [];
  m.onMessage((message) => inbox.push(message));
  await n.send(m.clientIp, bigContent(), { mode: "compressed" });
  await m.hostCommand(null, "echo", (args) => args);
  check("path server: event, compressed message and command through the path",
    (await waitFor(() => events.length === 1 && inbox.length === 1, 10)) && events[0].via === "proxy"
      && inbox[0].content.rows.length === 3000 && (await n.call("echo", { x: [1, 2] })).x[1] === 2, `${events.length} ${inbox.length}`);
  await m.close();
  return { n, errors };
}

async function browserChecks(n, errors) {
  console.log("== browser: a page under " + pathServer + "/site/ (Playwright, chromium)");
  const require = createRequire(import.meta.url);
  let playwright;
  try {
    playwright = require("playwright");
  } catch {
    skip("browser checks", "playwright not found - set NODE_PATH to the folder that has it");
    return;
  }
  let browser;
  try {
    browser = await playwright.chromium.launch();
  } catch (error) {
    skip("browser checks", "chromium does not start: " + String(error.message || error).split("\n")[0]);
    return;
  }
  const pageErrors = [];
  try {
    const page = await browser.newPage();
    page.on("pageerror", (error) => pageErrors.push(String(error)));
    page.on("console", (message) => {
      if (message.type() === "error") {
        pageErrors.push(message.text());
      }
    });
    const gotN = [];
    await n.subscribe(null, "web", (data) => gotN.push(data));
    const pageUrl = pathServer + "/site/tests/site/index.html";
    const answer = await page.goto(pageUrl);
    check("browser: the test page is served under <server>/site/ through the proxy", answer && answer.status() === 200,
      answer && answer.status());
    await page.waitForFunction(() => window.ready || window.failed, null, { timeout: 20000 }).catch(() => {});
    const ready = await page.evaluate(() => window.ready || { failed: window.failed || "nothing" });
    check("browser: ES module import + serverFromPage() -> connected to the server with path",
      ready.server === pathServer && typeof ready.clientIp === "string" && ready.clientIp.startsWith(pathServer + SPLIT),
      ready);
    if (!ready.clientIp) {
      return;
    }
    check("browser: serverFromPage() on the page", (await page.evaluate(() => window.BridgeClient.serverFromPage())) === pathServer);
    await page.evaluate(() => window.client.publish(null, "web", { from: "browser" }));
    check("browser publishes, Node gets the event", await waitFor(() => gotN.some((data) => data.from === "browser"), 5), gotN);
    await n.publish(null, "web", { from: "node", n: 1 });
    check("Node publishes, the browser gets it (long poll in the page)",
      await waitFor(() => page.evaluate(() => window.got.events.some((data) => data.from === "node")), 5));
    const big = bigContent();
    const hash = nodeSha(JSON.stringify(big));
    await n.send(ready.clientIp, big, { mode: "compressed" });
    await n.send(ready.clientIp, big, { mode: "safe" });
    const received = async () => page.evaluate(async () => Promise.all(window.got.messages.map(async (message) => ({
      mode: message.mode, encoding: message.encoding, hash: await window.BridgeClient.sha256(JSON.stringify(message.content)),
    }))));
    await waitFor(async () => (await received()).length >= 2, 20);
    const messages = await received();
    check("browser: compressed message unpacked (DecompressionStream) and checked (SHA-256)", messages.length === 2
      && messages[0].mode === "compressed" && messages[0].encoding === "zlib+base64" && messages[0].hash === hash, messages);
    check("browser: safe message (chunks + SHA-256)", messages.length === 2 && messages[1].mode === "safe"
      && messages[1].hash === hash, messages);
    const fallback = await page.evaluate(async () => {
      const { _testing } = await import("../../bridge.js");
      const text = "Hallo äöü 🚀".repeat(500);
      const hex = Array.from(_testing.sha256Fallback(new TextEncoder().encode(text)),
        (byte) => byte.toString(16).padStart(2, "0")).join("");
      return hex === await window.BridgeClient.sha256(text);
    });
    check("browser: plain-JS SHA-256 (for http pages without crypto.subtle) = crypto.subtle", fallback);
    await n.hostCommand(null, "mul", (args) => args.a * args.b);
    check("browser: calls a command hosted by Node", (await page.evaluate(() => window.client.call("mul", { a: 6, b: 7 }))) === 42);

    // pagehide with the back/forward cache: cleanup with fetch keepalive, then the page comes back
    const password = await page.evaluate(() => window.client._password);
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true })));
    const deleted = await waitFor(async () => (await post(pathServer, "/client/login",
      { client_ip: ready.clientIp, password }))._status === 401, 5);
    check("browser: pagehide deletes the ephemeral client (fetch keepalive)", deleted
      && (await page.evaluate(() => window.client.state)) === "closed");
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true })));
    const back = await waitFor(() => page.evaluate(() => window.client.state === "connected" && window.got.ipChanged.length === 1), 10);
    const newIp = await page.evaluate(() => window.client.clientIp);
    await n.publish(null, "web", { from: "node", n: 2 });
    check("browser: back from the back/forward cache -> registered again (new IP) with its subscription", back
      && newIp !== ready.clientIp && (await waitFor(() => page.evaluate(() => window.got.events.some((data) => data.n === 2)), 5)),
      newIp);

    // a real navigation away from the page
    const passwordNow = await page.evaluate(() => window.client._password);
    await page.goto("about:blank");
    check("browser: leaving the page deletes the client on the server", await waitFor(async () => (await post(pathServer,
      "/client/login", { client_ip: newIp, password: passwordNow }))._status === 401, 5));
    check("browser: no errors on the page", pageErrors.length === 0, pageErrors);
  } finally {
    await browser.close().catch(() => {});
  }
  await n.close();
  const unexpected = unexpectedOf(errors);
  check("path server: no unexpected background errors", unexpected.length === 0, unexpected);
}

async function main() {
  try {
    await offline();
    await mainServer();
    const { n, errors } = await pathServerChecks();
    await browserChecks(n, errors);
  } catch (crash) {
    fail++;
    console.log("  CRASH " + (crash && crash.stack || crash));
  }
  clearTimeout(watchdog);
  console.log(`\n${ok} ok, ${fail} failed${skipped ? `, ${skipped} skipped` : ""}`);
  process.exit(fail > 0 ? 1 : 0);
}

main();
