# Bridge für JavaScript

Eine einzige Datei ohne Abhängigkeiten (`bridge.js`, ES-Modul), mit der eine Website oder ein Node-Programm ein
Bridge-Client wird. Sie läuft unverändert im Browser und in Node 18+. Objektorientiert: jedes `BridgeClient` ist ein
eigener Bridge-Client (eigene Client-IP) – ein Programm kann beliebig viele haben.

Was die Bibliothek automatisch macht (wie die Java-Bibliothek und das Roblox-Modul):

- **Registrieren + Einloggen** im Hintergrund (`autoStart`)
- **Session-Tokens**: Erneuerung 2 Minuten vor Ablauf, bei `SESSION_INVALID` sofort neu einloggen
- **Bridge-Neustart ohne Backup**: neu registrieren und Realms, Topics und Commands wiederherstellen
  (`onClientIpChanged` meldet die neue IP). Erst danach gilt der Client wieder als bereit.
- **Empfangen** im Hintergrund per Long Polling, bis zu 50 Nachrichten pro Anfrage
- **safe**-Nachrichten: Chunks holen + SHA-256 prüfen, **compressed**: entpacken (`DecompressionStream`)
- **Senden**: `auto` = `fast` wenn klein, sonst `safe`
- **Nur der neueste Stand** (`publishLatest` / `subscribe(..., { latestOnly: true })`): für Zustände, die sich dauernd
  ändern (Positionen …). Ein noch nicht gesendeter älterer Wert wird ersetzt, ältere wartende Events werden übersprungen.
- **close()**: kurzlebige Clients werden auf dem Server gelöscht, die anderen melden Topics/Commands ab und loggen aus.
  Im Browser räumt der Client auch auf, wenn die Seite verlassen wird (`pagehide`, `fetch` mit `keepalive`).
- Fehler als `BridgeError` mit Bridge-Fehler-ID (`error.id`)

## Einbauen

`bridge.js` neben deine Dateien legen und importieren – im Browser als Modul:

```html
<script type="module">
  import { BridgeClient } from "./bridge.js";
</script>
```

In Node genauso (`import { BridgeClient } from "./bridge.js"`). Node 18 und 20 behandeln eine `.js`-Datei nur als
ES-Modul, wenn im nächsten `package.json` `"type": "module"` steht – sonst die Datei in `bridge.mjs` umbenennen. Direkt
aus diesem Ordner geht es auch: `npm install ../Bridge/extensions/javascript`, dann `import { BridgeClient } from
"bridge-client"`.

## Schnellstart

```js
import { BridgeClient } from "./bridge.js";

const client = new BridgeClient({ server: "https://muttchen.tail91b057.ts.net", name: "Mein Programm" });

// Topics (null = der öffentliche Realm des Servers)
await client.subscribe(null, "chat", (data, event) => console.log(event.senderIp + ": ", data));
await client.publish(null, "chat", { text: "Hallo" });

// Direkte Nachrichten
client.onMessage((message) => message.reply({ danke: true }));
await client.send(andereClientIp, { hallo: true });

// Commands
await client.hostCommand(null, "add", (args) => args.a + args.b);
const drei = await client.call("add", { a: 1, b: 2 });   // 3

await client.close();
```

Alle Methoden geben ein Promise zurück, das erfüllt wird, wenn Bridge geantwortet hat. Für Spiel-Schleifen gibt es
`publishAsync` (wartet nicht, Fehler gehen an `onError`, das Promise wird nie abgelehnt) und `publishLatest` (wartet
nie: der Wert ersetzt einen älteren, noch nicht gesendeten desselben Topics; der neueste geht raus, sobald der letzte
Request durch ist). Listener und Topic-Handler laufen nacheinander, in der Reihenfolge, in der die Nachrichten kamen –
gibt ein Handler ein Promise zurück, wird es abgewartet, bevor der nächste dran ist. Command-Handler laufen jeder für
sich (auch `async`).

## Auf einer Website (BridgeControll /site/)

BridgeControll liefert die Website eines Servers unter `<Server-URL>/site/` aus – auf **derselben** öffentlichen URL
wie den Bridge-Server (z. B. Server `https://pc.tail91b057.ts.net:10000/momentum`, Website
`https://pc.tail91b057.ts.net:10000/momentum/site/`). Jeder Bridge-Server liefert `bridge.js` selbst aus – unter
`<Server-URL>/server/extensions/bridge.js`, immer passend zu seiner Version. Von der Website aus ist das
`../server/extensions/bridge.js` (nichts kopieren). `BridgeClient.serverFromPage()` nimmt den Teil der Seiten-Adresse
vor `/site` als Server-URL:

```html
<!-- liegt unter https://pc.tail91b057.ts.net:10000/momentum/site/index.html -->
<script type="module">
  import { BridgeClient } from "../server/extensions/bridge.js";   // relativ! (oder eine Kopie: "./bridge.js")

  const client = new BridgeClient({ server: BridgeClient.serverFromPage(), name: "Meine Seite" });
  await client.subscribe(null, "chat", (data, event) => zeige(event.senderIp, data));
  document.querySelector("#senden").onclick = () => client.publish(null, "chat", { text: "Hallo" });
</script>
```

- **Links und Pfade auf solchen Websites müssen relativ sein** (`../server/extensions/bridge.js`, `bilder/logo.png`, `seite2.html`) –
  nie mit `/` am Anfang. Die Website liegt unter `/<Server-ID>/site/`; ein absolutes `/logo.png` landet beim Host ganz
  oben (bei einem anderen Server oder auf 404).
- `serverFromPage()` liest `document.baseURI` bzw. `location` und wirft `ARGUMENT_ERROR`, wenn die Seite nicht unter
  `/site/` liegt (z. B. beim Testen mit einem eigenen Dev-Server – dann die Server-URL direkt angeben).
- Der Browser redet nur mit dem **eigenen Ursprung** (gleiches Schema, Host, Port): Bridge schickt keine CORS-Header.
  Unter `/site/` passt das immer.
- **Seite verlassen** (Tab zu, Navigation, Back/Forward-Cache): der Client räumt mit `fetch` + `keepalive` auf
  (Browser ohne `keepalive`: `navigator.sendBeacon`) – kurzlebige Clients löschen sich, die anderen melden Topics und
  Commands ab. `onClose` läuft dabei **nicht** (der Browser wartet auf keine Antwort). Kommt die Seite aus dem
  Back/Forward-Cache zurück, verbindet sich der Client neu (kurzlebig: neue IP, `onClientIpChanged`) und stellt Realms,
  Topics und Commands wieder her. Abschalten mit `closeOnPageHide: false`.
- **Ein Client pro Seite** reicht meistens: jeder Client hält eine Long-Poll-Anfrage offen, und über HTTP/1.1 erlauben
  Browser nur 6 gleichzeitige Verbindungen pro Host (alle Tabs zusammen).
- Seiten über `http://` im LAN (kein „sicherer Kontext") haben kein `crypto.subtle` – dann rechnet die eingebaute
  SHA-256 in reinem JavaScript. Hintergrund-Tabs drosseln Timer: kommen dauernd Nachrichten, liegt zwischen zwei Polls
  dann bis zu 1 s.

## Optionen

`new BridgeClient({ server, ...optionen })` oder `new BridgeClient(server, { ...optionen })`:

| Option | Standard | Bedeutung |
|---|---|---|
| `server` | – | URL des Bridge-Servers (`/admin`, `/site` usw. werden abgeschnitten, `https://` ergänzt, ein Server-Pfad wie `/momentum` bleibt) |
| `name` | `JavaScript client` | Name des Clients |
| `password` | zufällig | ohne `password`, `identitySecret` und `clientIp` ist der Client **kurzlebig** |
| `identitySecret` | – | 32+ Zeichen: **immer dieselbe Client-IP** (auch nach einem Neustart) |
| `clientIp` | – | in einen bestehenden Client einloggen (mit `password`) |
| `ephemeral` | automatisch | kurzlebig ja/nein erzwingen |
| `pollWaitSeconds` / `pollIntervalMs` / `maxMessages` | 20 / 50 / 50 | Long Polling |
| `connectTimeout` | 30000 ms | so lange wartet ein Aufruf auf die Verbindung, dann `NOT_CONNECTED` |
| `sessionMarginSeconds` | 120 | so lange vor Ablauf wird die Session erneuert |
| `ignoreOwnEvents` | true | eigene Events nicht an die eigenen Handler geben |
| `autoStart` / `receive` | true / true | sofort verbinden / im Hintergrund empfangen |
| `closeOnPageHide` | true | Browser: beim Verlassen der Seite aufräumen (siehe oben) |
| `debug` / `warn` | – / `console.warn` | Funktionen für Meldungen (`debug: true` = `console.debug`, `warn: null` = still) |

**Listener** (geben den Client zurück, also verkettbar): `onConnected`, `onDisconnected`, `onClientIpChanged`
(`(neueIp, alteIp)`), `onMessage`, `onEvent`, `onTask` (Commands ohne Handler – mit `task.respond(...)` antworten),
`onResponse`, `onProgress`, `onError`, `onClose` (läuft am Anfang von `close()`, noch verbunden; darf `async` sein).

**Methoden:** `send(ip, inhalt, { mode, conversationId, causationId, expiresInSeconds })`, `broadcast(ips, inhalt)`,
`subscribe(realm, topic, handler, { latestOnly })` (gibt ein Objekt mit `close()`), `publish(realm, topic, daten,
{ mode, includeSelf })`, `publishAsync`, `publishLatest`, `hostCommand(realm, name, handler, { description,
signature, allowedRoles })` (gibt ein Objekt mit `close()`; der Handler bekommt `(args, task)` und darf ein Promise
zurückgeben), `call(name, args, { realm, timeout, mode, strategy, progress, serverWaitSeconds })`, `callNoWait`,
`getCommands`, `createRealm(typ, name, { accessKey, restrictedToOwner })`, `joinRealm(adresse, { accessKey })` oder
`joinRealm({ code, serverUrl })`, `leaveRealm`, `getRealmInfo`, `getMe`, `raw(pfad, body)` für jeden anderen
Endpunkt, `connect`, `waitForConnection`, `close`.

**Eigenschaften:** `clientIp`, `server`, `serverUrl`, `publicRealm`, `state` (`idle`, `connecting`, `connected`,
`reconnecting`, `failed`, `closed`), `online`, `ephemeral`, `requestCount`, `limits`. Statisch:
`BridgeClient.normalizeServer(url)`, `BridgeClient.serverFromPage()`, `BridgeClient.sha256(text)`,
`BridgeClient.ADDRESS_SPLIT`.

**Unterschiede zu Java:** alles ist `async` (deshalb kein `sendAsync`/`callAsync`); Wartezeiten in Millisekunden
(`connectTimeout`, `timeout` von `call`), Bridge-Sekunden bleiben Sekunden (`pollWaitSeconds`, `serverWaitSeconds`);
Optionen als Objekte statt Builder und `SendOptions`/`CallOptions`. JavaScript-Zahlen sind Doubles – ganze Zahlen über
2^53 verlieren Genauigkeit. `NaN`, `Infinity` und `BigInt` werden mit `ARGUMENT_ERROR` abgelehnt (statt still `null`).
Das Passwort zu einem `identitySecret` wird wie bei jeder Extension eigens abgeleitet – dasselbe `identitySecret`
gleichzeitig in Java und JavaScript ergibt dieselbe IP mit anderem Passwort (`ALREADY_EXISTS`); jedes Programm
braucht sein eigenes.

## Laufzeit

- **Browser:** Chrome/Edge 80+, Firefox 113+, Safari 16.4+. Ältere (ab Firefox 90 / Safari 14.1) gehen auch, nur
  compressed-Nachrichten melden dort `COMPRESSION_UNSUPPORTED` (kein `DecompressionStream`; die Nachricht wird nicht
  sofort zurückgegeben – sonst käme sie endlos wieder –, Bridge legt sie nach 15 Minuten selbst zurück, oder sie läuft
  ab).
- **Node 18+:** nutzt `fetch`, `AbortController`, `DecompressionStream`; Node 18 hat kein globales `crypto` – dann
  wird `node:crypto` von selbst nachgeladen. Ein Node-Programm endet nach `close()` von allein; ohne `close()` hält der
  Hintergrund-Poll es am Leben.

## Test

```
python extensions/javascript/run_tests.py
```

Startet zwei echte Bridge-Server (8511 und 8513), davor den Test-Proxy `tests/path_proxy.py` (8512, spielt Tailscale:
`/alpha` → Server, `/alpha/site` → Webserver auf 8514 für diesen Ordner). Dagegen laufen 92 Checks: Server-URLs (mit
Pfad und `/site`), `serverFromPage`, SHA-256 (auch die reine JS-Version), zlib, Topics und Batch-Poll,
Reihenfolge der Handler, `publishLatest` und `subscribe` mit nur dem neuesten Event, alle Nachrichten-Modi, Commands
(Fehler, Timeout, späte Antwort, 10 parallele Aufrufe, Fortschritt, `onTask`), Realms, Session-Erneuerung, feste
Identität und festes Passwort, Abo vor der Verbindung, Server-Reset (neu registrieren und wiederherstellen),
Aufräumen, ein Server mit Pfad hinter dem Proxy – und eine echte Seite unter `/alpha/site/` in Chromium (Playwright):
Modul-Import, `serverFromPage()`, Events in beide Richtungen, safe und compressed im Browser, Command-Aufruf,
`pagehide` mit Back/Forward-Cache und echtes Verlassen der Seite. Playwright wird über `NODE_PATH` gesucht (sonst
`npm root -g`); ohne Playwright werden die Browser-Checks übersprungen (`SKIP`).
