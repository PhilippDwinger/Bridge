# Bridge für Roblox

Ein ModuleScript (`src/Bridge.luau`), das einen Roblox-Spielserver mit einem Bridge-Server verbindet und **alles rund
um die Verbindung selbst erledigt**. Objektorientiert: jedes `Bridge.new(...)` ist ein eigener Bridge-Client
(eigene Client-IP) – ein Spielserver kann beliebig viele haben.

Was das Modul automatisch macht:

- **Registrieren + Einloggen** beim Start (im Hintergrund, `AutoStart`)
- **Session-Tokens**: die Session (60 min) wird 2 Minuten vor Ablauf erneuert, bei `SESSION_INVALID` sofort neu eingeloggt
- **Bridge-Neustart ohne Backup**: Client weg → registriert sich neu, tritt den Realms wieder bei, abonniert die Topics
  wieder und hostet die Commands wieder (`ClientIpChanged` meldet die neue IP)
- **Empfangen** im Hintergrund per Long Polling, bis zu 50 Nachrichten pro Anfrage
- **safe**-Nachrichten: Chunks holen, SHA-256 prüfen, bestätigen – **compressed**: Base64 + zlib in Luau entpacken
- **Senden**: `auto` = `fast` wenn klein, sonst `safe` (große Inhalte gehen von selbst)
- **Nur der neueste Stand** (`PublishLatest` / `Subscribe` mit `Latest`): für Zustände, die sich dauernd ändern
  (Positionen …). Der neueste Wert fährt im selben Request wie die nächste Abfrage mit, Ältere werden ersetzt bzw.
  übersprungen – nie wird ein Rückstand abgearbeitet.
- **HTTP-Limit**: Roblox erlaubt 500 Anfragen pro Minute pro Spielserver – alle Bridge-Clients zusammen nutzen höchstens
  400 (einstellbar mit `Bridge.SetRequestBudget`)
- **Herunterfahren** (`game:BindToClose`): kurzlebige Clients werden auf dem Bridge-Server gelöscht, die anderen melden
  ihre Topics/Commands ab und loggen aus
- Lesbare Fehler: `[Bridge] RECIPIENT_NOT_FOUND: ...` – `Bridge.ErrorId(err)` gibt die ID

Bridge bleibt dabei **pull-only**: das Modul fragt immer selbst (Long Polling), Bridge schickt nie von sich aus.

## Einbauen

**Mit Rojo:** `src/Bridge.luau` als ModuleScript `Bridge` nach `ServerStorage`.
**Ohne Rojo:** in Studio in `ServerStorage` ein ModuleScript `Bridge` anlegen und den Inhalt von `src/Bridge.luau`
hineinkopieren.

HTTP muss an sein: Studio → Home → Game Settings → Security → **Allow HTTP Requests** (die Rojo-Projekte hier
setzen `HttpService.HttpEnabled` schon selbst). Nur in **Scripts auf dem Server** benutzen – nie in LocalScripts.

Roblox erreicht nur **HTTPS**-Server im Internet (kein localhost, Ports 80/443 oder z. B. 8443/10000) – ein
Bridge-Server aus BridgeControll mit Tailscale Funnel passt genau.

## Schnellstart

```lua
local Bridge = require(game:GetService("ServerStorage").Bridge)

local client = Bridge.new({ Server = "https://muttchen.tail91b057.ts.net", Name = "Mein Spiel" })

-- Topics (nil = der öffentliche Realm des Servers)
client:Subscribe(nil, "chat", function(data, event)
	print(event.SenderIp, data.text)
end)
client:Publish(nil, "chat", { text = "Hallo" })

-- Direkte Nachrichten
client.MessageReceived:Connect(function(message)
	print(message.SenderIp, message.Content)
	message:Reply({ danke = true })
end)
client:Send(andereClientIp, { hallo = true })

-- Commands
client:HostCommand(nil, "add", function(args)
	return args.a + args.b
end)
print(client:Call("add", { a = 1, b = 2 })) --> 3
```

Alle Methoden außer `PublishLatest` warten (yielden) bis zur Antwort und werfen bei Fehlern – mit `pcall` abfangen, wenn nötig.

## Bridge.new(options)

| Option | Standard | Bedeutung |
|---|---|---|
| `Server` | – (Pflicht) | URL des Bridge-Servers. `/admin` usw. am Ende wird abgeschnitten, `https://` ergänzt |
| `Name` | `Roblox <JobId>` | Name des Clients |
| `Password` | zufällig | Ohne `Password`, `IdentitySecret` und `ClientIp` ist der Client **kurzlebig**: neue IP pro Start, wird beim Herunterfahren gelöscht |
| `IdentitySecret` | – | 32+ Zeichen: **immer dieselbe Client-IP** auf diesem Server (auch nach einem Neustart). Passwort wird daraus abgeleitet |
| `ClientIp` | – | Einloggen in einen bestehenden Client (mit `Password`) |
| `PollWait` | 20 | Sekunden, die eine Abfrage auf Nachrichten wartet (max 25) |
| `PollInterval` | 0.25 | mindestens so viele Sekunden zwischen zwei Abfragen |
| `MaxMessages` | 50 | Nachrichten pro Abfrage |
| `ConnectTimeout` | 30 | so lange wartet ein Aufruf auf die Verbindung, dann `NOT_CONNECTED` |
| `IgnoreOwnEvents` | true | eigene Topic-Events nicht ausliefern |
| `AutoStart` / `Receive` | true / true | sofort verbinden / im Hintergrund empfangen |
| `Debug` | false | ausgeben, was passiert |

## Methoden

| Methode | Antwort |
|---|---|
| `client:Send(ip, content, options?)` | direkte Nachricht. `options.Mode`: `auto` (Standard), `fast`, `safe`, `compressed`, `temporary`; `ConversationId`, `ExpiresInSeconds`, `SendInSeconds`, … |
| `client:Broadcast({ip, ...}, content, options?)` | dieselbe Nachricht an viele |
| `client:Subscribe(realm, topic, handler, options?)` | `handler(data, event)`; gibt ein Objekt mit `:Disconnect()` zurück. `options.Latest = true`: pro Absender nur das **neueste** Event – ältere, die noch warten, werden übersprungen |
| `client:Publish(realm, topic, data, options?)` | an alle Abonnenten (nicht an sich selbst, außer `IncludeSelf = true`) |
| `client:PublishLatest(realm, topic, data, options?)` | nur der **neueste** Wert zählt: wartet nicht, ersetzt einen noch nicht gesendeten älteren Wert desselben Topics. Fährt mit der nächsten Abfrage mit (ein Request für Senden + Empfangen); solange Werte kommen, fragt der Client alle `PollInterval` Sekunden. Ältere Bridge-Server: eigener Request |
| `client:HostCommand(realm, name, handler, options?)` | `handler(args, task)` gibt die Antwort zurück; Fehler → Aufrufer bekommt `COMMAND_FAILED`. `options`: `Description`, `Signature`, `AllowedRoles`. Gibt `{Remove = function}` |
| `client:Call(name, args, options?)` | wartet auf die Antwort. `options`: `Realm`, `Timeout` (20), `Strategy`, `Progress`, `Async` (gibt nur die Task-ID, Antwort kommt als `ResponseReceived`) |
| `client:CreateRealm(typ, name, options?)` / `client:JoinRealm(spec)` / `client:LeaveRealm(realm)` | Realms (`spec`: Adresse oder `{Realm, AccessKey}` oder `{Code, ServerUrl}`) |
| `client:GetRealmInfo(realm)`, `client:GetCommands(realm)`, `client:CreateCode(realm, options?)` | |
| `client:GetMe()`, `client:SetDirectPolicy(mode, allow, block)` | |
| `client:Request(pfad, body)` | jeder andere Bridge-Endpunkt (Session kommt automatisch dazu) |
| `client:Connect(timeout?)` / `client:WaitForConnection(timeout?)` | auf die Verbindung warten (wirft / gibt true/false) |
| `client:BindToClose(fn)` | läuft am Anfang von `Destroy()` (auch beim Herunterfahren), noch verbunden – z. B. für ein letztes „Tschüss“ |
| `client:Destroy()` | aufräumen (siehe oben) |
| `client:GetStats()`, `Bridge.GetRequestBudget()`, `Bridge.SetRequestBudget(proMinute, burst?)` | Statistik / HTTP-Budget |

`realm` ist eine Realm-Adresse oder `nil` für den öffentlichen Realm des Servers.

**Signale** (`:Connect(fn)`): `Connected(clientIp)`, `Disconnected(grund)`, `ClientIpChanged(neu, alt)`,
`MessageReceived(message)`, `EventReceived(event)`, `TaskReceived(task)` (Commands ohne Handler – mit
`task:Respond(...)` antworten), `ResponseReceived(response)`, `ProgressReceived(progress)`, `ErrorOccurred(fehler)`.

`message` hat `Id`, `SenderIp`, `Content`, `Mode`, `Type`, `ConversationId`, `Verified`, `Meta` und `:Reply(content)`.
`event` hat `Realm`, `Topic`, `Data`, `SenderIp`, `Meta`. `task` hat `Command`, `Args`, `CallerIp`, `:Respond()`,
`:Fail(text)`, `:Progress(prozent, inhalt)`.

## Tests (ohne Roblox)

`tests/` läuft mit [Lune](https://github.com/lune-org/lune) **0.8.9** (0.9/0.10 schicken die URL in einer Form, die
uvicorn mit 404 ablehnt) gegen einen echten Bridge-Server:

```
python extensions/roblox/tests/run_tests.py C:\Pfad\zu\lune.exe
```

- `test_compile.luau` – jedes Luau-Script in `src/` kompiliert wie in Roblox (u. a. Luaus Grenze von 200 lokalen
  Variablen pro Funktion)
- `test_units.luau` – SHA-256, Base64 und zlib gegen Python (40 Testvektoren, alle zlib-Stufen)
- `test_live.luau` – zwei Clients: Topics, Batch-Poll, `PublishLatest` / `Subscribe` mit `Latest` (auch mit einem
  älteren Bridge-Server), direkte Nachrichten (fast/safe/compressed/auto), Commands
  (Fehler, Timeout, späte Antwort, Async), Session-Erneuerung, `SESSION_INVALID`, feste Identität, Server-Reset
  (Neu-Registrierung + Wiederherstellen), Aufräumen, HTTP aus, Server weg, HTTP-Budget, Herunterfahren
