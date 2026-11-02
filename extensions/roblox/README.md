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

**Mit Rojo:** `src/Bridge.luau` als ModuleScript `Bridge` nach `ServerStorage` (siehe `playersync-a.project.json`).
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

## Test: PlayerSync (Spieler von Spiel A als NPCs in Spiel B und umgekehrt)

`examples/PlayerSync/PlayerSync.server.luau`: jeder Spielserver ist **ein** Bridge-Client, schickt seine Spieler
(Position, Geschwindigkeit, Richtung) an das Topic `playersync` im öffentlichen Realm und zeigt die Spieler aller
**anderen** Spielserver als NPCs (echter Avatar, Name „DisplayName · A“, Lauf-Animation). Verlässt ein Spieler das
Spiel, verschwindet sein NPC; fährt ein Server herunter, sagt er „bye“ und alle seine NPCs verschwinden sofort (sonst
nach 6 Sekunden ohne Update).

**Flüssig und immer aktuell:**

- Die eigenen Spieler werden 20× pro Sekunde gemessen, raus geht nur der **neueste** Stand (`PublishLatest`) – mit
  jeder Abfrage, also etwa 7× pro Sekunde, im selben Request, der die anderen holt. Verbrauch ~400 HTTP-Anfragen pro
  Minute (Limit 500).
- Gezeigt wird nur der **neueste** Stand (`Subscribe` mit `Latest` + Zeitstempel): ältere Snapshots werden
  übersprungen, nie nachgespielt.
- Zwischen zwei Snapshots läuft der NPC mit der gesendeten Geschwindigkeit weiter (Vorhersage, höchstens 0,35 s),
  Abweichungen werden in 0,1 s weich ausgeglichen – kein Stop-and-go.
- Gemessen (Bridge 60 ms entfernt): NPCs ~0,13 s hinter dem echten Spieler, Tempo gleichmäßig (vorher ~0,45 s und
  Stop-and-go). Bei einer Vollbremsung mit Umdrehen läuft der NPC kurz bis zu ~3 Studs weiter und gleitet zurück.

1. **Bridge-Server:** in BridgeControll läuft der Server **Roblox-Game-Sync** (Tailscale, Port 443) →
   `https://muttchen.tail91b057.ts.net`. Steht in `examples/PlayerSync/config/A.luau` und `B.luau` als `Server`.
2. **Spiel A:** Studio → neue Baseplate. In einer CMD im Ordner `extensions\roblox`:
   `rojo serve playersync-a.project.json --port 34872` → im Rojo-Plugin Port 34872 → Connect.
3. **Spiel B:** zweites Studio-Fenster → neue Baseplate. Zweite CMD:
   `rojo serve playersync-b.project.json --port 34873` → im Rojo-Plugin Port 34873 → Connect.
4. In beiden Fenstern **Play**. Im Output steht `[PlayerSync A] connected to Bridge as ...` und
   `sees game server B`. Du siehst in Spiel A dich selbst aus Spiel B als NPC „Name · B“ – und umgekehrt.

In Studio nutzt jedes Spiel immer denselben Bridge-Client (`StudioSecret` in der Config) – auf echten Servern bekommt
jeder Server einen eigenen, der beim Herunterfahren gelöscht wird.

## MinecraftWorld: die Minecraft-Welt in Roblox

`examples/MinecraftWorld/` gehört zur Minecraft-Mod **BridgeGameSync**
(`C:\Users\phili\Documents\Programmieren\Projekte\BridgeMinecraft`). Der Minecraft-Server ist ein Bridge-Client,
und jeder Roblox-Server mit diesem Spiel ist auch einer. Beide nutzen denselben Bridge-Server.

- **Welt:** Das Spiel holt sich die Blöcke um den Minecraft-Spawn mit den Commands `mcworld.info` und
  `mcworld.chunks`. Jeder Block wird ein grauer Platzhalter-Würfel, 1 Block = 3 Studs, die unterste Minecraft-Schicht
  liegt bei Höhe 0. Gleiche Nachbarblöcke werden zu großen Parts zusammengefasst, ein flacher Chunk ist dadurch
  **ein** Part.
- **Änderungen:** Was in Minecraft gesetzt oder abgebaut wird, kommt über das Topic `mcworld.changes`. Bei sehr vielen
  Änderungen (`/fill`, Explosion) lädt das Spiel die betroffenen Chunks neu. Startet Minecraft neu oder war die
  Verbindung weg, lädt es alles neu.
- **Spieler:** Das Script `PlayerSync` (dasselbe wie im Testspiel) teilt sich den Bridge-Client mit der Welt
  (`MinecraftWorldClient`). Roblox-Spieler sind in Minecraft Mannequins, Minecraft-Spieler in Roblox NPCs – beide
  stehen genau auf dem Boden (der Snapshot sagt mit `f`, wie hoch der Root-Part über den Füßen ist). Der gemeinsame Client fragt alle 0,15 s (eigene Spieler raus, Minecraft-Spieler und Blöcke rein, ein Request) und darf
  460 der 500 HTTP-Anfragen pro Minute nutzen – im Spiel nutzt sonst nichts HttpService.
- Die Spieler spawnen erst, wenn die Welt da ist, und zwar auf dem Minecraft-Spawn. Antwortet Minecraft 15 Sekunden
  lang nicht, warten sie auf einer Plattform hoch oben.
- **Texturen:** Die Bilder kommen aus dem Minecraft-Spiel selbst (Command `mcworld.assets`, das Spiel enthält keine).
  **Jeder Würfel-Block** sieht aus wie in Minecraft: die Mod liest Blockstate → Modell → Textur jeder der 6 Seiten
  (mit Overlay und Biom-Farbe für Gras und Laub; Glas und Laub durchsichtig). Taucht in der Welt ein Block auf, für den
  Roblox noch keine Bilder hat, fragt der Server ihn nach. Andere Formen (Stufen, Treppen, Blumen, Fackeln …)
  bleiben graue Würfel. Jeder Block bekommt eigene Parts mit einer `Texture` pro Seite (1 Kachel = 1 Block). Die
  Bilder macht das Client-Script `MinecraftClient` (EditableImage gibt es nur auf dem Client).
- **Hotbar + Inventar** mit Minecrafts eigener GUI-Grafik: Hotbar unten (Tasten **1–9**), Inventar mit **E**
  (Item anklicken = aufnehmen, anderes Feld anklicken = ablegen oder tauschen). Kreativmodus: Items gehen nie aus.
  22 Blöcke: Gras, Erde, Stein, Bruchstein, Eichenstamm, -bretter, -laub, Glas, Sand, Kies, Sandstein, Ziegel,
  Steinziegel, Werkbank, Bücherregal, weiße Wolle, Schnee, Kohle-, Eisen-, Gold-, Diamanterz, Obsidian (die ersten 9
  in der Hotbar). Icons als kleine 3D-Würfel.
- **Leben + Schaden wie Minecraft:** 20 HP = 10 Herzen über der Hotbar (Roblox' eigene Leiste ist aus).
  Fallschaden ab 4 Blöcken (1 pro Block über 3). **Linksklick auf einen Minecraft-Spieler** schlägt ihn (Minecraft
  macht den Schaden, mit Rückstoß von deinem Mannequin). Schlägt ein Minecraft-Spieler dein Mannequin, verlierst du
  Leben (Schaden wie in Minecraft, auch mit Schwert): roter Blitz, Kamera kippt, Rückstoß. Die Lebensleiste eines
  Minecraft-Spielers zeigt sich über seinem NPC, wenn er nicht voll ist.
- **Alle sind Minecraft-Spieler** (`MinecraftCharacter`, ReplicatedStorage): kein Roblox-Rig mehr, sondern
  Minecrafts Spielermodell (Kopf 8×8×8 Pixel, Körper 8×12×4, Arme 4 bzw. 3 „slim“, Beine, zweite Skin-Schicht),
  Maßstab wie Minecraft (1 Skin-Pixel = 0,176 Studs), Hitbox 0,6 × 1,8 Blöcke. Gelenke wie in Minecraft: jedes Teil
  hängt einzeln am `ModelRoot` (den Füßen). Der Server legt den `StarterCharacter` an und schaltet Roblox' `Animate` ab.
- **Skins** (Command `mcworld.skin`): Minecraft-Spieler tragen ihren eigenen Skin, Roblox-Spieler einen der 18
  Minecraft-Standardskins (fest nach UserId, wie Minecraft es mit UUIDs macht) – in Roblox und an ihrem Mannequin.
  **`/skin <Minecraft-Name>`** im Chat übernimmt den Skin eines echten Minecraft-Accounts, `/skin` allein geht zurück.
  Jede Fläche jedes Körperteils hat eine `Texture` (Attribut `McSkinFace` = Stelle im 64×64-Skin), der Client holt
  die Pixel (`GetSkin`) und macht die Bilder.
- **Bewegen wie Minecraft** (`MinecraftPlayer`, StarterPlayerScripts): Gehen 4,317 / Sprinten 5,612 / Schleichen
  1,295 Blöcke/s, Sprung 1,25 Blöcke, Gravitation 83,5 Studs/s² (ein Sprung dauert wie in Minecraft 12 Ticks, Stürze
  gleich lang). W A S D relativ zur Blickrichtung, **Leertaste** halten = immer wieder springen, **Shift** halten =
  schleichen (Augen tiefer, man fällt nicht von Kanten), **Strg** = sprinten nur solange gehalten und vorwärts.
- **Kamera wie Minecraft:** Maus gefangen, kein Cursor, **F5** (oder **V**, falls Studio F5 abfängt) wechselt
  Ego-Sicht → von hinten → von vorne
  (4 Blöcke, Wände ziehen die Kamera ran), Fadenkreuz in der Ego-Sicht. Mausrad = Hotbar-Fach.
- **Animationen aus Minecraft:** `tools/make_animations.luau` rechnet Minecrafts eigenen Code (HumanoidModel 26.3:
  Gehen, Atmen, Schleichen, Schlagen, Sterben) in KeyframeSequences um (`examples/MinecraftWorld/animations/*.rbxm`,
  Rojo: `ReplicatedStorage.MinecraftAnimations`). `tools/upload_animations.py` lädt sie über Open Cloud als echte
  Roblox-Animationen hoch und schreibt die IDs nach `MinecraftAnimationIds.luau`. Bis dahin spielt Studio sie direkt
  aus den Dateien (`RegisterKeyframeSequence`, geht nur in Studio). Gehen läuft mit Minecrafts Formel: Gewicht und
  Tempo = min(Blöcke pro Tick × 4, 1). Der Kopf folgt dem Blick (hoch/runter) bei allen.
- **Chat:** **T** öffnet ihn. Was du schreibst, steht auch in Minecraft (`<Name · Roblox> …`), Minecrafts Chat
  (Spieler, `/say`, Beitritte, Tode …) kommt in den Roblox-Chat. **`/…`** ist ein Minecraft-Command: er läuft als
  dein Mannequin (`@s`, `~ ~ ~`, `/tp @s …` bewegt dich mit), die Antwort siehst nur du. Rechte: Mod-Config
  `robloxCommandLevel` (Standard 2 = OP-Commands wie `/time`, `/gamemode`, `/give`, `/tp`).
- **Arm schwingen:** Schlägt oder baut jemand, schwingt der Arm (Minecrafts Schlag-Animation) – in Roblox und in
  Minecraft (Mannequins der Roblox-Spieler). Getroffene werden kurz rot wie in Minecraft.
- **Bauen:** **Linksklick** baut den Block ab, auf den du schaust (halten = weiter), **Rechtsklick** setzt das
  gewählte Item. Gezielt wird wie in Minecraft von den Augen aus (auch von hinten/vorne). Reichweite 5 Blöcke, ein
  schwarzer Rahmen zeigt den Block. Der Server prüft es, zeigt es sofort und schickt es über Bridge an Minecraft
  (`mcworld.edit`); sagt Minecraft nein, lädt er den Chunk neu.

So startest du es:

1. Minecraft mit der Mod starten (Einzelspieler geht auch, der hat einen eigenen Server drin). Im Log steht
   `Bridge connected as ...`, und `/bridge` im Spiel zeigt den Status.
2. Roblox Studio → neue Baseplate. In einer CMD im Ordner `extensions\roblox`:
   `rojo serve minecraft-world.project.json --port 34874` → im Rojo-Plugin Port 34874 → Connect.
3. Einmalig für die Texturen: **Game Settings → Security → „Allow Mesh / Image APIs“** einschalten (sonst bleiben
   die Blöcke einfarbig und Hotbar/Inventar grau – das Output sagt es dann). → **Play**.
4. Einmalig für die Animationen außerhalb von Studio: Open-Cloud-API-Key (create.roblox.com → Open Cloud → API Keys,
   „Assets“ Read + Write) in eine Datei, dann
   `python extensions\roblox\tools\upload_animations.py <Key-Datei> <deine UserId>` – die IDs landen in
   `MinecraftAnimationIds.luau`, Rojo bringt sie ins Spiel. Nach Änderungen an den Animationen:
   `lune run extensions/roblox/tools/make_animations.luau`, dann wieder hochladen.

Die Texturen kommen nur, wenn Minecraft selbst läuft (Einzelspieler oder IntelliJ „Minecraft Client“). Ein
Dedicated Server hat keine Bilder – dann bleibt alles grau, Bauen geht trotzdem.

## Tests (ohne Roblox)

`tests/` läuft mit [Lune](https://github.com/lune-org/lune) **0.8.9** (0.9/0.10 schicken die URL in einer Form, die
uvicorn mit 404 ablehnt) gegen einen echten Bridge-Server:

```
python extensions/roblox/tests/run_tests.py C:\Pfad\zu\lune.exe
```

- `test_units.luau` – SHA-256, Base64 und zlib gegen Python (40 Testvektoren, alle zlib-Stufen)
- `test_images.luau` – `MinecraftImages`: Hochskalieren (scharfe Pixel), einfarbige Bilder, Block-Icon (3D-Würfel),
  Ausschnitt (eine Fläche aus dem Skin)
- `test_character.luau` – `MinecraftCharacter`: Minecrafts Maße und Hitbox, Skin-Flächen an der richtigen Stelle,
  Slim-Arme, die 7 Animationen (Gehen: Bein 1,4 rad nach hinten / Arm nach vorne, Schleichen, Tod auf die linke Seite)
- `test_live.luau` – zwei Clients: Topics, Batch-Poll, `PublishLatest` / `Subscribe` mit `Latest` (auch mit einem
  älteren Bridge-Server), direkte Nachrichten (fast/safe/compressed/auto), Commands
  (Fehler, Timeout, späte Antwort, Async), Session-Erneuerung, `SESSION_INVALID`, feste Identität, Server-Reset
  (Neu-Registrierung + Wiederherstellen), Aufräumen, HTTP aus, Server weg, HTTP-Budget, Herunterfahren
- PlayerSync-Simulation: das **echte** Script als Spiel A und B in zwei Prozessen (Lunes Roblox-Instanzen,
  simulierte Spieler) – NPCs erscheinen, laufen mit, schleichen mit, verschwinden beim Verlassen und beim „bye“.
  Dazu eine Messung:
  Spiel A läuft Kreise, Spiel B verfolgt die NPCs jedes Frame, Bridge 60 ms entfernt (`BRIDGE_SIM_LATENCY`) – wie weit
  hinter dem echten Spieler und wie gleichmäßig
- `sim_game.luau` – Lasttest: Anfragen pro Minute und Verzögerung zweier Spielserver
- `sim_minecraftworld.luau` – die **echten** Scripts MinecraftWorld und PlayerSync gegen einen echten Bridge-Server
  **und einen echten Minecraft-Server mit der Mod** (braucht beide laufend; so in der Cloud getestet): 25 Chunks =
  75 texturierte Parts (Grundgestein, Erde, Gras mit Texturen aus den Modellen), Bilder für den Client (`GetAssets`),
  Spawn, Spieler spawnen erst mit Welt, `setblock` → Neuaufbau des Chunks, `/fill` → Chunk neu geladen, ein neuer
  Block (Smaragd) wird nachgefragt und texturiert, Roblox-Spieler als Mannequin in Minecraft (steht genau auf dem
  Boden, duckt sich beim Schleichen), Grasblock setzen und abbauen (kommt in Minecraft an, zu weit weg wird
  ignoriert), Minecraft-Charakter + Standardskin, `GetSkin`, Chat in beide Richtungen, `/time set day` und `/skin`
