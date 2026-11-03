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
- **Neu bauen nur, was sich ändert:** Nach einer Änderung bleibt jeder Part, dessen Box gleich geblieben ist, neue Parts
  kommen, bevor alte gehen – der Boden unter den Füßen verschwindet nie (kein Ruckeln der Kamera). Verschwinden
  Texturen, bekommen alle Blöcke dieser Art ihr Bild im nächsten Frame noch mal (Roblox ließ sie sonst manchmal grau).
- **Texturen + Formen:** Die Bilder kommen aus dem Minecraft-Spiel selbst (Command `mcworld.assets`, das Spiel
  enthält keine). **Jeder Blockzustand** sieht aus wie in Minecraft: Blocknamen tragen, wovon das Aussehen abhängt
  (`minecraft:oak_log[axis=x]`), die Mod schickt das fertig gedrehte Aussehen. Würfel (auch liegende Stämme, Kolben in
  jede Richtung) werden mit ihren Nachbarn zusammengefasst; Modelle (Hebel mit schrägem Griff, Redstone mit Farbe nach
  Stärke, Treppen, Stufen, Zäune, Türen, Falltüren, Knöpfe, Kolbenköpfe, Fackeln, Pflanzen, Wasser/Lava durchsichtig)
  bekommen je Box ein unsichtbares Teil mit einer `Texture` pro Seite, dazu „Collision“-Teile (wo man anstößt –
  Redstone, Hebel, Knöpfe haben keine) und „Outline“-Teile (worauf man zielt, mit Minecrafts Umriss). Taucht ein neuer
  Zustand auf, fragt der Server nach. Die Bilder macht das Client-Script `MinecraftClient` (EditableImage gibt es nur
  auf dem Client).
- **Spielmodi wie Minecraft** (Spielmodus + Inventar leben in Minecraft, `/gamemode` im Chat ändert ihn, neue Spieler
  bekommen den Standard der Welt): **Überleben** – Items werden verbraucht, Abbauen dauert Minecrafts Abbauzeit (mit
  Rissen; Minecraft sagt, wie schnell – Hand, Werkzeug, in der Luft 5× langsamer), Fallschaden, beim Tod fällt das
  Inventar raus (Todesnachricht in Minecraft).
  **Kreativ** – Items gehen nie aus, Abbauen sofort, **2× Leertaste = fliegen** (Leertaste hoch, Shift runter, Strg
  doppelt so schnell, Landen beendet es), kein Schaden, keine Herzen. **Abenteuer** – nichts abbauen/setzen, aber
  Türen, Hebel, Knöpfe benutzen. **Zuschauer** – immer fliegen, durch Blöcke, unsichtbar für alle außer anderen
  Zuschauern (die sehen einen durchsichtigen Kopf), kein Inventar, keine Hotbar, nichts anklicken; in Minecraft kein
  Mannequin. Minecraft-Spieler im Zuschauermodus sehen auch nur Zuschauer.
- **Items am Boden – ganz synchron:** Was abgebaut, mit Q weggeworfen oder beim Tod verloren wird, liegt als Item in
  der Welt, genau wie in Minecraft (es gibt jedes nur einmal: das Item-Entity in Minecraft). Topic `mcworld.items` →
  pro Item ein unsichtbarer Part in `workspace.MinecraftItems` (Attribute `McItem`, `McCount`), jeder Client zeichnet
  es wie Minecraft: Blöcke als kleiner Würfel bzw. Modell (¼ Block), flache Items als Bild (½ Block), dreht sich,
  wippt, mehr Kopien bei größeren Stapeln. Wer zuerst nah genug ist, bekommt es – ein Minecraft-Spieler oder ein
  Roblox-Spieler, **das entscheidet Minecraft, also immer nur einer**; das Item fliegt dann zu ihm und ist weg.
- **Alle Icons sofort:** Nach dem Laden der Welt holt der Server die Icons aller Items im Hintergrund, der Client
  macht daraus gleich alle Bilder (ein paar pro Frame) – Hotbar und Kreativ-Inventar sind von Anfang an voll.
- **Hotbar + Inventar** mit Minecrafts eigener GUI-Grafik: Hotbar unten (Tasten **1–9**, Mausrad) mit Anzahl und
  Haltbarkeit, **E** = Inventar: Überleben/Abenteuer Minecrafts Inventar mit Minecrafts eigenen Klicks (links =
  aufnehmen/ablegen/tauschen, rechts = Hälfte/einzeln, Shift = verschieben, **2×2-Werkbank**, Klick daneben = wegwerfen),
  Kreativ das Kreativ-Inventar (alle Items, Mausrad scrollt; Klick = 1 aufnehmen, Rechtsklick = Stapel, Shift = Stapel
  in die Hotbar; zweiter Reiter = normales Inventar). **Q** wirft ein Item weg (Strg + Q den Stapel), **Mittelklick**
  nimmt den angeschauten Block (Kreativ: neu, Überleben: aus dem Inventar). Kreativ-Liste: die 23 von vorher, alle
  Holzblöcke aller Holzarten (Stämme, Holz, entrindet, Bretter, Treppen, Stufen, Zäune, Zauntore, Türen, Falltüren,
  Knöpfe, Druckplatten) und Redstone (Staub, Fackel, Block, Hebel, Knöpfe, Kolben, klebriger Kolben, Lampe,
  Verstärker, Komparator, Beobachter). Icons wie in Minecraft: flach (Redstone, Türen) oder 3D (auch Treppen, Zäune).
- **Leben + Schaden wie Minecraft:** 20 HP = 10 Herzen über der Hotbar (Roblox' eigene Leiste ist aus).
  Fallschaden ab 4 Blöcken (1 pro Block über 3). **Linksklick auf einen Minecraft-Spieler** schlägt ihn (Minecraft
  macht den Schaden, mit Rückstoß von deinem Mannequin). Schlägt ein Minecraft-Spieler dein Mannequin, verlierst du
  Leben (Schaden wie in Minecraft, auch mit Schwert): roter Blitz, Kamera kippt, Rückstoß. Die Lebensleiste eines
  Minecraft-Spielers zeigt sich über seinem NPC, wenn er nicht voll ist.
- **Alle sind Minecraft-Spieler** (`MinecraftCharacter`, ReplicatedStorage): kein Roblox-Rig mehr, sondern
  Minecrafts Spielermodell (Kopf 8×8×8 Pixel, Körper 8×12×4, Arme 4 bzw. 3 „slim“, Beine, zweite Skin-Schicht),
  Maßstab wie Minecraft (1 Skin-Pixel = 0,176 Studs). Der Root-Part **ist** Minecrafts Hitbox (0,6 × 1,8 Blöcke), nur
  0,1 Studs über dem Boden (so hält der Humanoid ihn selbst und bremst): man steht auf einem Block, solange irgendein
  Teil der Hitbox darüber ist – an Kanten sinken die Beine nicht mehr in den Block. Ohne Taste bremst Minecrafts
  Boden-Reibung (× 0,546 pro Tick), niemand rutscht. Gelenke wie in Minecraft: jedes Teil
  hängt einzeln am `ModelRoot` (den Füßen). Der Server legt den `StarterCharacter` an und schaltet Roblox' `Animate` ab.
- **Skins** (Command `mcworld.skin`): Minecraft-Spieler tragen ihren eigenen Skin, Roblox-Spieler einen der 18
  Minecraft-Standardskins (fest nach UserId, wie Minecraft es mit UUIDs macht) – in Roblox und an ihrem Mannequin.
  **`/skin <Minecraft-Name>`** im Chat übernimmt den Skin eines echten Minecraft-Accounts, `/skin` allein geht zurück.
  Jede Fläche jedes Körperteils hat eine `Texture` (Attribut `McSkinFace` = Stelle im 64×64-Skin), der Client holt
  die Pixel (`GetSkin`) und macht die Bilder.
- **Bewegen wie Minecraft** (`MinecraftPlayer`, StarterPlayerScripts): Gehen 4,317 / Sprinten 5,612 / Schleichen
  1,295 Blöcke/s, Sprung 1,25 Blöcke, Gravitation 83,5 Studs/s² (ein Sprung dauert wie in Minecraft 12 Ticks, Stürze
  gleich lang). Die Geschwindigkeit setzt das Script jedes Frame selbst mit Minecrafts Reibung (Boden × 0,546, Luft
  × 0,91 pro Tick – in der Luft bleibt der Schwung), der Root-Part hat keine Reibung: man bleibt nirgends mehr
  hängen und rutscht nicht weiter. Stufen bis 0,6 Blöcke (Stufen, Falltüren) läuft man hoch. Der Körper dreht sich mit
  einem AlignOrientation statt per CFrame. W A S D relativ zur Blickrichtung, **Leertaste** halten = immer wieder
  springen (nur mit den Füßen auf einem Block), Sprinten + Springen schiebt nach vorn, **Shift** halten = schleichen
  (Augen tiefer, man fällt nicht von Kanten), **Strg** = sprinten nur solange gehalten und vorwärts, oder **2× W**
  schnell = sprinten bis W losgelassen wird (wie Minecraft). In Studio Strg erst *nach* W drücken oder 2× W nehmen:
  Studio schnappt sich Strg + W, wenn Strg zuerst gedrückt ist (im echten Roblox-Spiel geht beides).
- **Kamera wie Minecraft:** Maus gefangen, kein Cursor, **F5** (oder **V**) wechselt Ego-Sicht → von hinten →
  von vorne. In Studio gehört F5 dem Studio („Play“) – dort ggf. File → Advanced → Customize Shortcuts den
  F5-Eintrag entfernen; im echten Spiel geht F5 so
  (4 Blöcke, Wände ziehen die Kamera ran), Fadenkreuz in der Ego-Sicht. Mausrad = Hotbar-Fach.
- **Animationen aus Minecraft:** `tools/make_animations.luau` rechnet Minecrafts eigenen Code (HumanoidModel 26.3:
  Gehen, Atmen, Schleichen, Schlagen, Sterben) in KeyframeSequences um (`examples/MinecraftWorld/animations/*.rbxm`,
  Rojo: `ReplicatedStorage.MinecraftAnimations`). `tools/upload_animations.py` lädt sie über Open Cloud als echte
  Roblox-Animationen hoch und schreibt die IDs nach `MinecraftAnimationIds.luau`. Bis dahin spielt Studio sie direkt
  aus den Dateien (`RegisterKeyframeSequence`, geht nur in Studio). Gehen läuft mit Minecrafts Formel: Gewicht und
  Tempo = min(Blöcke pro Tick × 4, 1). Der Kopf folgt dem Blick (hoch/runter) bei allen.
- **Chat:** **T** öffnet ihn. Was du schreibst, steht auch in Minecraft (`<Name · Roblox> …`), Minecrafts Chat
  (Spieler, `/say`, Beitritte, Tode …) kommt in den Roblox-Chat. **`/…`** ist ein Minecraft-Command: er läuft als
  du (dein Stellvertreter in Minecraft: `@s`, `~ ~ ~`, `/tp @s …` bewegt dich mit, `/gamemode creative`, `/give @s …`,
  `/clear`, `/kill`), die Antwort siehst nur du. Rechte: Mod-Config
  `robloxCommandLevel` (Standard 2 = OP-Commands wie `/time`, `/gamemode`, `/give`, `/tp`).
- **Arm schwingen:** Schlägt oder baut jemand, schwingt der Arm (Minecrafts Schlag-Animation) – auch ein Schlag in
  die Luft (Remote `Swing`), in Roblox und in Minecraft (Mannequins der Roblox-Spieler). Getroffene werden kurz rot.
- **Einstellungen (M)** im Minecraft-Look (Minecrafts Buttons/Slider aus dem Spiel): Sichtfeld 30–110 (Normal 70,
  Quake Pro 110) und **Shader**: Aus (das Spiel wie es ist), Sanft (warmes Licht, weiche Schatten, Dunst, Wolken),
  Kräftig (satte Farben, Leuchten, Sonnenstrahlen, goldener Dunst) – `MinecraftShaders`. Nur Aussehen, nur auf dem
  eigenen Client, nichts geht über Bridge oder an andere. Gilt für die Sitzung.
- **Tag + Nacht + Wetter wie Minecraft** (`MinecraftSky`, ReplicatedStorage; vom Client gestartet): Minecraft
  schickt seine eigenen Himmelswerte (Topic `mcworld.sky` – aus Minecrafts Zeitleisten „day“/„moon“, dem Biom und
  der Wetter-Schicht: Zeit, Sonnen-/Mondwinkel, Himmels-, Nebel-, Wolken-, Sonnenaufgangsfarbe, Himmelslicht 1 … 0,24,
  Regen/Gewitter, Regen oder Schnee hier) → Attribute `Mc…` an `Lighting`. Daraus: die Uhr (`/time set` in Minecraft
  stellt sie sofort), Helligkeit wie Minecrafts Lightmap (Tag hell, Nacht dunkelblau, Höhlen dunkel), keine
  Spiegelungen, der Horizont im Nebel- und der Himmel im Himmelsfarbton, Sonnenaufgang glüht, Minecrafts **eckige
  Sonne** und sein **Mond in der richtigen Phase** (ohne Kasten: Minecraft addiert sie auf den Himmel, ihr Schwarz
  wird durchsichtig), **Wolken** aus Minecrafts Wolkenbild auf Wolkenhöhe (ziehen nach
  Osten), Sterne nachts, **Regen und Schnee** wie Minecrafts Wetter (pro Blocksäule um die Kamera ein fallendes Bild,
  am Boden endend). Unter Wasser Minecrafts Wassernebel, in Lava sein Lavanebel. **Licht:** Fackeln, Laternen,
  Glowstone, Lava … leuchten wie Minecrafts Blocklicht (PointLight, Reichweite = Lichtstufe in Blöcken, warmes
  #FFD88C). Ein Shader aus dem Menü (M) übernimmt das Licht, Uhr/Sonne/Wolken/Regen bleiben.
- **Wasser + Lava wie Minecraft:** so hoch wie in Minecraft (Quelle 8/9 Block, fließendes Wasser stufenweise
  niedriger), Minecrafts bewegte Bilder (Wasser 32 Bilder alle 2 Ticks, fließend auf den Seiten, Lava in ihrer
  eigenen Reihenfolge), fließt wie in Minecraft (Minecraft rechnet, Roblox zeigt). **Eimer** (Kreativ-Liste: Eimer,
  Wassereimer, Lavaeimer, dazu Schnee, Eis, Fackel, Laterne, Glowstone, Seelaterne): Rechtsklick gießt / schöpft wie in
  Minecraft, auch in die Luft. **Schwimmen:** im Wasser Minecrafts Physik (langsam, Leertaste hoch, man sinkt langsam,
  an Kanten springt man raus, Lava noch zäher), **Sprinten unter Wasser = schwimmen** – liegend mit Minecrafts
  Schwimm-Animation (Armzüge, Beinschlag), Augen tief, hoch/runter wohin man schaut; alle sehen es (auch Minecraft:
  das Mannequin schwimmt, und schwimmende Minecraft-Spieler schwimmen in Roblox). **Luftblasen** wie Minecraft (10
  rechts über der Hotbar, 15 s Luft, platzen, danach 1 Herz pro Sekunde – „ertrunken“ in Minecraft), kein
  Fallschaden beim Landen im Wasser.
- **Bauen:** gezielt wird wie in Minecraft von den Augen aus (auch von hinten/vorne), Reichweite 4,5 Blöcke (Kreativ
  5), ein schwarzer Rahmen zeigt den Block bzw. seine Form. **Rechtsklick** = benutzen: Minecraft entscheidet mit
  seinem eigenen Code – Tür/Falltür/Zauntor auf und zu, Hebel umlegen, Knopf drücken (Holz 1,5 s, Stein 1 s an),
  sonst setzt es das Item in der Hand: der Stamm liegt wie geklickt, Treppen/Kolben schauen wie in Minecraft, Knöpfe
  hängen an der geklickten Seite, Redstone verbindet sich; mit Shift wird immer gesetzt. **Linksklick** = abbauen
  (Kreativ sofort, halten = alle 5 Ticks; Überleben mit Abbauzeit). Einfache Blöcke (Bretter, Stein, Erde …) auf
  einfache Blöcke (Gras, Stamm, Stein – nicht Werkbank, Tür, Kürbis: Minecrafts `use` im Look) stehen wie in
  Minecrafts eigenem Client **sofort** da – erst bei dir (ein Teil in `MinecraftWorld/McAtOnce`, bis der Block des
  Servers kommt; sagt Minecraft nein, ist er wieder weg), gleich danach beim Server für alle. **Hochbauen (springen +
  Rechtsklick)** geht deshalb wie in Minecraft: entschieden wird mit der Position, die dein Client beim Klick hatte
  (die Kopie des Servers hängt einen Moment hinterher – sie stand noch im Block), und die Antwort eines älteren
  Klicks macht einen neueren Block nicht mehr kaputt. Alles andere kommt, sobald Minecraft geantwortet hat (dann
  aber gleich richtig gedreht). Alles, was in Minecraft passiert (Kolben schieben, Redstone an/aus, Knopf geht
  aus), kommt sofort nach Roblox.

So startest du es:

1. Minecraft mit der Mod starten (Einzelspieler geht auch, der hat einen eigenen Server drin). Im Log steht
   `Bridge connected as ...`, und `/bridge` im Spiel zeigt den Status.
2. Roblox Studio → neue Baseplate. In einer CMD im Ordner `extensions\roblox`:
   `rojo serve minecraft-world.project.json --port 34874` → im Rojo-Plugin Port 34874 → Connect.
3. Einmalig für die Texturen: **Game Settings → Security → „Allow Mesh / Image APIs“** einschalten (sonst bleiben
   die Blöcke einfarbig und Hotbar/Inventar grau – das Output sagt es dann). → **Play**.
4. Einmalig für die Animationen außerhalb von Studio: Open-Cloud-API-Key (create.roblox.com → Open Cloud → API Keys,
   „Assets“ Read + Write) in eine Datei, dann
   `python extensions\roblox\tools\upload_animations.py <Key-Datei> <deine UserId>` – lädt die Animationen ohne ID
   hoch (neue wie „swim“), die IDs landen in `MinecraftAnimationIds.luau`, Rojo bringt sie ins Spiel. Nach Änderungen
   an den Animationen: `lune run extensions/roblox/tools/make_animations.luau`, dann mit `--all` am Ende alle neu.
5. Das Licht: `Lighting.Technology` = **Future** (setzt das Projekt; falls Studio es nicht übernimmt: von Hand im
   Explorer unter Lighting), sonst leuchten Fackeln nicht.

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
  Slim-Arme, die 8 Animationen (Gehen: Bein 1,4 rad nach hinten / Arm nach vorne, Schleichen, Tod auf die linke Seite,
  Schwimmen: liegend, Armzüge), `MinecraftSky`: Uhr aus dem Sonnenwinkel, Minecrafts Lightmap
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
