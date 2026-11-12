# 10 – Phase 6: SDKs, KI-Agenten, KI-Dienst, Suche, Föderation

Stand: 13.11.2026 (von Claude entworfen – Paddy war weg, „entscheide selber“; Freigabe steht aus). Entscheidungen:
ADR 0021 (SDKs), ADR 0022 (Agenten-Ausweise), ADR 0023 (Föderation), ADR 0024 (KI-Dienst lokal).

Ziel: Bridge aus jeder wichtigen Sprache nutzbar machen (Python, JavaScript, Java, Luau), KIs sicher einbinden (eigener,
begrenzter Ausweis statt geliehener Schlüssel), einen freien lokalen KI-Dienst anbieten, besser suchen und Netze
miteinander verbinden – alles mit denselben Regeln wie bisher (Zero Trust Z1–Z10, Abteile).

## 1. Überblick

| Teil | Was | Wo |
|---|---|---|
| SDKs | Python, JavaScript (Node + Browser), Java, Luau (Roblox-Server, Lune) – gleiche Prüfungen wie der Rust-Kern | `sdk/python`, `sdk/javascript`, `sdk/java`, `sdk/luau`, Testvektoren `sdk/vectors` |
| Agenten-Ausweise | Aussage `agent`: ein Mitglied gibt einem Programm (z. B. einer KI) einen eigenen Schlüssel mit wenigen Rechten, kurzer Laufzeit, Widerruf | `bridge-net::agent`, Knoten, alle SDKs, CLI `agent …` |
| KI-Dienst | `bridge-node ai`: beantwortet Aufgaben mit einem **lokalen** Modell (Ollama- oder OpenAI-kompatibler Server auf dem eigenen PC) | `services/ai`, `bin/bridge-node` |
| Suche | mehrere Wörter, Umlaute/Akzente egal, kleine Tippfehler, Filter nach Art | `bridge-net::state` |
| Föderation | Aussage `federation`: zwei Netze verbinden sich **beidseitig** über benannte Empfänger; Mitglieder schreiben sich Ende-zu-Ende verschlüsselt | `bridge-net`, Knoten, alle SDKs |

## 2. SDKs

### 2.1 Gemeinsame Regeln (für jede Sprache)
- **Ein Protokoll**: docs/04 genau so wie `bridge-core`: strenges JSON (doppelte Schlüssel, Kommazahlen, Zahlen außerhalb
  ±(2^53−1), Tiefe > 32 → Fehler), kanonisches JSON (RFC 8785, nur ganze Zahlen), Base64url ohne `=` und nur in
  kanonischer Schreibweise, IDs (Base32 von SHA-256 des Signier-Schlüssels, 20 Bytes), Domänen-Trennung
  `bridge4/<art>\n`, Grenzen vor dem Parsen.
- **Keine eigene Krypto** (Z10). Geprüfte Bibliotheken je Sprache (docs/02 §4):

  | Sprache | Ed25519, X25519, HKDF, ChaCha20-Poly1305, SHA-256 |
  |---|---|
  | Python ≥ 3.9 | `cryptography` (pyca, OpenSSL) |
  | JavaScript (Node ≥ 18 und Browser) | `@noble/curves`, `@noble/hashes`, `@noble/ciphers` 2.x (geprüft, MIT) – **eingebettet** in `sdk/javascript/vendor/` mit fester Version und SHA-256 je Datei (`vendor/SUMS`), damit Browser-Apps ohne npm laufen |
  | Java ≥ 17 | JDK (`Ed25519`, `XDH`, `ChaCha20-Poly1305`, `HmacSHA256`); HKDF nach RFC 5869 aus `HmacSHA256` |
  | Luau | Port von **TweetNaCl-js** (gemeinfrei, 2017 von Cure53 geprüft) für Ed25519/X25519/Poly1305 + ChaCha20, SHA-256, HMAC/HKDF nach RFC (Risiko R1, siehe 2.5) |
- **Strenge Prüfung wie im Kern**: Ed25519-Schlüssel kleiner Ordnung (die 14 Schreibweisen der 8 Punkte, Liste in den
  Testvektoren) und Signaturen mit `S ≥ L` werden abgelehnt; ein X25519-Ergebnis aus lauter Nullen ebenso.
- **N1**: Wegwerf-Schlüssel und Nonce erzeugt nur das SDK selbst aus dem Zufall des Systems; die öffentliche Schnittstelle
  nimmt nie einen Schlüssel oder eine Nonce an.
- **Gleiche Namen** in allen Sprachen (Stil der Sprache): `Identity` (erzeugen, laden, speichern), `KeyCard`, `Client`
  mit `join(link)`, `connect()`, `card_of(id)`, `send(card, text|bytes|json)`, `receive(wait)`, `request(card, json)`
  (Aufgabe senden und auf die Antwort warten), `ack`; Agenten: `issue_agent(…)`, `connect(agent=…)`; Föderation:
  `card_of(id, net)`, `send(…, net)`.
- **Schlüsseldatei**: dasselbe Format wie der Knoten (`{"v":4,"t":"secret","sign":"…","box":"…"}`), angelegt nur für den
  Besitzer lesbar (Unix 0600; Windows: im Benutzerordner). Luau hat kein Dateisystem: Schlüssel aus einem Modul im
  `ServerStorage` oder einem DataStore – nie im `ReplicatedStorage`.
- **Empfangen** wie in Rust: Umschlag prüfen (Form, an mich, mein Netz oder ein geprüftes verbundenes Netz §6, Zeit,
  Absender-Karte passt zur ID, Signatur), öffnen, Doppelte verwerfen (gemerkte `(from, id)` bis zum Ablauf, höchstens
  100.000; optional Datei), alles Abgeholte bestätigen, fehlgeschlagene Bestätigungen beim nächsten Abholen wiederholen.
- **Beitritt** wie in Rust: Netz-Info prüfen (Karte, signierte `info`-Aussage, Netz-ID), Gründungs-Manifest bis zur
  Netz-ID, Empfänger im Log (`gateway_in_log`), PoW lösen (höchstens 2^30 Versuche), Einladungscode, `member` prüfen.
- **Nicht in v1** (nur Rust-SDK): LAN-Suche (mDNS, gepinntes TLS), Ströme (> 180 KiB), Dateien/Apps/Speicher/Rechnen.
  Größere Daten: Dateien über das Rust-SDK oder später.

### 2.2 Testvektoren
`sdk/vectors/vectors.json` erzeugt ein Rust-Test (`tests/e2e/tests/sdk_vectors.rs`) **deterministisch** (feste Seeds,
fester Zufall) und vergleicht ihn mit der Datei im Repo – jede Änderung am Format fällt so sofort auf
(`BRIDGE_WRITE_VECTORS=1` schreibt sie neu). Jedes SDK muss alle Vektoren bestehen:
- JSON: gültige Eingaben → kanonische Bytes; ungültige (doppelt, Kommazahl, zu groß, zu tief, falsche Escapes) → Fehler.
- Kodierung: Base32, Base64url (auch nicht-kanonische → Fehler), ID aus Schlüssel.
- Identität aus geheimen Bytes → öffentliche Schlüssel, ID, Schlüsselkarte **byte-genau** (Ed25519 ist deterministisch).
- Aussagen (ein und mehrere Unterzeichner) byte-genau + Hash; signierte Anfrage prüfen (und verfälscht → Fehler).
- Umschlag von Rust versiegelt → das SDK öffnet ihn (Klartext genau); verfälschte Felder → Fehler.
- Inhalt (`content`) byte-genau; PoW-Lösung prüfen; Einladungs-Links (gültig/ungültig); schwache Schlüssel → abgelehnt.
- Agenten-Aussage und Föderations-Aussage prüfen (§3, §6).

### 2.3 Live-Test gegen einen echten Knoten
`tests/e2e` enthält das Programm `sdk-fixture`: es startet ein offenes Testnetz (ein Knoten auf 127.0.0.1), einen
**Echo-Client in Rust** (antwortet auf jede Nachricht mit `echo: <text>` und auf Aufgaben mit derselben JSON) und gibt
eine Zeile JSON aus (`{"link","echo","net","node"}`). Jedes SDK-Testskript startet es, tritt per Link bei, sendet an den
Echo-Client und muss die Antwort öffnen – so prüft jede Sprache beide Richtungen gegen Rust (versiegeln ↔ öffnen,
signieren ↔ prüfen). Dazu: Agent ausstellen und als Agent senden/empfangen; Sicht auf `agent_of`.

### 2.4 Pakete
- **Python** `sdk/python` (Paket `bridge4`, nur `cryptography` als Abhängigkeit, HTTP mit `urllib`, synchron). Tests:
  `python -m unittest` (Vektoren + Live).
- **JavaScript** `sdk/javascript` (ES-Modul `bridge4.js` + `src/`, ohne Build-Schritt, `fetch`; Node ≥ 18 und moderne
  Browser). Tests: `node --test`.
- **Java** `sdk/java` (Paket `net.bridge4`, nur JDK, eigener strenger JSON-Leser, `java.net.http`). Tests: ein
  Test-Programm ohne Fremd-Bibliotheken (`run_tests.sh`).
- **Luau** `sdk/luau` (Module `Bridge4`, `Crypto`, `Json`, …; HTTP über eine kleine Schnittstelle: Roblox `HttpService`
  oder Lune `net`). Tests mit Lune 0.8.9.

### 2.5 Luau (Risiko R1)
- Roblox hat keine Krypto-Bausteine. Der Port von TweetNaCl-js rechnet mit 16 Gliedern zu 16 Bit in Luau-Zahlen
  (Doubles, wie das JavaScript-Original) – deshalb ein **Port** statt eigener Mathematik. ChaCha20, SHA-256, HMAC und HKDF
  folgen den RFCs zeilennah. Geprüft nur über Testvektoren (RFC 8439, RFC 7748, RFC 8032, FIPS 180-4, RFC 5869) und die
  Bridge-Vektoren – nicht von Dritten. Deshalb im SDK sichtbar gekennzeichnet („Luau-Krypto: Port, Restrisiko R1“).
- Keine Timing-Garantie (Luau-Interpreter); der Schlüssel liegt nur auf dem Roblox-Server.
- Nur auf dem Server (`HttpService`), höchstens 500 Anfragen pro Minute (Roblox-Grenze): Abholen mit `wait` ≤ 20 s.
- Leistung (Lune, Richtwert): Signieren/Prüfen/Öffnen je einige Millisekunden bis wenige zehn Millisekunden – reicht für
  Spiel-Server mit wenigen Nachrichten pro Sekunde.

## 3. Agenten-Ausweise (KI-Agenten mit begrenzten Rechten)

**Problem**: Eine KI (oder ein Bot) soll für ein Mitglied Nachrichten schicken und lesen – mit dem Schlüssel des Mitglieds
könnte sie alles (Apps veröffentlichen, Namen eintragen, beitreten, melden …), und ein Leck wäre der ganze Ausweis.
**Lösung**: Der Agent hat einen **eigenen** Schlüssel. Das Mitglied (Inhaber) stellt ihm eine Aussage `agent` aus: wenige
Rechte, ein Heim-Knoten, kurze Laufzeit, jederzeit widerrufbar. Der Agent ist **kein Mitglied** und bekommt nie
Mitglieds-Rechte.

### 3.1 Aussage `agent` (nicht im Log)
```json
{"v":4,"t":"agent","net":"<netz>","iss":"<inhaber>","iat":0,"exp":0,"sig":"…",
 "body":{"agent":"<agent-id>","card":<karte des agenten>,"owner":<karte des inhabers>,"node":"<heim-knoten>",
         "scopes":["receive","send"],"to":["<id>",…],"rate":60,"note":"Rika KI"}}
```
- Ein Unterzeichner = Inhaber (`iss` = `owner.id`); `owner` und `card` sind geprüfte Schlüsselkarten (Rolle `client` oder
  `admin` beim Inhaber, `client` beim Agenten), `card.id` = `agent`, Agent ≠ Inhaber.
- `scopes`: nicht leer, ohne Doppelte, nur `send` (Nachrichten schicken) und `receive` (abholen, bestätigen). Unbekannte
  Rechte → ungültig (spätere Rechte kommen nur mit neuer Spezifikation).
- `to` (optional, 1–32 IDs, ohne Doppelte): an wen der Agent schreiben darf. Fehlt es: an alle Mitglieder des Netzes.
- `rate` (optional, 1–3.600, Standard 60): Sendungen pro Stunde. `note` (optional, ≤ 64 Zeichen, druckbar): Name/Zweck.
- Laufzeit `exp − iat` ≤ **30 Tage**; Größe wie jede Aussage (≤ 64 KiB).

### 3.2 Anmelden, Rechte, Weiterleiten
- Anmelden **nur am Heim-Knoten** (`node`): Login wie üblich mit der Karte des Agenten und zusätzlich `"agent": <aussage>`
  (ohne `home`). Der Knoten prüft: Aussage gültig (§3.1, Zeit, Signatur des Inhabers), `agent` = `iss` des Logins,
  Karte gleich, `node` = dieser Knoten, Knoten ist Empfänger, **Inhaber ist Mitglied und nicht gesperrt**, Agent nicht
  widerrufen. Dann ist die Aussage der „Heim-Eintrag“ des Agenten (wie `home`, docs/06 §8) und reist im Heim-Austausch zu
  den anderen Empfängern – so finden Nachrichten an den Agenten ihren Weg.
- **Standard: verboten.** Eine Agenten-Sitzung darf nur: `/v4/send` (Recht `send`; Empfänger in `to`, falls gesetzt;
  höchstens `rate` pro Stunde; nicht über Netzgrenzen §6), `/v4/poll` und `/v4/ack` (Recht `receive`), `/v4/card`.
  Alles andere mit Sitzung → `403 FORBIDDEN`. Signierte Anfragen eines Agenten scheitern ohnehin an der Mitglieds-Prüfung.
- Bei jeder Nutzung erneut: Aussage noch gültig, Inhaber noch Mitglied und nicht gesperrt, nicht widerrufen. Die Sitzung
  merkt sich, dass sie einem Agenten gehört (ein Mitglied, das zugleich Agent eines anderen ist, behält in seiner eigenen
  Sitzung seine Rechte). Höchstens 16 Agenten je Inhaber und Knoten (ihre Heim-Einträge teilen die Tabelle mit den
  Mitgliedern).
- Weiterleiten an andere Empfänger (`/v4/node/relay`): Die Anfrage trägt zusätzlich `"agent": <aussage>`; der Empfänger
  prüft sie genauso (Inhaber Mitglied, `send`, `to`) statt der Mitgliedschaft des Absenders.
- Nachrichten **an** einen Agenten: Weg über seinen Heim-Eintrag; zugestellt wird nur, solange die Aussage gilt und der
  Inhaber Mitglied ist.

### 3.3 Widerruf
`POST /v4/agent/revoke` am Heim-Knoten: signierte Anfrage des Inhabers (`op: "agent-revoke"`,
`body: {"agent":"<id>"}`, mit Sitzung des Inhabers). Alle Agenten-Aussagen dieses Inhabers für diesen Agenten mit
`iat` ≤ jetzt sind ab sofort ungültig: laufende Sitzungen enden, der Heim-Eintrag verschwindet, die Sperre bleibt
gespeichert (Schema 13, bis zum spätesten möglichen Ablauf: 30 Tage), höchstens 256 je Inhaber und 100.000 je Knoten.
Ohne Widerruf endet jeder Agent spätestens nach 30 Tagen.

### 3.4 Was der Empfänger sieht
Die Antwort von `/v4/poll` trägt zusätzlich `"agents": {"<agent-id>": <aussage>}` für Absender, die Agenten sind. Das SDK
prüft die Aussage selbst (Signatur des Inhabers, Form, Zeit) und meldet die Nachricht als „von Agent X **im Auftrag von**
Inhaber Y (note)“ (`agent_of`). Fehlt oder scheitert die Aussage, erscheint nur der Agent – nie ein falscher Inhaber.

### 3.5 Werkzeuge
CLI: `bridge-node agent issue --owner-key <datei> --agent-key <datei> --net <id> --node <id> --scopes send,receive
[--to id,…] [--rate n] [--days n] [--note text] > agent.json` (legt die Agenten-Schlüsseldatei an, falls sie fehlt);
`bridge-node agent revoke --owner-key <datei> --node-url <url> --agent <id>`. SDKs: `issue_agent(…)` und Anmelden mit
`agent=…`.

## 4. KI-Dienst (lokal, gratis)

`bridge-node ai` ist ein **Client** des Netzes mit eigener Identität (Mitglied wie jeder andere): Er holt Aufgaben ab,
fragt ein Sprachmodell **auf demselben PC** und antwortet Ende-zu-Ende verschlüsselt. Kein Cloud-Schlüssel, keine Kosten,
die Fragen verlassen den PC nicht (außer verschlüsselt zum Fragenden).

- **Aufgabe**: Inhalt `type: "task"`, `ctype: "application/json"`, `data` = JSON
  `{"prompt":"…","system":"…"?,"model":"…"?,"max_tokens":n?}` (Prompt ≤ 32 KiB, System ≤ 8 KiB, `max_tokens` 1–4.096,
  Standard 512; `model` nur aus der erlaubten Liste, sonst das Standard-Modell).
- **Antwort**: `type: "response"`, `reply` = ID des Aufgaben-Umschlags, `ctype: "application/json"`, `data` =
  `{"text":"…","model":"…"}` (Text ≤ 64 KiB, sonst gekürzt mit `"truncated":true}`) oder `{"error":"CODE","message":"…"}`
  mit `BAD_TASK`, `NOT_ALLOWED`, `RATE_LIMITED`, `BUSY`, `BACKEND`.
- **Modell-Server**: `--api ollama` (Standard, `POST /api/generate`, `stream:false`) oder `--api openai`
  (`POST /v1/chat/completions`, z. B. llama.cpp-Server, LM Studio). `--backend` muss **Loopback** sein
  (`http://127.0.0.1:…`, `http://[::1]:…`, `http://localhost:…`) – sonst startet der Dienst nicht (kein Weg ins Internet,
  keine Daten-Abflüsse). Zeitlimit 120 s, Antwort des Modell-Servers ≤ 1 MiB.
- **Wer darf**: `--allow <id,…>` (Liste) oder `--allow-members yes` (jedes Mitglied, das ihn erreicht – auch aus
  verbundenen Netzen); Agenten nur mit `--allow-agents yes` (und bei einer Liste nur, wenn der Agent selbst darauf
  steht).
- **Start**: `bridge-node ai --key ki.json --join <link> --model llama3.2 --allow-members yes` (danach
  `--node-url <adresse>` statt `--join`); `--backend` Standard `http://127.0.0.1:11434` (Ollama).
- **Grenzen**: eine Aufgabe zur Zeit (Modelle sind groß), Warteschlange ≤ 16, je Absender ≤ `--rate` Aufgaben pro Stunde
  (Standard 30; auch fehlerhafte zählen). Antworten nie an Unbekannte: geantwortet wird nur dem geprüften Absender des Umschlags.
- **Finden**: Der Betreiber kann dem Dienst einen Namen geben (`names` Art `member`, docs/08), z. B. `ki.meinnetz`.
- Abteile: `services/ai` (Crate `bridge-ai`) enthält die reine Logik (Aufgabe prüfen, Modell-Anfrage bauen, Antwort
  lesen, Grenzen) und nutzt nur `bridge-plugin-api` + `bridge-core`; das Programm (`bin/bridge-node`, Befehl `ai`)
  verbindet Netz (Rust-SDK) und Modell-Server (HTTP).

## 5. Suche verbessern (docs/08 §7)
`POST /v4/names/search` `{"q","safe"?,"max"?,"kind"?}`:
- **Mehrere Wörter** (durch Leerzeichen, höchstens 4): jedes Wort muss passen (Name, Schlagwort oder ein Wort der
  Beschreibung); der Rang ist der schlechteste der Wörter.
- **Umlaute und Akzente egal**: Vergleich nach Falten (`ä→a`, `ö→o`, `ü→u`, `ß→ss`, `é→e` …) in Kleinbuchstaben – für
  Beschreibungen und Schlagworte (Namen sind ohnehin ASCII).
- **Kleine Tippfehler** (neuer Rang 5): ein Buchstabe falsch, zu viel, zu wenig oder zwei vertauscht – für Wörter ab
  4 Buchstaben (ohne Ziffern: `shop24` ist kein Tippfehler von `shop25`), nur gegen Namen und Schlagworte (in linearer
  Zeit je Name geprüft, ohne Tabelle). Auch reservierte Schlagworte (z. B. `paypa1` eines Inhabers der Stufe 3)
  erscheinen so – nach allen besseren Treffern.
- **Filter** `kind`: `app`, `node` oder `member`.
- Grenzen unverändert (≤ 50 Ergebnisse, `MAX_SEARCH_CHECKS`, `more`).

## 6. Föderation (Netze verbinden)

Zwei Netze verbinden sich nur, wenn **beide** Hauptschlüssel es wollen (wie das beidseitige Server-Vertrauen in Bridge 3).
Danach können Mitglieder des einen Mitgliedern des anderen schreiben – Ende-zu-Ende verschlüsselt, über benannte
Empfänger. Namen, Apps und Rechte bleiben in jedem Netz für sich.

### 6.1 Aussage `federation` (im Log)
```json
{"v":4,"t":"federation","net":"<A>","iss":"<A>","iat":0,"exp":0,"sig":"…",
 "body":{"peer":"<B>","gateways":[<knotenkarte eines empfängers von B, mit urls>,…],"scope":["messages"]}}
```
- Nur der **Hauptschlüssel** des Netzes unterschreibt (allein). `peer` ≠ eigenes Netz. `gateways`: 1–8 Empfänger des
  anderen Netzes mit ihren Knotenkarten (Rolle `node`, mit `urls`, ohne Doppelte). `scope`: genau `["messages"]` (mehr
  später). Höchstens 32 verbundene Netze; eine neue Aussage für denselben `peer` ersetzt die alte; Widerruf über `revoke`
  (nur Hauptschlüssel). Laufzeit wie jede Aussage (≤ 2 Jahre). CLI: `bridge-node net federate --data <ordner>
  --peer <netz-id> --gateway <adresse>…` (holt die Karten, prüft, dass sie zum Netz gehören, fragt die 24 Wörter) und
  `net unfederate --peer <netz-id>` (Widerruf mit dem Hauptschlüssel).
- **Beidseitig**: A leitet nur an B weiter, wenn A eine gültige `federation(B)` hat; B nimmt nur von A an, wenn B eine
  gültige `federation(A)` hat **und** der anrufende Knoten in deren `gateways` steht.

### 6.2 Umschlag mit Ziel-Netz
Neues optionales Feld im Umschlag: `"dnet":"<ziel-netz>"` (≠ `net`, signiert und in den AAD wie jedes Kopf-Feld). `net`
bleibt das Netz des Absenders. Ohne `dnet`: wie bisher.

### 6.3 Weg einer Nachricht A → B
1. Client (Mitglied von A) holt die Karte des Empfängers: `POST /v4/card {"id","net":"<B>"}` → sein Knoten fragt die
   Empfänger von B (`POST /v4/fed/card`, signierte Anfrage `op:"fed-card"`, `body:{"id"}`); B antwortet nur, wenn
   `federation(A)` gilt, der Anrufer gelistet ist und `id` ein Mitglied mit Heim-Eintrag ist. Karten beglaubigen sich
   selbst (ID = Hash).
2. Client sendet den Umschlag mit `dnet: B` an seinen Knoten (`/v4/send`): Form, Zeit, `from` = Sitzung, `net` = A,
   Signatur, `federation(B)` gilt → in die Warteschlange (wie Weiterleiten, dauerhaft, Wiederholen bis `ttl`).
3. Der Knoten von A übergibt an die Empfänger aus `federation(B).gateways` (der Reihe nach, bis einer annimmt):
   `POST /v4/fed/relay` `{"envelope","rq"}`, `rq.op = "fed-relay"`, `rq.body = {"envelope":"<hash>","card":<absender>}`.
4. Der Empfänger in B prüft: Anfrage für ihn, frisch, einmalig; `federation(A)` gilt in B; Anrufer in deren `gateways`
   (Signatur mit **dieser** Karte); Umschlag `net` = A, `dnet` = B, Absender-Karte passt, Absender nicht in B gesperrt,
   Signatur; Empfänger ist Mitglied von B mit **Heim hier** (sonst `UNKNOWN_IDENTITY` → A versucht den nächsten
   Empfänger); Grenzen und Replay wie immer → Postfach. Kein weiterer Sprung.
5. Abholen: Die Antwort von `/v4/poll` trägt für Umschläge aus fremden Netzen `"feds": {"<A>": <federation(A)>}` und
   `"master": <karte des eigenen hauptschlüssels>`. Das SDK nimmt einen Umschlag mit `net` ≠ eigenes Netz nur an, wenn
   `dnet` = eigenes Netz und die beigelegte `federation`-Aussage gilt: Art, Netz = eigenes, allein vom Hauptschlüssel
   signiert (Karte: Rolle `net`, ID = eigenes Netz), `peer` = `net` des Umschlags, Zeit, `scope` mit `messages`.
6. Antworten gehen genauso zurück (B → A mit `dnet: A`).

### 6.4 Grenzen und Schutz
- Agenten schreiben nicht über Netzgrenzen (v1). Bans gelten je Netz: B kann ein Mitglied von A für B sperren.
- Grenzen wie beim Weiterleiten (Postfach, je Absender, Replay); `fed-card` 5/s je Anrufer.
- Föderation verrät dem anderen Netz nur, was zum Zustellen nötig ist: Absender-Karte und Empfänger-ID.

## 7. Abnahme Phase 6
- Python, JavaScript, Java, Luau: alle Testvektoren grün; Live-Test gegen `sdk-fixture` (beitreten, senden, Echo
  öffnen, Aufgabe/Antwort, als Agent senden/empfangen) grün.
- Agent: darf nur `send`/`receive`, nur an `to`, nur `rate`; nach Widerruf/Ablauf/Sperre des Inhabers sofort nichts mehr;
  Empfänger sieht den Inhaber richtig, eine gefälschte Aussage nie.
- KI-Dienst: Aufgabe → Antwort vom (Test-)Modell; nicht erlaubte Absender, zu große Aufgaben, Rate → Fehler-Antwort;
  Nicht-Loopback-Backend → startet nicht.
- Suche: mehrere Wörter, Umlaute, Tippfehler, Filter.
- Föderation: Mitglied A ↔ Mitglied B in beide Richtungen; einseitige Föderation, nicht gelisteter Knoten, falsches
  `dnet`, gefälschte `federation` beim Client → abgelehnt; Widerruf trennt sofort.

## 8. Offen
- SDKs v1 ohne LAN, Ströme, Dateien – später je Bedarf. Luau-Krypto: unabhängige Prüfung wäre gut (R1).
- Föderation nur für Nachrichten; Namen/Apps über Netzgrenzen später.
- KI-Dienst: Ströme für lange Antworten, mehrere Modelle gleichzeitig später.
