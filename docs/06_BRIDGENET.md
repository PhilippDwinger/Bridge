# 06 – BridgeNet (Phase 3): Netz, Log, Mitglieder, Weiterleitung

Baut auf 02 (Sicherheitsmodell) und 04 (Protokoll) auf. Alle Objekte sind strenges JSON, signiert mit
Domänen-Trennung (`bridge4/<t>`), alle Listen begrenzt. Dieses Dokument ist die Vorlage für `bridge-net` und die
Netz-Teile von `bridge-node`.

## 1. Hauptschlüssel aus 24 Wörtern
- **Erzeugen**: 32 Byte Zufall → BIP-39 (englische Standard-Liste, 24 Wörter, Prüfsumme).
- **Ableiten** (deterministisch, gleiche Wörter → gleicher Schlüssel überall):
  1. `seed = BIP-39-Seed(wörter, passphrase "")` (PBKDF2-HMAC-SHA512, 2048 Runden, 64 Byte).
  2. `sign = HKDF-SHA256(ikm = seed, salt = "bridge4/master/v1", info = "sign", 32 Byte)`
  3. `box = HKDF-SHA256(ikm = seed, salt = "bridge4/master/v1", info = "box", 32 Byte)`
- **Netz-ID** = ID des Hauptschlüssels (Schlüsselkarte mit `role: "net"`). Ein Hauptschlüssel meldet sich nie bei
  einem Knoten an (04 §7).
- Die Wörter werden einmal angezeigt und nicht gespeichert. Gebraucht werden sie nur für: Genesis-Manifest,
  Delegationen (Admins), Widerruf von Admins, Manifest-Änderungen ohne Admins.
- Falsche Wörter (Tippfehler) scheitern an der BIP-39-Prüfsumme, bevor ein Schlüssel entsteht.

## 2. Schlüsselkarte von Knoten: Adressen
Knoten-Karten (`role: "node"`) dürfen ein Feld `urls` haben: 1–4 verschiedene Adressen (`https://…` oder
`http://…`, je max. 200 Zeichen). Es ist mit-signiert, also kann niemand einem Knoten eine fremde Adresse
unterschieben. Karten anderer Rollen mit `urls` oder `tls` sind ungültig. Clients und andere Knoten erreichen ihn
darüber.

*Nach Prüfung 8* – **Form einer Adresse** (eine Regel für Karten, Start-Empfänger im Manifest, `gw` im
Einladungslink, `--url`, BridgeControll; `bridge_core::keys::check_url`): genau `http(s)://host[:port][/pfad]`.
`host` ist ein DNS-Name (Teile aus `A–Z a–z 0–9 - _`, durch einzelne Punkte getrennt, kein leerer Teil, kein Punkt am
Ende), eine IPv4-Adresse in dieser Form oder eine IPv6-Adresse in eckigen Klammern (ohne Zone); `port` 1–65535, nur
Ziffern; `pfad` nur `/` und `A–Z a–z 0–9 - . _ ~`, keine Teile `.` oder `..`. Also kein `?`, `#`, `@`, keine
Benutzer-Angabe, keine `%`-Kodierung, keine Leer- oder Steuerzeichen. Grund: Knoten hängen ihre API-Pfade an diese
Adressen an (`<url>/v4/info`); mit `http://10.0.0.1/admin?x=` würde daraus eine ganz andere Anfrage. Karten im Log, die
das nicht erfüllen, sind ungültig (das Abspielen überspringt ihre Siegel).

*Nach Prüfung 8* – **Adress-Schutz** (`bridge-node`, `bridge_transport::HttpClient::new_public`): Adressen, die ein
Knoten **allein** gewählt hat, ruft ein anderer Knoten nur auf öffentlichen IP-Adressen an – sonst könnte jedes
Mitglied ihn gegen sein eigenes Netz richten (`http://127.0.0.1:7380/…`, `http://169.254.169.254/…`, der Router).
„Allein gewählt“ sind die Adressen einer **Anmeldung beim Wächter** (§11.5) und die Adressen einer Karte, die **nur
ein Wächter** gesiegelt hat (Stufe-1-Siegel, §11). Adressen, für die ein Admin oder der Hauptschlüssel eingestanden
hat (Karte in einem Siegel, das nicht von einem Wächter allein ist; Start-Empfänger im Manifest), gelten wie bisher
(`NetState::vetted_urls`).
- Ein Name wird für jeden Aufruf neu aufgelöst (höchstens 3 s, höchstens 8 Adressen); nur öffentliche Adressen
  bleiben, und genau mit ihnen wird verbunden (der Name ist für diesen Aufruf darauf festgelegt – keine zweite
  Auflösung, die anders antworten könnte; kein Proxy dazwischen). IP-Adressen werden in der Form geprüft, die der
  HTTP-Client selbst benutzt (`http://2130706433/` ist `127.0.0.1`).
- **Nicht öffentlich**: 0.0.0.0/8, Loopback, privat (10/8, 172.16/12, 192.168/16), 100.64/10 (CGNAT – auch Tailscale),
  Link-Local (169.254/16), Multicast, Broadcast und 240/4, Dokumentation, 198.18/15, 192.0.0/24; bei IPv6 `::`, `::1`,
  fc00::/7 (ULA), fe80::/10, fec0::/10, Multicast, ::/96, 100::/64, Teredo, 2001:db8::/32 – IPv4 in IPv6 (`::ffff:…`,
  64:ff9b::/96, 2002::/16) nach der IPv4-Adresse darin.
- **Ausnahme LAN**: Ein Knoten, der im LAN über seinen **gepinnten** TLS-Fingerabdruck erreicht wird, ist geprüft –
  ohne passendes Zertifikat geht keine Anfrage hinaus.
- **Regel** `bridge-node --peer-addresses public|tailnet|any` (`NodeConfig::peer_addresses`,
  `bridge_transport::PeerAddresses`):
  - `public` (Standard von `bridge-node`): nur öffentliche Adressen wie oben.
  - `tailnet`: öffentliche Adressen **und** die Bereiche von Tailscale – IPv4 100.64.0.0/10 und IPv6
    fd7a:115c:a1e0::/48 (auch als `::ffff:100.64.…`), sonst nichts: Loopback, RFC 1918, Link-Local, andere ULAs bleiben
    gesperrt. Grund: Im eigenen Tailnet löst MagicDNS `<gerät>.<tailnet>.ts.net` (auch Funnel-Adressen) zu einer
    100.x-Adresse auf – ein Wächter auf einem Tailnet-PC erreicht die Funnel-Adressen der anderen eigenen Knoten sonst
    nicht. Bleibt: Jedes Gerät im selben Tailnet ist so erreichbar (wer das nicht will, nimmt `public`).
    **Standard in BridgeControll v2** (je Knoten einstellbar: „Öffentlich“ / „Öffentlich + Tailnet“ / „Alle
    (unsicher)“; ADR 0017).
  - `any`: keine Prüfung – nur für Netze in einem LAN und für Tests auf 127.0.0.1.
Für das LAN (ADR 0004) kommt optional `tls` dazu: Base64url(SHA-256 des DER-Zertifikats) des selbst-signierten
TLS-Zertifikats des Knotens. Wer die Karte kennt, verbindet sich im LAN nur mit genau diesem Zertifikat (Pinning
statt Zertifizierungsstelle). mDNS-Ankündigungen (`_bridge4._tcp`, TXT `id=<knoten-id>`) sind nur Hinweise, wo
der Knoten gerade ist – vertraut wird erst nach dem gepinnten TLS-Handshake.

*Beim Bau festgelegt (`bridge-transport`, Modul `lan`):* Schlüssel ECDSA P-256/SHA-256 (rustls mit ring, kein
aws-lc), selbst-signiert, 10 Jahre gültig – Name und Daten zählen nicht, nur der Fingerabdruck. Nur TLS 1.3, keine
Sitzungs-Wiederaufnahme (jede Verbindung beweist den Schlüssel neu), kein SNI, ALPN `http/1.1`, Handshake max. 10 s.
Zertifikat und Schlüssel liegen als eine PEM-Datei (geheim) im Datenordner des Knotens. mDNS: Instanzname = Knoten-ID,
Host `bridge4-<id>.local.`, TXT `id` und `v=4` (+ max. 8 kurze Zusatz-Einträge); eine Suche liefert max. 256 Treffer
mit je max. 8 Adressen, kaputte Einträge werden ignoriert, dieselbe ID kann mehrfach vorkommen (alle probieren).

### LAN im Knoten und im SDK (Phase 3)
*Beim Bau festgelegt (`bridge-node`, `sdk/rust`):*
- **Einschalten**: `bridge-node … --lan 7443` (oder `--lan <ip:port>`). Der Knoten lauscht dann zusätzlich per TLS auf
  `0.0.0.0:7443` – mit **demselben Handler und denselben Grenzen** wie die normale Adresse, aber **ohne vertraute
  Proxys** (im LAN steht niemand dazwischen; `X-Forwarded-For` zählt dort nie). Er kündigt sich per mDNS an (TXT
  zusätzlich `net=<netz-id>`, wenn er in einem Netz ist) und sucht andere Knoten seines Netzes. Schlägt die
  Ankündigung fehl (kein Multicast, Firewall), läuft er weiter und meldet das – im LAN ist er dann nur mit Adresse
  erreichbar. Beim Beenden: Ankündigung zurückziehen (Goodbye), dann beide Zugänge schließen.
- **Zertifikat**: `node-tls.pem` im Daten-Ordner, wie `node-key.json` einmal angelegt (neue Datei, nur für den
  Besitzer lesbar, erst unter Zwischennamen geschrieben) und **nie ersetzt**: eine kaputte Datei (Müll, abgeschnitten,
  Schlüssel passt nicht zum Zertifikat, über 16 KiB) stoppt den Start mit klarer Meldung und bleibt unverändert. Ohne
  `--lan` wird die Datei nicht gelesen.
- **Karte**: Mit LAN trägt die Karte des Knotens `tls` = Fingerabdruck dieses Zertifikats, ohne LAN nicht.
- **Fingerabdruck stabil halten – wegen der Siegel**: Andere Knoten nehmen den Pin für einen Knoten aus seiner Karte
  **im Log** (Siegel bzw. Start-Empfänger), nicht aus seiner aktuellen Antwort. Ein Siegel enthält die Karte vom
  Zeitpunkt des Siegelns. Damit sie passt, bleibt das Zertifikat über Neustarts gleich. Folgen:
  - `net create` legt `node-tls.pem` gleich mit an, damit Genesis-Manifest und Siegel des Owner-Knotens den
    Fingerabdruck von Anfang an enthalten (ob der Knoten im LAN erreichbar ist, entscheidet erst `--lan`).
  - Ein Knoten, der erst nach seinem Siegel mit `--lan` startet (oder dessen `node-tls.pem` gelöscht wurde), wird von
    anderen Knoten im LAN nicht erkannt, bis er mit seiner aktuellen Karte neu gesiegelt ist (`net seal`); bis dahin
    gehen Knoten-Anfragen über seine `urls`. Der Knoten warnt beim Start, wenn die Karte in seinem Siegel ein anderes
    (oder kein) Zertifikat nennt. Clients betrifft das nicht (sie nehmen den Pin aus dem Link oder der Karte).
  - **Welche Karte gilt** (*nach Prüfung 4, geändert nach Prüfung 5*): Hat ein Knoten mehrere Siegel (verschiedene
    Stufen), zählt die **neueste Karte** unter ihnen – nach dem `iat` der **Karte selbst** (bei Gleichstand das `iat`
    des Siegels, dann sein Hash), gleich auf welcher Stufe. Eine Karte signiert nur der Knoten selbst, also kann nur er
    eine neuere machen: Ein Neu-Siegeln mit seiner aktuellen Karte ersetzt immer die alte Adresse und den alten Pin,
    ein Neu-Siegeln mit einer **alten** Karte aus dem Log (z. B. durch einen einzelnen Admin mit `seals` auf Stufe 1
    über ein Stufe-3-Siegel des Hauptschlüssels) holt nie alte Adressen oder einen alten Pin zurück (`card_of`,
    `gateways()`, §6). Vorher zählte das neueste *Siegel* – so ließ sich die Karte zurückdrehen (Prüfung 5, Befund 4).
    *Nach Prüfung 6* (Befund 6): „Neueste“ heißt größtes `min(iat der Karte, iat des Siegels)`, und ein Siegel, dessen
    Karte mehr als 5 min (Uhren-Toleranz) **nach** dem Siegel selbst ausgestellt ist, ist ungültig (das Abspielen
    überspringt es, §6). Vorher gewann eine Karte mit `iat` weit in der Zukunft (falsche Uhr, absichtlich) für immer –
    keine spätere echte Karte kam mehr an ihr vorbei.
    `net seal` nimmt beim Neu-Siegeln ohne `--level` die Stufe des höchsten aktiven Siegels des Knotens und ohne
    `--services` dessen Dienste – es ersetzt also genau dieses Siegel, statt ein zweites auf Stufe 2 daneben zu legen.
    Ohne Siegel bleibt es bei Stufe 2 und `gateway`.
- **Knoten ↔ Knoten** (Weiterleitung, `home`-Austausch, Log folgen, Gossip, Zeugen, `submit`): Für einen Knoten X
  wird erst über das LAN versucht – wenn X kürzlich im LAN gesehen wurde **und** seine Karte im Log `tls` hat, mit
  genau diesem Pin (höchstens 4 LAN-Adressen) –, dann über die `urls` seiner Karte. Scheitert eine Verbindung, kommt
  die nächste Adresse dran; eine Antwort ist eine Antwort (keine zweite Zustellung über den anderen Weg).
- **Suchen, begrenzt**: Nie pro Anfrage. Ein Hintergrund-Takt hört alle 30 s für 2 s auf mDNS; was er sieht, gilt
  drei Runden (96 s), höchstens 256 Knoten mit je 8 Adressen. Eine LAN-Adresse, mit der keine Verbindung zustande
  kam (tot, falsches Zertifikat, Unsinn), wird bis zur nächsten Runde vergessen – **nur für diese ID** (eine gefälschte
  Ankündigung mit der Adresse eines echten Knotens nimmt diesem seine Adresse nicht weg). Verbindungsaufbau im LAN max.
  3 s. Statt mDNS kann ein Programm Adressen vorgeben (`Discovery::Hints`, z. B. Tests oder Netze ohne Multicast).
  Welche IDs gemerkt werden (*nach Prüfung 4*): Hat der Knoten einen Netz-Zustand, nur IDs, deren Karte im Log einen
  `tls`-Pin hat (nur zu ihnen geht er je über das LAN – erfundene IDs können die Tabelle nicht füllen). Ohne Zustand
  (Log wird noch geladen) jede; ist die Tabelle voll, wird die am längsten nicht gesehene verdrängt.
  *Nach Prüfung 5*: Dieser Filter läuft schon **in der Suche selbst**, vor allen „wer zuerst kommt“-Grenzen
  (`Discovery::peers_matching`, `browse_matching`) – sonst füllten 256 Ankündigungen erfundener IDs die Trefferliste,
  bevor die echten ankommen. Von einer ID zählen höchstens **4 Ankündigungen** (verschiedene Instanznamen, die ersten
  gewinnen), Treffer kommen in der Reihenfolge, in der sie zuerst gesehen wurden, und ihre Adressen werden **reihum**
  zusammengelegt (erste Adresse jeder Ankündigung, dann die zweite …), die früheste zuerst: Eine Kopie der ID mit 8
  eigenen Adressen kann nicht alle 8 Plätze des echten Knotens belegen.
  *Nach Prüfung 6* (Befund 5): Vier Kopien einer ID unter anderen Instanznamen, die zuerst ankamen, hielten den echten
  Knoten draußen. Jetzt wird die **kanonische** Ankündigung (Instanzname = TXT `id`, so kündigt sich jeder Knoten an)
  immer aufgenommen – ist der Platz der ID (oder die ganze Liste) voll, macht die zuletzt gekommene Kopie Platz (bei
  voller Liste eine Kopie irgendeiner ID; nie eine andere kanonische Ankündigung) – und steht unter den Ankündigungen
  ihrer ID an erster Stelle, also auch mit ihren Adressen zuerst und vor jeder Grenze im Verzeichnis des Knotens.
  Einen gleichnamigen Fälscher (derselbe Instanzname) verhindert das nicht; er scheitert wie jede Lüge am Pin.
- **Erster Kontakt** (`--join-net` mit einem Link mit `node` + `tls`, §7): Solange der Knoten noch kein Log hat, holt
  er es zuerst vom Empfänger des Links im LAN (gepinnt), dann über `gw`. Der Pin wird mit der Mitgliedschaft im
  Daten-Ordner gespeichert. Der Vertrauensanker bleibt die Netz-ID (Eintrag 0).
- **Clients** (SDK): `Client::connect_auto(identität, NodeAddress { node, tls, url }, optionen)` und
  `Client::join(identität, link)`: Mit `tls` wird zuerst im LAN gesucht (mDNS, bis 2 s, endet sobald der Knoten
  gesehen wurde, plus 300 ms für weitere Ankündigungen derselben ID), jede gefundene Adresse (max. 8) mit genau diesem
  Pin probiert (je max. 5 s): Der Knoten muss seine Karte mit der erwarteten ID **und** genau diesem `tls` zeigen,
  dazu eine gültige `info`. Sonst die Internet-Adresse. Alles danach (Login, Log-Prüfung beim Beitritt, Umschläge)
  ist auf beiden Wegen gleich. `Client::via_lan()` sagt, welcher Weg es ist. `Client::new` + `connect` bleiben wie
  bisher (nur die angegebene Adresse).

## 3. Aussagen eines Netzes
Alle sind Aussagen nach 04 §3 mit `net` = Netz-ID. `exp` ist zugleich das Ablaufdatum des Inhalts.

| Art | `body` | Wer darf |
|---|---|---|
| `manifest` | siehe §4 | Version 1: nur der Hauptschlüssel. Danach: Hauptschlüssel **oder** `approvals.rules` Admins mit Recht `rules` (Mehr-Augen: ein Objekt mit `sigs`) |
| `delegation` | `{"admin":"<id>","rights":["members","seals","bans","rules"],"card":<karte des admins>}` | nur Hauptschlüssel; `exp` Standard 90 Tage |
| `invite` | `{"code_hash":"<SHA-256 des Codes>","uses":1–1000}` | Admin mit `members` |
| `member` | `{"member":"<id>","invite":"<code_hash>"?}` → Stufe 0 | Empfänger (Siegel mit Dienst `gateway`, Stufe ≥ 2) oder Admin mit `members`; eine bestehende Mitgliedschaft ersetzt nur ihr Aussteller, ein Admin mit `members` (bzw. der Hauptschlüssel) oder jeder, sobald sie abgelaufen ist – ein Nicht-Admin nie mit früherem `exp` |
| `seal` | `{"subject":"<id>","level":1–3,"services":[…],"card":<schlüsselkarte>?}` | Stufe 1–2: Admin mit `seals`. Stufe 3: `approvals.seal3` Admins mit `seals` (Mehr-Augen) oder Hauptschlüssel. Stufe 1 auch ein **Wächter** allein, nach den Regeln in §11 |
| `revoke` | `{"statement":"<hash>"}` oder `{"identity":"<id>","cascade":false}`, dazu `"reason"` (max. 200 Zeichen) | wer die Aussage ausstellen durfte (ein Wächter also seine eigenen Stufe-1-Siegel, §11), ein Admin mit dem passenden Recht, oder der Hauptschlüssel |
| `ban` | `{"subject":"<id>","reason":"…"}` | Admin mit `bans` (Dauer = `exp`; höchstens 1.000 je Admin und Tag) |
| `head` | `{"size":n,"root":"<32 Byte>"}` | Log-Führer (im Manifest) – **steht nicht im Log** |
| `cosign` | `{"head":"<hash des head>","log":"<id>","size":n,"root":"<32 Byte>"}` | Zeuge (im Manifest); für den Übergangs-Kopf einer Not-Wiederherstellung auch der Hauptschlüssel (§5) – **steht nicht im Log** |
| `home` | `{"node":"<id des Empfängers>"}` | das Mitglied selbst – **steht nicht im Log** (§8) |
| `app` | eine Version einer Bridge-App (07 §3) | App-Schlüssel **und** Owner (`sigs`) – **steht nicht im Log**, die Hosts behalten sie (Phase 4a) |
| `name` | Name → Ziel, Art, Inhaber, Karten, Beschreibung, Schlagworte, Kategorie (08 §3) | der Inhaber (bei Apps mit dem App-Schlüssel, `sigs`) nach den Namensregeln (Phase 4) |
| `label` | `{"target":"<name oder id>","category":"adult\|general","reason":"…"}` (08 §5) | Admin mit `seals` (Phase 4) |
| `retire` | `{"app":"<app-id>","owner":"<mitglied-id>","card":<karte des app-schlüssels>,"owner_card":<karte des owners>}` – eine App löschen (07 §10, ADR 0028) | App-Schlüssel **und** Owner (`sigs`; der Owner ist Mitglied, keiner gesperrt), Laufzeit ≥ 1 Jahr; nicht widerrufbar (nur Hauptschlüssel) |

- **Hash einer Aussage** = Base64url(SHA-256(kanonische Bytes der Aussage **ohne** `sig` bzw. `sigs`)). Er ist die
  Identität der Aussage für Widerruf (`revoke` mit `statement`), Ersetzen („neuer ersetzt älter“), Doppelte und
  `cosign`: Derselbe Inhalt mit anderen Unterzeichnern (oder anderer Reihenfolge) ist **dieselbe** Aussage – ein
  widerrufenes Mehr-Augen-Siegel kommt mit vertauschten oder anderen Signaturen nicht zurück. Bei einem einzelnen
  Aussteller gehört `iss` zum Inhalt. Nur die Blätter des Merkle-Baums (§5) hashen die ganzen Bytes des Eintrags.
- **Karten im Log**: Das Manifest trägt die Karte des Hauptschlüssels (`card`, Rolle `net`), jede Delegation die
  Karte des Admins (`card`, Rolle `admin`, Pflicht), ein Siegel optional die Karte des Inhabers (Pflicht bei
  `gateway`, mit `urls`). So kann jeder, der das Log hat, alle Signaturen prüfen.
- **Mehr-Augen** (`sigs`) nur bei `manifest` und `seal` (dazu `name` einer App und `retire`: App-Schlüssel + Inhaber); alle
  anderen Arten haben genau einen Aussteller. Jeder
  Unterzeichner muss selbst berechtigt sein. `sigs` ist streng aufsteigend nach `iss` sortiert (derselbe
  Unterzeichner zweimal ist damit ungültig), jeder Eintrag ist genau `{"iss","sig"}` – sonst ist die Aussage ungültig
  (04 §3: genau eine Byte-Form).
- **Strenge Bodies**: nur die genannten Felder (unbekannte Felder im `body` → ungültig).
- **Dienste** (`services`): `gateway` (Empfänger), `log` (Log-Führer), `witness` (Zeuge), `watch` (Wächter), `names`,
  `storage`, `compute`, `web`. Max. 8 pro Siegel.
- Bei Knoten mit Dienst `gateway` gehört die eigene Schlüsselkarte (mit `urls`) ins Siegel (`card`). So kennt jeder,
  der das Log hat, alle Empfänger samt Adressen.
- `revoke` mit `identity` entzieht alles, was diese Identität **bekommen** hat: Delegation, Mitgliedschaft, Siegel.
  Mit `cascade: true` (nur Hauptschlüssel) werden zusätzlich alle Aussagen ungültig, die diese Identität
  **ausgestellt** hat – für gestohlene Admin- oder Empfänger-Schlüssel.
  Genau (`bridge-net`, `state.rs`):
  - Ohne `cascade`: Hauptschlüssel – oder ein Admin mit `members` **und** `seals`, wenn X kein aktiver Admin ist.
    Alle Aussagen für X mit `iat ≤` Prüfzeit (§6) gelten nicht mehr (auch nicht neu ins Log gestellt); spätere
    Aussagen für X sind wieder möglich.
  - Mit `cascade`: zusätzlich ist X für immer gesperrt (kann nichts mehr unterschreiben oder bekommen), und alle
    Einladungen, Mitgliedschaften, Siegel und Sperren, die X (allein oder mit anderen) unterschrieben hat, entfallen
    (ein gestohlener Admin-Schlüssel kann so auch keine Sperr-Flut hinterlassen). Widerrufe von X bleiben (einzeln
    durch neue Aussagen ersetzen).
  - War X ein Start-Empfänger (§4), gilt X nie wieder als Start-Empfänger – auch nicht, wenn der Widerruf nach zwei
    Jahren vergessen ist oder ein späteres Manifest X wieder nennt (begrenzte Liste mit 1.024 Einträgen; ist sie
    voll, endet die Start-Empfänger-Ausnahme für alle – fail closed).
- `revoke` mit `statement`: Hauptschlüssel, ein Unterzeichner der Aussage, oder ein Admin mit dem passenden Recht
  (`members` für member/invite, `seals` für seal, `name` und `label`, `bans` für ban; Delegationen nur der
  Hauptschlüssel). Ziel muss
  gerade gelten; Manifeste und Widerrufe sind nicht widerrufbar (neue Version bzw. neue Aussage).

## 4. Manifest
```json
{"name":"Mein Netz","description":"…","version":1,"template":"open|invite|closed",
 "join":{"mode":"open|invite|closed","pow_bits":0},
 "approvals":{"rules":1,"seal3":1},
 "logs":["<id>"],"witnesses":["<id>"],"witness_threshold":1,
 "gateways":[{"id":"<id>","url":"https://…","card":<karte>?}],
 "limits":{"members":100000,"log_entries_per_day":10000},
 "card":<karte des hauptschlüssels>}
```
- Grenzen: `name` 1–64 Zeichen, `description` max. 500 (Zeilenumbruch erlaubt), `pow_bits` ≤ 28, `approvals`
  je 1–16, `limits.members` 1–1.000.000, `limits.log_entries_per_day` 1–100.000. Alle Felder sind Pflicht – außer
  dem optionalen `apps` (Phase 4a, 07 §3): `{"min_level":0-3}`, die Stufe, die ein Owner zum Veröffentlichen von Apps
  braucht (ohne das Feld: 0), und dem optionalen `watch` (Regeln der Wächter, §11.3; ohne das Feld: die
  Standardwerte dort) und – *Phase 4* – `short`, `contact`, `names`, `adult`, `blocklists` (08 §2). Fehlen sie,
  bleiben sie weg (ältere Manifeste behalten ihre Bytes und ihren Hash).
- Das neueste Manifest gilt bis zur nächsten Version; sein `exp` zählt nur beim Annehmen.
- `version` steigt bei jeder Änderung um genau 1. Das jeweils neueste gültige Manifest gilt.
- `logs`: 1–3 Log-Führer, `witnesses`: 1–16 Zeugen, `1 ≤ witness_threshold ≤ len(witnesses)`. Beide Listen dürfen die
  Netz-ID nicht enthalten (der Hauptschlüssel ist nie Log-Führer oder Zeuge – sonst zählte sein `cosign` für jeden
  Kopf, vgl. Not-Wiederherstellung in §5).
- **Vorbeugung gegen unerfüllbare Log-Regeln** (*nach Prüfung 4*; nur beim Log-Führer in `validate_candidate`, nicht
  beim Abspielen – §6 bleibt unverändert): Ein Manifest, das `logs`, `witnesses` oder `witness_threshold` ändert, nimmt
  der Log-Führer nur an, wenn (zur Prüfzeit und zur echten Zeit) der **erste** Log-Führer ein aktives Siegel mit Karte
  und Dienst `log` hat und **mindestens `witness_threshold`** der genannten Zeugen je ein aktives Siegel mit Karte und
  Dienst `witness` (alle nicht gesperrt). Ein Tippfehler in einer ID oder ein nie gesiegelter Knoten friert das Netz so
  nicht ein; dazu muss ein neuer Zeuge oder Log-Führer **vorher** mit diesem Dienst gesiegelt werden
  (`net seal --services gateway,witness`). Das Genesis-Manifest prüft das nicht; `net create` siegelt den Owner-Knoten
  gleich mit `gateway`, `log` und `witness` (Stufe 3), so erfüllt jedes spätere Manifest mit ihm die Regel.
- `gateways`: Start-Empfänger (1–8), damit der erste Beitritt ohne weiteres Wissen klappt. Sie brauchen trotzdem ein
  Siegel, um als Empfänger zu gelten (Ausnahme: bis das erste `gateway`-Siegel mit Stufe ≥ 2 im Log steht, gelten
  die `gateways` des aktuellen Manifests als Empfänger, damit das Netz starten kann – nur mit `card`, sonst kann
  niemand ihre Unterschrift prüfen; ein je als Identität widerrufener Start-Empfänger nie wieder, §3).
- **Vorlagen**: `open` (jeder darf beitreten, PoW nur unter Last), `invite` (nur mit Einladungscode), `closed`
  (nur ein Admin nimmt auf). Kleine Netze: Owner-Knoten = Log-Führer = Zeuge = Empfänger, `witness_threshold: 1`.

## 5. Transparenz-Log
- **Einträge**: kanonische Bytes von Aussagen der Arten `manifest`, `delegation`, `invite`, `member`, `seal`,
  `revoke`, `ban`, *seit Phase 4* `name` und `label` (08 §3, §5; je max. 64 KiB). **Eintrag 0 = Genesis-Manifest** (Version 1, signiert von der Netz-ID).
- **Merkle-Baum nach RFC 6962**: Blatt = SHA-256(0x00 ‖ Eintrag), Knoten = SHA-256(0x01 ‖ links ‖ rechts), leerer
  Baum = SHA-256(""). Nachweise: Inclusion (Eintrag i in Größe n) und Consistency (Größe m → n) wie RFC 6962 §2.1.
- **Kopf** (`head`): Größe + Wurzel, signiert vom Log-Führer, `iat` = Zeit, `exp` = `iat` + 30 Tage. Neuer Kopf,
  sobald neue Einträge da sind (spätestens alle 10 s), sonst alle 10 min.
- **Zeugen** holen jeden neuen Kopf, prüfen die Konsistenz zu ihrem eigenen Log und zu ihrem zuletzt bezeugten Kopf
  (gleich welcher Log-Führer ihn ausgestellt hat – Konsistenz betrifft das Log, nicht den Log-Führer), und dass jeder
  neue Eintrag `iat ≤ iat des Kopfes + 5 min` hat (keine vordatierten Einträge), und signieren ein `cosign`
  (`exp` = `exp` des Kopfes). Einen kleineren Kopf als ihren zuletzt bezeugten signieren sie nie. **Bezeugt** ist ein
  Kopf mit `witness_threshold` gültigen `cosign` verschiedener Zeugen der Log-Regeln, die für ihn gelten (nächster
  Punkt).
- **Log-Regeln beim Manifest-Wechsel** (`logs`, `witnesses`, `witness_threshold`, zusammen die *Log-Regeln*): Für einen
  Kopf der Größe n sei j der Index des letzten angenommenen Manifest-Eintrags mit j < n. Ist n = j + 1 (der Kopf endet
  genau mit diesem Manifest), werden Kopf und `cosign` gegen die Log-Regeln geprüft, die **vor** Eintrag j galten
  (für j = 0: das Genesis-Manifest selbst); sonst gegen die von Manifest j. Kurz: es gelten die Log-Regeln nach den
  ersten n − 1 Einträgen. Die alte Besetzung bezeugt also noch den Kopf, der den Wechsel enthält („Übergangs-Kopf“),
  jeder spätere Kopf braucht die neue. So kennen alle Beteiligten die Regel, bevor sie gilt, und niemand kann das
  Übergangs-Fenster nutzen: Die neuen Zeugen können den Übergangs-Kopf nicht ohne die alten bezeugen, die alten
  (entfernten) nichts danach.
  - **Log-Führer**: Nach dem Anhängen eines Manifests, das die Log-Regeln ändert, stellt er sofort den Kopf genau
    dieser Größe aus und nimmt **keine weiteren Einträge** an, bis dieser Kopf bezeugt ist (einzige Ausnahme: ein
    Manifest der Not-Wiederherstellung, unten). Köpfe stellt nur aus, wer
    für deren Größe aktiver Log-Führer ist (erster aus `logs` der geltenden Log-Regeln ohne Beweis gegen ihn);
    Einträge nimmt an, wer es für den nächsten Kopf ist. Ein neuer Log-Führer übernimmt also, sobald er das Log bis
    zum bezeugten Übergangs-Kopf geholt hat, und macht von dort weiter; der alte hört dann auf.
  - **Zeugen** entscheiden ihre Rolle für jeden Kopf nach derselben Regel. Liegt zwischen ihrem Log und einem neuen
    Kopf ein signiertes Manifest mit neuen Log-Regeln, signieren sie erst, wenn sie das Log bis dorthin geholt haben.
  - **Folgende Knoten** ebenso: Für Köpfe bis zur eigenen Log-Größe kennen sie die Regeln aus dem Abspielen
    (die letzten 64 Wechsel werden gemerkt; ältere Köpfe gelten nicht – fail closed). Für einen Kopf der Größe n
    weiter vorn (eigenes Log: s < n Einträge) gilt (*nach Prüfung 4*) – **bevor etwas geladen wird**:
    1. Vorprüfung unter den **aktuellen** Log-Regeln (`WitnessedHead::precheck`, *nach Prüfung 5*): von einem
       Log-Führer der Regeln, dessen Karte bekannt ist, signiert (Signatur und Zeit geprüft), und genug `cosign`
       **können** zählen: von verschiedenen Zeugen der Regeln – mit bekannter Karte muss es gültig sein, ist die Karte
       noch unbekannt (Zeuge erst in den neuen Einträgen gesiegelt), zählt es als „vielleicht“, wenn es wenigstens
       genau diesen Kopf nennt. Abgelehnt nur, wenn gültige + vielleicht < `witness_threshold`. Dann wird geladen; die
       volle Prüfung kommt nach dem Laden (Schritt 4). Vorher zählten nur Karten aus dem Zustand – ein ehrlicher Kopf
       mit einem später gesiegelten Zeugen wurde nie geladen (Prüfung 5, Befund 2).
    2. Sonst könnte er nur gelten, wenn vor seinem letzten Eintrag ein Manifest die Log-Regeln ändert. Kleiner erster
       Schritt: das aktuelle Manifest der Quelle (`GET …/manifest`: Aussage + Index i). Geladen wird nur, wenn es ein
       Manifest dieses Netzes mit **höherer Version** als das eigene ist, i ≥ s, das Abspielen es zu seiner Zeit noch
       nehmen könnte (`exp` nach seinem `iat` und nach der eigenen Log-Uhr, `iat` höchstens 5 min voraus), und gültig
       **und annehmbar** signiert: vom Hauptschlüssel (Mitunterzeichner mit Karte im Log) oder nur von Admins mit
       `rules`, die der Knoten kennt – bei der nächsten Version mindestens `approvals.rules` von ihnen (weiter voraus
       kann ein Manifest dazwischen die Zahl gesenkt haben, dann reicht einer). Kennt er einen Unterzeichner nicht als
       Admin mit `rules` (ein Fremder, ein gesiegelter Knoten, ein Admin mit anderen Rechten – sein Recht kann in den
       neuen Einträgen kommen; *nach Prüfung 5* nicht mehr „ungültig“), muss stattdessen der Kopf gültig von einem
       Log-Führer der aktuellen Regeln signiert sein. **Immer**, wenn die Karte des Unterzeichners des Kopfes bekannt
       ist (Zustand oder Karten im Manifest), werden Signatur und Zeit des Kopfes geprüft – ein gefälschter Kopf kommt
       nie weiter (*nach Prüfung 5*, Befund 3). Liegt das Manifest vor dem letzten Eintrag des Kopfes (i + 1 < n),
       gelten seine Log-Regeln für den Kopf: von einem seiner Log-Führer signiert, genug `cosign` können zählen (wie
       Schritt 1). Endet der Kopf genau mit der nächsten Version (i + 1 = n), ist er ihr Übergangs-Kopf: die aktuellen
       Regeln gelten (bei einem Manifest allein vom Hauptschlüssel auch die Not-Form). Sonst: nichts laden.
    3. Fehlende Einträge holen (höchstens 65.536 / 64 MiB) und prüfen, dass sie genau die Wurzel des Kopfes ergeben.
    4. Regeln für den Kopf bestimmen (`rules_ahead`, ohne die Sperre des Netz-Zustands): Es zählen nur Manifeste
       **vor** dem letzten Eintrag mit genau der nächsten möglichen Version (aktuelle + 1; jedes gültig geprüfte
       erweitert die Reihe um + 1) und mit Unterzeichnern, die beim Abspielen gelten können: der Hauptschlüssel samt
       Mitunterzeichnern mit Karte, oder lauter Admins mit `rules` (bekannt oder vom Hauptschlüssel in den neuen
       Einträgen delegiert), mindestens so viele wie das kleinste `approvals.rules` des aktuellen und der bisher
       gezählten Manifeste (eines davon gilt beim Abspielen), und nur, wenn das Abspielen sie zu ihrer Zeit noch nehmen
       könnte (*nach Prüfung 5*: ein Manifest, das nie gelten kann, erzwingt keine Kopie mehr). Karten kommen aus dem
       Zustand **und** aus den neuen Einträgen (selbst-beglaubigend) – so
       stimmt die Entscheidung mit dem Abspielen für jedes Manifest überein, das das Abspielen annimmt. Jede dieser
       Aussagen wird geprüft, zusammen höchstens 64 Signatur-Prüfungen (Manifeste und nötige Delegationen); mehr →
       der Kopf wird abgelehnt, nichts abgespielt. Ändert keines die Regeln, gelten die aktuellen. Sonst werden die
       Einträge auf einer **Kopie** des Zustands abgespielt und der Kopf gegen die so ermittelten Regeln geprüft. Die
       Kopie entsteht nie unter der Sperre: Der Zustand liegt als geteilter Schnappschuss vor, Kopieren und Abspielen
       laufen in einem Hintergrund-Thread. Ebenso, wenn der Kopf nur über die Not-Wiederherstellung gelten kann (er
       endet mit einem gültig allein vom Hauptschlüssel signierten Manifest und ist vom **ersten** Log-Führer der
       aktuellen Regeln signiert – nur dessen Kopf kann die Not-Form haben, *nach Prüfung 6*). Beim Abspielen merkt sich
       die Kopie jeden Wechsel der Log-Regeln (`NetState::apply_tracked`).
    5. **Jeder** dabei überquerte Wechsel muss durch seinen Übergangs-Kopf bestätigt sein (*nach Prüfung 5*, ADR 0013,
       nächster Punkt). Erst dann wird übernommen (Z9).
    Ein Rest bleibt: Steht ein Knoten wirklich hinter einem echten Manifest-Wechsel und erreicht er nur böse Quellen,
    können diese ihn laden und abspielen lassen – begrenzt (*nach Prüfung 6*, Befund 4): Ein abgelehnter Kopf (Größe +
    Wurzel) wird **4 Folge-Takte** lang von keiner Quelle mehr geladen (die nächste Quelle mit demselben Kopf kostet
    nur den kleinen Abruf von `/head`), die Quelle, die ihn zeigte, wird so lange übersprungen (ebenso eine Quelle,
    deren Einträge nicht zur Wurzel ihres Kopfes passen – deren Kopf bleibt erlaubt, eine andere Quelle kann die
    richtigen Einträge haben), und ein Übergangs-Kopf, den keine der gefragten Quellen hatte, wird so lange nicht
    erneut erfragt. Je Quelle also höchstens ein teurer Versuch (Laden, Abspielen, höchstens 4 `head/at` für den
    ersten nicht bestätigten Wechsel) je 4 Takte; gemerkt werden je Art höchstens 64 Einträge. Ehrliche Quellen
    (zuerst der Log-Führer) beenden das, sobald er aufgeholt hat. Jede Runde versucht höchstens 16 Quellen (je Knoten
    eine, mit bis zu 8 Adressen, LAN zuerst) und zusammen höchstens 32 Adressen.
  - **Übergänge beim Aufholen** (*nach Prüfung 5*, ADR 0013): Bis Prüfung 4 prüfte ein Knoten, der hinter einem
    Wechsel stand, nur den neuesten Kopf – gegen die Regeln, die die (abgespielten) neuen Einträge selbst festlegen.
    Wer allein die 24 Wörter hat (oder die `approvals.rules` Admins), konnte so einen erfundenen Anhang zeigen:
    eigener Log-Führer und Zeuge gesiegelt, Manifest auf sie umgestellt, Kopf von ihnen – ein nachhängender Knoten
    nahm ihn (Gabelung). Jetzt gilt für **jeden** Wechsel an Index j, den ein Knoten beim Aufholen überquert
    (j ≥ eigene Log-Größe):
    1. Der **Übergangs-Kopf** der Größe genau j + 1 muss unter den Regeln **vor** j bezeugt sein (ein Log-Führer der
       alten Regeln signiert, `witness_threshold` alte Zeugen) – bei einem Manifest allein vom Hauptschlüssel auch in
       der Not-Form (**erster** Log-Führer der alten Regeln + `cosign` des Hauptschlüssels, *nach Prüfung 6*). Die
       Einträge [0, j + 1), die der Knoten geladen hat, müssen genau seine Wurzel ergeben. Ohne Zeit-Prüfung (ein alter
       Kopf ist längst abgelaufen, seine Aussage bleibt wahr; Unterzeichner können jede Zeit wählen). Erst dann gelten
       die neuen Regeln weiter vorn.
    2. Endet der geholte Kopf selbst mit dem Wechsel (n = j + 1), ist er dessen Übergangs-Kopf (schon gegen die alten
       Regeln geprüft).
    3. Ausnahme Not-Wiederherstellung während eines hängenden Wechsels (unten): Den Übergangs-Kopf von j gibt es dann
       nie. Ist der Eintrag **direkt danach** (j + 1) ein Wechsel allein vom Hauptschlüssel und selbst bestätigt, zählt
       dessen Bestätigung auch für j – aber nur, wenn ihr Kopf vom **ersten** Log-Führer **der Regeln vor j** signiert
       ist (*nach Prüfung 6*; vorher genügte irgendein Log-Führer dieser Regeln). Der alte Log-Führer bürgt also für
       das Log mit j, der Hauptschlüssel für die Reparatur.
    **Was ein Fälscher braucht** (*nach Prüfung 6*, ADR 0014), um einen Knoten, der schon folgt, auf eine Gabelung zu
    führen – für den ersten Wechsel, an dem die Gabelung von den echten Regeln abweicht:
    - **Normal-Form**: den Schlüssel **irgendeines** Log-Führers der alten Regeln **und** die Schlüssel von
      `witness_threshold` alten Zeugen (die Mehrheit der alten Zeugen müsste also mitmachen oder gestohlen sein);
    - **Not-Form** (nur für ein Manifest allein vom Hauptschlüssel): die 24 Wörter **und** den Schlüssel des
      **ersten** Log-Führers der alten Regeln (`logs[0]`) – nicht eines zweiten oder dritten.
    Die 24 Wörter allein (oder die Admins mit `rules`) reichen nie, auch nicht in zwei Schritten: Prüfung 6 (Befund 1)
    zeigte, dass man mit den Wörtern im echten Log einen eigenen Knoten A als **zweiten** Log-Führer eintragen
    (`logs = [O, A]`, sieht nach der empfohlenen Vorsorge aus) und dann einem Folgenden einen Anhang zeigen konnte,
    dessen Not-Übergangs-Kopf A signiert. Wer A mit den Wörtern zum **ersten** Log-Führer macht, braucht dafür ein
    sichtbares Manifest im echten Log, bezeugt von der alten Zeugen-Mehrheit – und führt damit das echte Netz für
    alle sichtbar (keine heimliche Gabelung mehr, sondern eine Übernahme, die der Owner im Log sieht).
    **Entscheidung zur Normal-Form**: Dort genügt weiter **jeder** Log-Führer der alten Regeln. Die Zeugen bezeugen
    nur Köpfe, die zu ihrem eigenen Log und ihrem zuletzt bezeugten Kopf passen – gleich, wer sie signiert hat –,
    also ist die alte Zeugen-Mehrheit der Anker. Den ersten Log-Führer auch hier zu verlangen, nähme dem zweiten
    Log-Führer die Übernahme nach einem Beweis gegen den ersten (`operator_for_head`: erster ohne Beweis). In der
    Not-Form fehlen die Zeugen; dort bürgt nur der Log-Führer für das Log, also nur der, der die Köpfe ausstellt.
    Beweise gegen ihn zählen dabei nicht (sie liegen nicht bei jedem Knoten vor, die Entscheidung muss überall gleich
    sein): Ist der erste Log-Führer abgesetzt, gibt es keine Not-Form – siehe Grenze unten.
    **Holen** (*nach Prüfung 6*, Befunde 2 und 4): Die Köpfe holt der Knoten mit `POST …/head/at` `{"size":j+1}`
    (§9) bei bis zu **4 verschiedenen Knoten**: zuerst beim Knoten seiner Quelle (die Adresse, die geantwortet hat,
    dann dessen andere), dann bei den nächsten drei Quellen seiner Liste – je Knoten an der ersten Adresse, die
    überhaupt antwortet (LAN zuerst). Vorher waren es „die Quelle und drei weitere“ **Adressen**, oft viermal derselbe
    Knoten. Die Wechsel werden **vom neuesten zum ältesten** einzeln geprüft (`Transitions::endorsement`), jeder Kopf
    wird erst geholt, wenn er gebraucht wird, und beim ersten Wechsel, der sich nicht bestätigen lässt, hört der
    Knoten auf. Geprüfte Köpfe merkt er sich bis zum Erfolg (eine Runde, die an der Rate-Grenze endet, macht später
    dort weiter); einen Kopf, den keiner der 4 Knoten hatte, fragt er 4 Takte lang nicht erneut. Mehr als 64 Wechsel
    auf einmal → der Kopf wird nicht genommen (fail closed, wie die 64 gemerkten Regel-Wechsel).
    - **Jeder Knoten behält Übergangs-Köpfe für immer**: Sobald er einen bezeugten Kopf hat (selbst ausgestellt und
      bezeugt, geholt oder beim Aufholen geprüft), der genau mit einem Wechsel endet, speichert er ihn samt `cosign`
      (SQLite, Schema 4, Tabelle `net_transitions`; die letzten 64 Wechsel, ältere fallen weg) und gibt ihn über
      `head/at` heraus. *Nach Prüfung 6* (Befund 3):
      - Nach einem Neustart wird **jeder** gespeicherte Kopf so geprüft, wie ein Folgender ihn prüft: gegen die Regeln
        vor seinem Wechsel (Normal- oder Not-Form), mit den Karten von damals (beim Abspielen des gespeicherten Logs
        gemerkt) und der Wurzel des eigenen Logs. Was nicht passt (kaputte Zeile, unlesbare `cosign` – vorher wurden
        sie stillschweigend zu „keine“ –, andere Größe oder Wurzel), wird nicht herausgegeben. Zeilen für Größen, an
        denen kein Wechsel endet, werden gelöscht.
      - Fehlt danach der Kopf eines Wechsels im eigenen Log (Zeile kaputt oder nie gespeichert, z. B. Knoten direkt
        nach dem Merken beendet), holt der Knoten ihn bei bis zu 4 Quellen neu und prüft ihn ebenso – einen je Takt,
        mit sich verdoppelnden Pausen (bis 64 Takte), höchstens 8 Versuche je Kopf (einen Wechsel, der über eine
        Not-Wiederherstellung bestätigt wurde, hat nirgends einen eigenen Kopf), danach erst nach dem nächsten
        Neustart wieder. Ein so geprüfter Kopf **ersetzt** die kaputte Zeile (vorher blieb die erste Zeile je Größe
        für immer).
      - Eine Zeile, die sich nicht speichern ließ (Fehler der Datenbank), bleibt im Speicher (höchstens 64) und wird
        bei jedem weiteren Speichern und in jedem Folge-Takt erneut versucht (vorher nur eine Warnung).
    - **Erster Kontakt** (Knoten ohne Log): prüft ebenso die Übergangs-Köpfe aller Wechsel im geladenen Log (die
      letzten 64; Quelle, dann die anderen Start-Adressen). Sein Vertrauensanker bleibt die Netz-ID: Wer die Wörter
      hat, kann einem ganz neuen Knoten ein ganz anderes Log ab Eintrag 0 zeigen (§10).
  - **Not-Wiederherstellung** (*nach Prüfung 4*, ADR 0012): Ist das Manifest j **allein vom Hauptschlüssel** signiert
    und ändert es die Log-Regeln, zählt für seinen Übergangs-Kopf (Größe genau j + 1) statt `witness_threshold`
    Zeugen-Signaturen auch **ein gültiges `cosign` des Hauptschlüssels** (Aussteller = Netz-ID, für genau diesen Kopf,
    gültig zur Prüfzeit). Der Kopf selbst muss weiter vom **ersten** Log-Führer der Regeln vor j (`logs[0]`) signiert
    sein (*nach Prüfung 6*; vorher genügte irgendein Log-Führer dieser Regeln – siehe „Was ein Fälscher braucht“).
    Für jeden anderen Kopf zählt ein `cosign` des Hauptschlüssels nie (die Netz-ID ist nie Zeuge, §4). So kommt ein
    Netz wieder in Gang, dessen Log-Regeln nicht mehr erfüllbar sind (Zeugen-Schlüssel verloren, Mehrheit weg) – ohne
    den Ausweg würde schon der Übergangs-Kopf des reparierenden Manifests gegen die kaputten Regeln geprüft.
    - Der Log-Führer nimmt ein solches Manifest auch an, während er auf die Bezeugung eines früheren Übergangs-Kopfes
      wartet (sonst bliebe ein Netz hängen, dessen letzter Wechsel nie bezeugt werden kann) – nur wenn es die
      geltenden Log-Regeln ändert. Er stellt den Übergangs-Kopf sofort aus und nimmt `POST …/cosign` des
      Hauptschlüssels nur für genau diesen Kopf an (sonst `FORBIDDEN`).
    - Zeugen und folgende Knoten prüfen jeden Kopf gleich (`NetState::check_witnessed`: Regeln nach Größe, bei einem
      Not-Übergangs-Kopf zusätzlich das `cosign` des Hauptschlüssels). Ein Knoten, der über einen hängenden Wechsel
      und die Not-Wiederherstellung hinweg aufholt, nimmt den hängenden Wechsel über den Not-Übergangs-Kopf an (siehe
      „Übergänge beim Aufholen“, Punkt 3).
    - Grenze: Ersetzt werden nur die Zeugen. Ist der **erste** Log-Führer für immer weg oder abgesetzt (Beweis gegen
      ihn), hilft die Not-Wiederherstellung nicht (*nach Prüfung 6*: ein zweiter Log-Führer zählt für die Not-Form
      nicht). Ein zweiter Log-Führer im Manifest hilft nur, solange die alte Zeugen-Mehrheit da ist: Nach einem Beweis
      gegen den ersten stellt er die Köpfe aus und kann den ersten per Manifest entfernen lassen (§10).
    - Befehl `bridge-node net rescue` (§10). Er prüft vor dem `cosign` selbst: ganzes Log vom Owner-Knoten geholt und
      abgespielt, der zuletzt bezeugte Kopf passt zu diesem Log, das eigene Manifest steht genau an Stelle j, der Kopf
      hat Größe j + 1, die Wurzel dieses Logs und die Signatur des **ersten** Log-Führers der Regeln vor j.
- **Regel (Z9)**: Knoten und Clients wenden Aussagen erst an, wenn sie in einem bezeugten Kopf enthalten sind.
- **Annahme**: Der Log-Führer nimmt nur Aussagen an, die nach dem Zustand aller vorherigen Einträge gültig sind
  – mit Rechten zur Prüfzeit (§6) **und** zur echten Zeit, `iat` höchstens 5 min voraus –, höchstens
  `limits.log_entries_per_day` pro Tag. Prüfer verlassen sich nicht darauf (§6: ungültige Einträge werden
  übersprungen). Wer einem Log folgt, übernimmt jeden Eintrag bis 64 KiB (auch Müll), damit sein Baum zu den Köpfen
  passt; Müll zählt beim Abspielen nicht.
- **Rollen im Knoten** (`bridge-node`, Modul `network`) kommen nur aus dem abgespielten Zustand: **aktiver
  Log-Führer** ist der erste aus `logs`, gegen den lokal kein Beweis vorliegt; **Zeuge**, wer in `witnesses` steht;
  **Empfänger** nach `gateways()` (§6). Alle übrigen Knoten **folgen**: neuesten bezeugten Kopf holen
  (`/head`, zuerst beim Log-Führer, dann bei Empfängern und Start-Adressen), fehlende Einträge holen, prüfen, dass
  sie genau die Wurzel des Kopfes ergeben, **erst speichern, dann anhängen und abspielen**. Ein Neustart macht mit
  dem gespeicherten Log weiter. Pro Runde höchstens 65.536 Einträge / 64 MiB; eine Seite muss mindestens 16
  Einträge enthalten (sonst bricht die Runde ab).
- Zeugen holen den neuesten (auch unbezeugten) Kopf beim Log-Führer über `GET /v4/net/{netz}/head/latest` und geben
  ihr `cosign` per `POST /v4/net/{netz}/cosign` ab. Der Log-Führer hält bis zu 4 Köpfe offen; ein `cosign` für einen
  davon zählt (sonst könnte ein Strom neuer Einträge jedes Bezeugen verhindern).
- Takt (Standard; Tests ~100–300 ms): Folgen 2 s, Gossip 5 s, Kopf-Prüfung 1 s (neuer Kopf bei neuen Einträgen,
  sonst alle 10 min), Zeugen 2 s, `home`-Austausch 5 s, Weiterleitung erneut nach 30 s.

### Split-View und Absetzen
- **Beweis** (`evidence`) = zwei Köpfe desselben Log-Führers, die nicht zusammenpassen:
  - (a) gleiche Größe, andere Wurzel – für sich allein prüfbar;
  - (b) Größe m < n, aber die Wurzel der ersten m Einträge des Logs mit Kopf n ist nicht die Wurzel von Kopf m.
    Prüfbar für jeden, der die Einträge zu Kopf n hat (alle Knoten im Netz halten das ganze Log).
- Wer einen Beweis hat, setzt den Log-Führer **sofort lokal ab**: Er nimmt keine Köpfe mehr von ihm an, bezeugt
  keine mehr, meldet den Beweis über `/v4/net/{netz}/evidence` weiter (Gossip) und alarmiert (Log + Owner-Dashboard).
  Ein zweiter Log-Führer im Manifest übernimmt; das endgültige Entfernen ist eine Manifest-Änderung.
- Ein Log-Führer, der einen Beweis gegen **sich selbst** bekommt (sein Schlüssel ist offenbar in fremder Hand), hört
  auf zu führen: keine `submit`, keine Köpfe mehr (fail closed). Beweise zählen nur gegen Log-Führer des aktuellen
  Manifests – sonst könnte jeder mit eigenem Schlüssel die (begrenzte) Beweis-Tabelle füllen. Beweise werden
  gespeichert (max. 16 je Netz) und gelten nach einem Neustart weiter.
- **Gossip**: Knoten fragen reihum `/v4/net/{netz}/head` bei allen bekannten Empfängern (alle 5 s, je Gegenüber
  höchstens 1×/s, je Runde höchstens 8) und vergleichen mit den eigenen Köpfen (selbst ausgestellte, bezeugte,
  selbst bezeugte). Dabei holen sie auch `/v4/net/{netz}/evidence` der Gegenüber (geprüft, nie blind). Clients
  schicken ihren zuletzt gesehenen Kopf beim Abholen mit (später).

## 6. Netz-Zustand (deterministisch)
Der Zustand entsteht nur durch **Abspielen des Logs der Reihe nach**. Jeder Knoten rechnet selbst und kommt zum
selben Ergebnis.
1. Eintrag 0 muss ein Manifest Version 1 sein, signiert von der Netz-ID – sonst ist das ganze Log ungültig.
2. Jeder weitere Eintrag wird geprüft: kanonische Form, Signatur(en), `net`, Rechte des Ausstellers **zum
   Zeitpunkt seines Eintrags** (Delegation gültig, nicht widerrufen, nicht gesperrt). Zeitpunkt = **Prüfzeit
   t = max(`iat`, Log-Uhr)**; die Log-Uhr ist das größte t aller bisher angenommenen Einträge. So hängt der Zustand
   nur von den Einträgen ab (nicht davon, welche Köpfe ein Knoten gesehen hat), und Rückdatieren hinter frühere
   Einträge hilft nicht. Die Regel „`iat` ≤ Zeit des nächsten Kopfes + 5 min“ prüfen Log-Führer und Zeugen (§5).
   Außerdem: `exp` > t, Aussage nicht widerrufen oder ersetzt (Identität = Hash ohne Signaturen, §3). Eine neuere
   Aussage (größeres `iat`) zum selben Gegenstand ersetzt die ältere (Delegation je Admin, Mitgliedschaft je
   Mitglied, Siegel je Inhaber und Stufe); ersetzte und widerrufene Aussagen gelten nie wieder, auch nicht erneut
   eingetragen. Eine Mitgliedschaft ersetzt nur ihr Aussteller, ein Admin mit `members` oder der Hauptschlüssel – oder
   jeder, wenn sie zur Prüfzeit abgelaufen ist; ein Nicht-Admin darf `exp` dabei nie verkürzen (kein Empfänger kann
   Mitglieder anderer Empfänger hinauswerfen). Sperren und Widerrufe wirken ab ihrer Position (fail closed).
   Ungültige Einträge zählen nicht (werden übersprungen), stoppen aber nichts. Ein Siegel ist ungültig, wenn die Karte
   darin mehr als 5 min nach dem Siegel selbst ausgestellt ist (`iat` der Karte > `iat` des Siegels + 5 min; *nach
   Prüfung 6*).
3. Abfragen zur Zeit T: `iat` − 5 min ≤ T < `exp`, nicht widerrufen, nicht gesperrt.
   - `level(id)`: höchstes gültiges Siegel. Sonst 0, wenn Mitglied. Sonst keine Stufe (kein Mitglied).
   - `is_member(id)`, `services(id)`, `admins()`, `gateways()` (mit Karten), `current_manifest()`.
   - Karten aus dem Log (`card_of`, auch für `gateways()`): Netz-ID → Manifest; Admin → Delegation; sonst die
     **neueste Karte** unter den Siegeln des Inhabers (größtes `min(iat der Karte, iat des Siegels)`, dann `iat` des
     Siegels, dann Hash; bei `gateways()` nur aktive Siegel; *nach Prüfung 6*); sonst die Karte im Manifest
     (Start-Empfänger). Karten sind selbst-beglaubigend –
     für Signaturen ist jede Karte einer ID gleich gut, für Adressen und den TLS-Pin zählt die neueste (§2).
   - `check_witnessed(kopf)`: ein Kopf bis zur eigenen Log-Größe + 1, geprüft gegen die Log-Regeln für seine Größe
     (§5), beim Übergangs-Kopf einer Not-Wiederherstellung auch mit dem `cosign` des Hauptschlüssels (dann nur, wenn
     der erste Log-Führer dieser Regeln ihn signiert hat).
   - `is_transition_head(n)`: endet ein Kopf der Größe n genau mit einem Wechsel der Log-Regeln (nicht Eintrag 0,
     innerhalb der gemerkten 64)? `apply_tracked`: wie `apply`, merkt sich dabei jeden Wechsel samt Regeln davor und
     den Karten ihrer Log-Führer und Zeugen (für „Übergänge beim Aufholen“, §5).
4. Grenzen: Mitglieder nach `limits.members` (höchstens 1.000.000), je 10.000 Admins, Siegel, Sperren (davon max.
   8 je Identität) und Einladungen. Einträge nach `limits.log_entries_per_day` (Tag nach Prüfzeit); Einträge des
   Hauptschlüssels zählen nicht, `revoke`/`ban` haben 10 % Reserve (Admins können nach einer Flut noch handeln).
   *Nach Prüfung 8*: Die 10.000 Siegel sind die von Admins und Hauptschlüssel; Siegel von Wächtern haben eine eigene
   Tabelle (höchstens `limits.members`) und Einträge von Wächtern einen eigenen Topf von `log_entries_per_day` (§11.2)
   – ein Wächter kann Admins nie aussperren.
   Sperren: höchstens 1.000 je Admin und Tag (nach Prüfzeit); der Hauptschlüssel ist davon und von der Grenze je
   Identität ausgenommen und hat 1.000 eigene Plätze über den 10.000 – Admins können ihn nie aussperren.
   Abgelaufenes wird vergessen, sobald die Log-Uhr 5 min darüber ist.

## 7. Beitritt
- **Einladungslink**:
  `bridge4://join?net=<netz-id>&gw=<url-kodierte Empfänger-URL>&code=<code>&node=<empfänger-id>&tls=<pin>`
  - `code` nur bei `invite`.
  - `node` (optional): ID des Empfängers. Der Client pinnt sie von Anfang an (auch über das Internet) – ein Knoten mit
    anderer ID wird abgelehnt. Nicht die Netz-ID.
  - `tls` (optional, **nur zusammen mit `node`**): Base64url(SHA-256) des TLS-Zertifikats des Empfängers (genau 32
    Byte, kanonisch, §2). Dann sucht der Client den Empfänger zuerst im LAN (nach `node`) und verbindet sich nur mit
    diesem Zertifikat – im selben WLAN geht der Beitritt so auch ohne Internet; `gw` bleibt der Ersatzweg.
  - Streng: jeder Schlüssel höchstens einmal, max. 8 Parameter, max. 1.024 Zeichen, unbekannte Schlüssel werden
    übergangen.
  - `net create` zeigt einen Link mit `node` (ohne `tls`, der Knoten läuft da noch nicht); `net invite` holt die
    geprüfte Karte des Owner-Knotens (`/v4/info`, ID wie in `admin-key.json`) und setzt `node` und – wenn die Karte
    `tls` hat, der Knoten also mit `--lan` läuft – `tls`.
  - Als QR-Code in BridgeControll v2 (ADR 0017; SVG aus dem Programm).
- **Knoten-Ausweis** (BridgeControll v2, ADR 0017): `bridge4://node?card=<Base64url der kanonischen Knoten-Karte>`,
  höchstens 4.096 Zeichen. Damit gibt ein Knoten-PC dem Owner seine selbst-signierte Karte (Rolle `node`, mindestens
  eine Adresse) zum Siegeln – auch wenn der Owner ihn nicht über `http` erreicht (nur LAN). Der Owner bestätigt dazu
  mindestens die ersten 12 Zeichen der Knoten-ID, abgelesen am Knoten-PC (wie `--node-id` bei `net seal`). Streng:
  genau dieses Präfix und ein Wert; eine Karte mit falscher Signatur, anderer Rolle oder ohne Adresse wird abgelehnt.
- Ablauf (Client):
  1. Empfänger anfragen: `/v4/info` (Karte, `net` muss passen; mit `node`: ID muss passen; über das LAN: `tls` der
     Karte muss der benutzte Pin sein).
  2. Log holen und prüfen: `POST /v4/net/{netz}/log` `{"from":0}`. Eintrag 0 bis zur Netz-ID prüfen. Das Rust-SDK
     (ohne `bridge-net`) prüft außerdem, dass der Empfänger im Genesis-Manifest steht oder ein `gateway`-Siegel
     (Stufe ≥ 2) des Hauptschlüssels bzw. eines vom Hauptschlüssel delegierten Admins hat (erste 4.096 Einträge;
     Widerrufe und Ablauf prüfen die Knoten, die das ganze Log abspielen).
  3. Challenge holen mit Body `{"for":"join"}` (dann trägt das Rätsel mindestens `join.pow_bits` des Manifests),
     dann `POST /v4/net/join`: `rq` mit `op:"join"`, `body:{"challenge","card","code"?,"pow"?}`.
- Der Empfänger prüft billig zuerst: er ist selbst Empfänger → `rq` (für ihn, frisch) → Challenge einmalig → PoW
  (Rätsel mit weniger Bits als `join.pow_bits` → `POW_REQUIRED`) → Karte (Rolle `client` oder `node`, `id = iss`) →
  Signatur → Regeln (gesperrt → `BANNED`; `closed` → `FORBIDDEN`; `invite`: Code fehlt, falsch oder verbraucht →
  `FORBIDDEN`). Dann stellt er `member` aus (`exp` = 1 Jahr), gibt es dem Log-Führer (`submit`), wartet höchstens
  20 s, bis die Mitgliedschaft in einem bezeugten Kopf bei ihm angekommen ist, und antwortet `{"member":<aussage>}`
  (schon Mitglied: `{"member":null,"already":true}`). Danach normales Login.
- **Login im Netz** (04 §7) verlangt ab Phase 3: der Knoten ist Empfänger, der Aufrufer Mitglied (oder Siegel) und
  nicht gesperrt (`NOT_MEMBER`/`BANNED`, 403). Das gilt bei **jeder** Nutzung einer Sitzung erneut – ein Widerruf
  oder eine Sperre beendet laufende Sitzungen, sobald der Eintrag angekommen ist. Knoten ohne Netz (Einzelknoten)
  bleiben wie in Phase 2.

## 8. Heim-Empfänger und Weiterleitung
- Jedes Mitglied hat einen **Heim-Empfänger** (dort liegt sein Postfach). Es meldet ihn mit `home`
  (`{"node":"<id>"}`, `exp` max. 30 Tage), signiert von sich selbst, bei jedem Login an seinen Empfänger: Feld
  `home` im `body` der Login-Anfrage (04 §7). Der Empfänger prüft es (Signatur, Netz, `node` = er selbst) und speichert
  es samt Karte.
- Empfänger tauschen `home`-Einträge untereinander aus: `POST /v4/node/homes` mit `rq` (`op:"homes"`,
  `body:{"since":n}`, nur von Empfängern) → `{"homes":[{"card":<karte>,"home":<aussage>,"seq":n},…],"next":n}` –
  nur Einträge von Mitgliedern, die bei **diesem** Empfänger wohnen, max. 256 je Antwort, `seq` steigt mit jeder
  Änderung. **Die Karte des Mitglieds reist mit**, so findet `/v4/card` auch Mitglieder anderer Empfänger. Angenommen
  wird nur, was selbst-signiert ist, von einem Mitglied stammt und einen Empfänger nennt; kennt der eigene Zustand das
  Mitglied noch nicht (Log eine Runde hinterher), wird ein Eintrag bis 2 min nach `iat` erneut geholt. Der neueste
  gültige Eintrag eines Mitglieds gilt. Max. 1 Eintrag pro Mitglied, höchstens `limits.members`.
- Wohin ein Umschlag geht, entscheidet **nur** der `home`-Eintrag des Empfängers (ohne Eintrag oder mit einem
  Heim-Empfänger, der keiner mehr ist: `UNKNOWN_IDENTITY`).
- **Senden an ein Mitglied eines anderen Empfängers**: Der eigene Empfänger prüft den Umschlag wie in Phase 2, legt
  ihn in seinen Ausgang (gespeichert, Replay-Schutz und Kontingente wie Postfächer: 10.000 Umschläge / 256 MiB, je
  Ziel 5.000) und reicht ihn per `POST /v4/node/relay` weiter. Weil eine signierte Anfrage höchstens 64 KiB hat, ein
  Umschlag aber 256 KiB haben darf, bindet die Anfrage den Umschlag über seinen Hash:
  `{"envelope":<umschlag>,"rq":<rq>}` mit `rq` des Knotens, `op:"relay"`,
  `body:{"envelope":"<Base64url SHA-256 der kanonischen Bytes des Umschlags>","card":<karte des absenders>}`.
- Der Ziel-Empfänger prüft:
  1. Der Aufrufer ist ein gültiger Empfänger dieses Netzes (Siegel `gateway`, Stufe ≥ 2).
  2. `rq` ist für ihn bestimmt und frisch, und `(iss, n)` wurde noch nie benutzt (`REPLAY`).
  3. Umschlag: Form, Zeit, Signatur mit der Karte des Absenders – die Karte kommt mit
     (`body.card`, selbst-beglaubigend). Absender ist Mitglied und nicht gesperrt.
  4. Der Empfänger des Umschlags wohnt bei ihm.
  5. Kontingente und Replay wie Phase 2.
- Kein Weiterleiten über mehr als einen Zwischenschritt (kein Schleifen-Risiko).
- Fällt der Ziel-Empfänger aus, bleibt der Umschlag beim Absender-Empfänger und wird alle 30 s erneut versucht, bis
  `ttl` abläuft. Lehnt das Ziel ab, wird nur bei endgültigen Gründen (`BAD_FORMAT`, `TOO_LARGE`, `BAD_SIGNATURE`,
  `EXPIRED`, `NOT_YET_VALID`, `BANNED`) sofort verworfen; andere Ablehnungen (z. B. `NOT_MEMBER`, weil das Log des
  Ziels eine Runde hinterher ist) werden bis zu 50-mal wiederholt. `REPLAY` heißt: ist schon da.

## 9. Endpunkte (Phase 3, zusätzlich zu 04 §7)
Lese-Endpunkte mit Parametern sind `POST` mit kleinem JSON-Body (max. 1 KiB), weil der Transport dem Knoten keine
Query-Strings übergibt (siehe §10). `proof`, `consistency`, `evidence` (lesen und melden) und `head/at` haben
zusätzlich eine engere Grenze je Adresse (Standard 5/s, kurz bis 10); Nachweise gibt es nur für Größen bis zur eigenen
Log-Größe,
Beweise werden nur gegen Köpfe geprüft, die der Knoten billig nachrechnen kann (Merkle-Baum mit gespeicherten
Teilbäumen: Wurzeln und Nachweise in O(log n), gerechnet ohne die Sperre des Netz-Zustands).

| Endpunkt | Wer | Antwort |
|---|---|---|
| `GET /v4/net/{netz}/head` | alle | `{"head":<aussage>,"cosigns":[…]}` (neuester bezeugter Kopf, zu dem der Knoten das Log hat; nie von abgesetzten Log-Führern) |
| `GET /v4/net/{netz}/head/latest` | Zeugen | neuester Kopf des Log-Führers, auch unbezeugt (nur beim aktiven Log-Führer) |
| `POST /v4/net/{netz}/head/at` `{"size":n}` | alle | `{"head":<aussage>,"cosigns":[…]}` – der Übergangs-Kopf dieser Größe, den der Knoten behält (§5 „Übergänge beim Aufholen“), sonst `NOT_FOUND` |
| `GET /v4/net/{netz}/manifest` | alle | `{"manifest":<aussage des aktuellen manifests>,"index":i}` |
| `POST /v4/net/{netz}/log` `{"from":i,"max":n}` | alle | `{"entries":["<Base64url>",…],"size":n}` (genaue Bytes, max. 256 Einträge bzw. 1 MiB) |
| `POST /v4/net/{netz}/proof` `{"index":i,"size":n}` | alle | `{"index","size","proof":["<hash>",…]}` (Inclusion) |
| `POST /v4/net/{netz}/consistency` `{"from":m,"to":n}` | alle | `{"from","to","proof":[…]}` (Consistency) |
| `POST /v4/net/{netz}/submit` | Hauptschlüssel, Admins, Empfänger, Wächter (§11) | `rq` mit `op:"submit"`, `body:{"statement":…}` → `{"index","size","hash"}` (beim aktiven Log-Führer; ein Empfänger, der es nicht ist, reicht Aussagen des Hauptschlüssels und der Admins einmal an ihn weiter – Empfänger-Anfragen nie, also keine Schleifen) |
| `POST /v4/net/{netz}/cosign` | Zeugen | die `cosign`-Aussage selbst → `{"ok":true,"witnessed":bool}` (beim Log-Führer) |
| `GET /v4/net/{netz}/evidence` / `POST …` | alle | `{"evidence":[{"a":<kopf>,"b":<kopf>},…]}` / einen Beweis melden → `{"ok":true,"new":bool}` (geprüft, nie blind übernommen) |
| `POST /v4/net/join` | Clients | Beitritt (§7) |
| `POST /v4/node/relay` | Empfänger | Weiterleitung (§8) → `{"ok":true}` |
| `POST /v4/node/homes` | Empfänger | `home`-Einträge austauschen (§8) |
| `POST /v4/node/app` | Hosts einer App | eine App-Version anbieten (Phase 4a, 07 §5/§7) |
| `POST /v4/node/watch` | Knoten (Mitglieder) | beim Wächter zu Proben anmelden (§11.5) → `{"ok":true,"since":<ms>\|null}` |

Fehler wie 04 §9 (z. B. falsches `aud` → 401 `BAD_SIGNATURE`, Weiterleitung von einem Nicht-Empfänger → 403
`FORBIDDEN`, Empfänger wohnt nicht hier → 404 `UNKNOWN_IDENTITY`, wiederholte Anfrage → 409 `REPLAY`). Ein Knoten
ohne Netz kennt keinen dieser Endpunkte (404); ein Knoten, der sein Log noch lädt, antwortet `UNAVAILABLE`.

## 10. Grenzen und offene Punkte von Phase 3
- **LAN** (mDNS + TLS-Pinning über die Karte) ist gebaut (§2 „LAN im Knoten und im SDK“, §7). Offen:
  - Knoten nehmen den Pin anderer Knoten nur aus dem Log. Wer LAN nach seinem Siegel einschaltet, muss neu gesiegelt
    werden (§2); ein automatisches Neu-Siegeln oder frischere Karten über `/v4/info` gibt es noch nicht.
  - Kein Wechsel des Zertifikats im laufenden Betrieb (Rotation): neues Zertifikat = Datei löschen, neu siegeln, neue
    Links.
  - Ein Client, der schon über das Internet verbunden ist, wechselt nicht von selbst ins LAN (erst beim nächsten
    `connect_auto`).
  - Die mDNS-Suche liest nur `id`, `v` und den Port; `net` ist ein Hinweis für spätere Werkzeuge.
  - `net seal --node-url` holt die Karte eines Knotens noch nicht gepinnt über das LAN (nur `http(s)://`; die
    erwartete ID schützt trotzdem).
- **BridgeControll v2** ist gebaut (ADR 0017, `apps/bridgecontroll`): Assistent „Neues BridgeNet“, Beitritt per Link,
  Siegeln mit ID-Bestätigung (Knoten dieses PCs oder Knoten-Ausweis, §7), Siegel entziehen, Sperren, Einladungen mit
  QR-Code, Owner-Dashboard. Daneben (und für alles, was die 24 Wörter braucht) gibt es die Kommandozeile:
  - `bridge-node net create --data <ordner> --name <text> --url <öffentliche adresse> --contact <meldeweg>
    [--short <kurzname>] [--template open|invite|closed] [--adult allowed|forbidden]` (*Phase 4*: `--contact`,
    `--short`, `--adult`, 08 §2) zeigt die 24 Wörter **einmal** an, legt die Knoten-Identität (falls nötig), den delegierten Admin-Schlüssel
    `admin-key.json` (alle Rechte, 90 Tage, nur für den Besitzer lesbar), Genesis-Manifest (1 Jahr), Delegation und
    das Siegel des Owner-Knotens (Stufe 3: `gateway`, `log`, `witness`, 1 Jahr) an. Der nächste Start
    `bridge-node --data <ordner>` ist der Owner-Knoten.
  - `bridge-node net invite --data <ordner> [--uses N] [--days D]` → Link
    `bridge4://join?net=…&gw=…&code=…&node=…` (+ `&tls=…`, wenn der Owner-Knoten mit `--lan` läuft, §7).
  - `bridge-node net seal --data <ordner> --node-url <adresse> --node-id <id> [--level 2] [--services gateway]`
    holt und prüft die Karte des Knotens über `/v4/info` (selbst-signiert, `info` des Netzes) und gibt das Siegel
    nur ab, wenn die Karte genau die erwartete ID hat (`--node-id`; der Knoten zeigt sie beim Start an). Fehlt
    `--node-id` oder passt die ID nicht, bricht der Befehl ab und nennt die gefundene ID – sonst könnte jeder, der
    die Adresse (über `http://`) umleitet, sich selbst siegeln lassen. Bei Erfolg zeigt er die ID des Inhabers.
    Ohne `--level`/`--services` gelten beim Neu-Siegeln Stufe und Dienste des höchsten aktiven Siegels des Knotens
    (dafür holt der Befehl das Log vom Owner-Knoten und spielt es ab), sonst Stufe 2 und `gateway` (§2). Wer Zeuge
    oder Log-Führer werden soll, braucht ein Siegel mit `witness` bzw. `log` (§4), z. B. `--services gateway,witness`.
  - `bridge-node net revoke … (--statement <hash> | --identity <id>)`, `bridge-node net ban … --identity <id>`.
  - `bridge-node net rescue --data <ordner> (--witnesses <id,…> [--threshold n] [--logs <id,…>] | --file <json>)
    [--node <adresse>]` – die **Not-Wiederherstellung** (§5, ADR 0012). Fragt die 24 Wörter ab (eine Zeile, höchstens
    1 KiB; sie werden nie angezeigt, gespeichert oder geloggt). *Nach Prüfung 5*: nie über den globalen Puffer der
    Standard-Eingabe von Rust (der behielte sie bis zum Ende des Programms): Ist die Eingabe unter Unix ein Terminal,
    wird direkt vom Terminal gelesen (`/dev/tty`), sonst – und unter Windows **immer** (*nach Prüfung 6*, Befund 7) –
    von einer eigenen Kopie des Eingabe-Handles; Byte für Byte in einen Puffer, der nie wächst und beim Freigeben
    gelöscht wird. Vorher las Windows im Terminal von der Konsole `CONIN$`: In Git Bash/MSYS (mintty) ist die Eingabe
    eine Pipe, die Rust als Terminal meldet, während `CONIN$` zu einer unsichtbaren Konsole gehört – der Befehl hing. Unter Unix ist
    die Anzeige beim Tippen aus (das Zeilenende erscheint), und die alten Terminal-Einstellungen kommen auf **jedem**
    Weg zurück: Zeile gelesen, Fehler, oder Signal (Ctrl+C, `Ctrl+\`, Ctrl+Z, `SIGTERM`, `SIGHUP` – Eingabe
    abgebrochen, Ende mit Code 130; danach beendet jedes dieser Signale den Befehl ebenso, Ctrl+Z hält ihn also nicht
    an). Umgesetzt mit `rustix` (sichere termios-Schnittstelle, ohne eigenes `unsafe`). **Grenze Windows**: Die
    Konsole (bzw. mintty) zeigt die Wörter beim Tippen (die Anzeige abzuschalten geht nur über die Konsolen-API, also
    mit `unsafe` – verboten); niemand darf zusehen. Die Aufforderung erscheint, wenn die Eingabe ein Terminal ist. Prüft, dass sie zur Netz-ID in
    `admin-key.json` gehören, holt das ganze Log vom Owner-Knoten, spielt es ab und prüft den zuletzt bezeugten Kopf
    dagegen. Baut das nächste Manifest aus dem aktuellen mit den neuen `logs`/`witnesses`/`witness_threshold`
    (`--file`: JSON-Objekt mit genau diesen Feldern, alle optional, max. 16 KiB; ohne `--threshold` bleibt die
    Schwelle, höchstens die Zahl der Zeugen), prüft es wie der Log-Führer (§4 Vorbeugung) und bricht ab, wenn es die
    Log-Regeln nicht ändert. Dann: allein mit dem Hauptschlüssel signieren (1 Jahr), abgeben (`submit`, Anfrage
    vom Hauptschlüssel signiert), auf den Übergangs-Kopf warten (`head/latest` beim Log-Führer, max. 60 s), ihn
    prüfen (§5) und das `cosign` des Hauptschlüssels beim Log-Führer abgeben. Zeigt, wie viele noch nicht bezeugte
    Einträge damit bestätigt wurden.
  - Ein zweiter Knoten: `bridge-node --data <ordner> --join-net <link> --url <öffentliche adresse> [--lan <port>]` –
    er lädt das Log (mit `node` + `tls` im Link zuerst über das LAN) und folgt ihm; Empfänger wird er mit seinem
    Siegel. Die Mitgliedschaft im Netz wird im Daten-Ordner gespeichert. Soll er im LAN für andere Knoten erreichbar
    sein, läuft er schon beim Siegeln mit `--lan` (§2). *Nach Prüfung 8*: `--join-net-file <datei>` liest den Link aus
    einer Datei (höchstens 4 KiB) – so steht kein Einladungscode in der Prozessliste, die jeder Benutzer des PCs lesen
    kann (BridgeControll macht es so); `--peer-addresses public|tailnet|any` siehe §2 „Adress-Schutz“.
  - Die `net`-Befehle reden mit dem laufenden Owner-Knoten (Adresse aus `admin-key.json` oder `--node`), alles mit
    dem Admin-Schlüssel signiert (`net rescue`: mit dem Hauptschlüssel). Admin-Verlängerung und `cascade` brauchen
    die 24 Wörter (noch kein Befehl).
- **Grenzen nach Prüfung 4**:
  - Die Not-Wiederherstellung ersetzt nur die Zeugen, nicht einen für immer verlorenen (einzigen) Log-Führer. Ändert
    das hängende Manifest den Log-Führer, kann der alte das reparierende Manifest nicht mehr annehmen.
  - Ein Knoten, der hinter einem Wechsel der Log-Führer steht, den nur später delegierte Admins unterschrieben haben,
    lädt ihn nicht (Schritt 2 in §5 kann das Manifest nicht prüfen und der Kopf stammt nicht von einem aktuellen
    Log-Führer) – bis ein späteres Manifest vom Hauptschlüssel oder von bekannten Admins kommt.
  - Mehr als 64 Signatur-Prüfungen für Manifeste in einer Runde (über 64 Manifest-Wechsel auf einmal) → der Kopf wird
    nicht genommen (fail closed, wie die 64 gemerkten Regel-Wechsel).
  - Der erste Kontakt (Knoten ohne Log) lädt das Log von seiner Start-Adresse ohne Vorprüfung (der Vertrauensanker
    entsteht erst mit Eintrag 0); er läuft außerhalb jeder Sperre, eine böse Start-Adresse kostet nur Bandbreite.
- **Grenzen nach Prüfung 5**:
  - Erster Kontakt: Der Vertrauensanker ist nur die Netz-ID. Wer die 24 Wörter hat, kann einem ganz neuen Knoten ein
    ganz anderes Log ab Eintrag 0 zeigen (die Übergangs-Köpfe schützen nur Knoten, die schon folgen). Abhilfe später:
    beim Beitritt zusätzlich die ID des Empfängers (`node` im Link) oder einen bezeugten Kopf als Anker prüfen.
  - Der erste Kontakt prüft nur die Übergangs-Köpfe der letzten 64 Wechsel; ältere Wechsel (und ihre Köpfe) behält
    niemand. Ein Folgender, der mehr als 64 Wechsel auf einmal überquert, nimmt den Kopf nicht (fail closed).
  - Übergangs-Köpfe gibt es erst ab dieser Version: ein Log, das vorher Wechsel hatte, hat für sie keine gespeicherten
    Köpfe (Phase 3 ist noch nicht im Einsatz – betrifft nur Test-Netze).
  - Fehlt ein Übergangs-Kopf bei allen erreichten Quellen (z. B. alle Knoten, die ihn hatten, sind weg), kommt ein
    nachhängender Knoten nicht über diesen Wechsel – bis eine Quelle ihn hat.
  - LAN: Ohne Netz-Zustand (Log wird noch geladen) gibt es keinen Filter – eine Flut erfundener IDs kann die Suche
    dann füllen; das LAN ist nur eine Abkürzung, `urls` bleiben der Weg.
- **Grenzen nach Prüfung 6**:
  - Not-Wiederherstellung nur mit dem **ersten** Log-Führer der alten Regeln (§5, ADR 0014). Ist er für immer weg oder
    abgesetzt **und** die alte Zeugen-Mehrheit ebenfalls, kommt das Netz nicht mehr in Gang (dann neu erstellen). Ein
    zweiter Log-Führer hilft nur zusammen mit der alten Zeugen-Mehrheit.
  - Ein Fälscher kann hinter seinem ersten (unbestätigbaren) Wechsel weitere Wechsel unter seinen eigenen Regeln
    anhängen, deren Übergangs-Köpfe er selbst liefert: Je teurem Versuch prüft ein Folgender dann bis zu 63 solcher
    Köpfe (je ein kleiner Abruf bei der Quelle selbst), bevor er beim gefälschten Wechsel aufhört – begrenzt, und je
    Quelle höchstens ein solcher Versuch je 4 Takte (§5).
  - Die Merk-Tabellen gegen wiederholte Arbeit (abgelehnte Köpfe, fehlende Übergangs-Köpfe, Quellen in der Pause)
    gelten nur im Speicher und je 4 Takte; ein Knoten ohne erreichbare ehrliche Quelle wiederholt seine Versuche also
    in diesem Abstand. Ein Übergangs-Kopf, den eine böse Quelle als „fehlend“ erscheinen ließ (alle gefragten Knoten
    böse oder tot), wird auch bei einer ehrlichen Quelle erst nach 4 Takten erneut erfragt.
  - Ein Übergangs-Kopf, der nach einem Neustart fehlt, wird nur 8-mal neu geholt (dann erst nach dem nächsten
    Neustart). Ob eine Zeile in die Datenbank kam, prüft niemand außer dem Knoten selbst; Zeilen, die beim Beenden
    noch nicht gespeichert waren, holt er nach dem Neustart bei anderen Knoten.
  - Gegen einen Fälscher mit **demselben** mDNS-Instanznamen wie der echte Knoten hilft die Regel aus §2 nicht (die
    letzte Ankündigung gilt); er scheitert am Pin, kann aber die LAN-Adressen des echten Knotens verdrängen – dann
    gehen die Anfragen über dessen `urls`.
- Wächter-Proben und automatische Stufe 1 sind gebaut (§11, ADR 0016); Bürgen kommen später.
- **Query-Strings**: Der Transport gibt dem Knoten nur den Pfad. Sobald `bridge-transport` die Query mitliefert,
  können `log`, `proof`, `consistency` zusätzlich als `GET …?from=…` angeboten werden (gleiche Antworten).
- **Folgen über große Lücken**: Wer mehr als 65.536 Einträge hinterher ist, kommt so nicht nach (dafür bräuchte es
  Zwischenköpfe oder Consistency-Nachweise je Abschnitt). Alle Knoten halten das ganze Log im Speicher.
- **Mehrere Log-Führer**: Übernahme durch den nächsten aus `logs` ist angelegt (aktiver Log-Führer = erster ohne
  Beweis; seine Köpfe zählen mit der Zeugen-Mehrheit, nie in der Not-Form, §5). Getestet sind der Wechsel von Zeugen
  und von Log-Führer per Manifest (§5), nicht die Übernahme nach einem Beweis.
- **Nach einem Log-Führer-Wechsel** reden die `net`-Befehle weiter mit dem Owner-Knoten; ist er Empfänger, reicht er
  die Aussagen an den neuen Log-Führer weiter. Gibt es 30 Tage lang keinen neuen Eintrag, läuft der letzte bezeugte
  Kopf ab (der neue Log-Führer stellt erst mit dem ersten neuen Eintrag einen eigenen aus).
- **Umzug eines Mitglieds** zu einem anderen Empfänger: Post, die beim alten noch liegt, bleibt dort bis zum Ablauf.

## 11. Wächter (`watch`): automatische Stufe 1
Stufe 1 „Geprüft“ (02 §6) vergibt kein Mensch, sondern ein **Wächter**: ein Knoten, der Mitglieder nach Zeit und
Verhalten und Knoten nach bestandenen Proben beurteilt und dafür Siegel der Stufe 1 ins Log stellt. Was er darf, prüft
der Netz-Zustand (§6, deterministisch, `bridge-net`); was er beobachtet (Proben), steht nicht im Log – dafür bleibt
sein Schaden begrenzt (nur Stufe 1, feste Dienste, Budget, kurze Lebensdauer, widerrufbar). Entscheidungen: ADR 0016.

### 11.1 Wer Wächter ist
- Ein Wächter ist eine Identität mit einem **aktiven Siegel der Stufe ≥ 2 mit Dienst `watch` und Karte** (§6 Abfrage
  zur Prüfzeit; nicht gesperrt, nicht per `cascade` widerrufen). Allein aus dem Log, wie alle Rollen (§5).
- So ein Siegel vergibt nur, wer Stufe 2 bzw. 3 vergeben darf (§3), z. B.
  `bridge-node net seal … --level 2 --services gateway,watch` (ein Wächter muss kein Empfänger sein; über die `urls`
  seiner Karte erreichen ihn die Knoten, die sich anmelden).
- Ohne Wächter im Netz gibt es Stufe 1 nur von Admins (wie bisher).

### 11.2 Was ein Wächter unterschreiben darf (Zustand, §6)
Ein `seal`, das nicht nach §3 von Admins/Hauptschlüssel getragen ist, gilt nur, wenn **alle** Punkte zutreffen
(sonst wird es übersprungen bzw. beim Log-Führer abgelehnt, Fehler `FORBIDDEN`, beim Budget `QUOTA_EXCEEDED`):
1. **Genau ein Unterzeichner**, und der ist zur Prüfzeit Wächter (11.1). Mehr-Augen-Siegel gibt es nur von Admins.
2. **`level` = 1.** Stufe 2 und 3 nie.
3. **Inhaber** ≠ der Wächter selbst, und zur Prüfzeit **Mitglied** (aktive Mitgliedschaft, nicht gesperrt): Stufe 1
   baut auf Stufe 0 auf – der Beitritt nach dem Modus des Netzes (`open`/`invite`/`closed`) bleibt das Tor, auch für
   Knoten. Die üblichen Regeln für Inhaber (§6: nicht die Netz-ID, nicht kaskadiert, nicht per Identitäts-Widerruf
   für ältere Aussagen gesperrt) gelten weiter.
4. **Art des Siegels** – genau eine von zwei:
   - **Mitglied** (ohne `card`): `services` leer. Die geltende Mitgliedschaft wurde spätestens `iat des Siegels −
     member_age` (11.3) **angenommen** – gezählt ab ihrer Prüfzeit beim Abspielen (Log-Uhr), nicht ab ihrem `iat`
     (*nach Prüfung 8*: ein Empfänger, der eine Mitgliedschaft zurückdatiert, macht sie nicht älter) –, und das Ende
     der letzten Sperre des Inhabers, die der Zustand kennt, liegt mindestens
     `member_age` vor dem `iat` des Siegels („keine Verstöße“ = keine Sperre in dieser Zeit; eine vorzeitig widerrufene
     Sperre zählt bis zu ihrem `exp`). Der Zustand merkt sich dafür je Identität das späteste Sperr-Ende, bis
     365 Tage danach, höchstens 100.000 Identitäten; ist die Liste voll, gilt bis zum spätesten so vergessenen Ende
     + 365 Tage **kein** Mitglieds-Siegel eines Wächters (fail closed).
   - **Knoten** (`card` mit Rolle `node` und mindestens einer Adresse in `urls`): `services` ⊆ **{`web`}**. Kein
     Mindestalter der Mitgliedschaft – die Beobachtungszeit der Proben (11.6) ersetzt es; die Proben selbst kann der
     Zustand nicht prüfen. Eine Karte einer anderen Rolle ist ungültig.
   Erlaubte Dienste sind eine feste Liste im Code, das Manifest kann sie nicht erweitern: nur `web`, weil Websites
   und Apps vom Client geprüft werden (Hash-Listen, zwei Signaturen, 07) – ein schlechter Host kann nur ausfallen, das
   messen die Proben. `storage`, `compute` und `names` kommen erst mit ihren eigenen Proben (Speicher-Proben,
   Nachrechnen, Namens-Prüfung) dazu; `gateway`, `log`, `witness` und `watch` sind Infrastruktur und bleiben bei
   Admins (Stufe ≥ 2).
5. **Lebensdauer** `exp − iat ≤ seal_s` (11.3).
6. **Nur ein Stufe-1-Siegel je Inhaber zählt** (es gibt je Inhaber und Stufe ohnehin nur eines, §6). Ein Wächter
   ersetzt ein bestehendes nur, wenn es **von ihm selbst** ist (Verlängerung, neueres `iat`) oder sein Aussteller zur
   Prüfzeit **kein Wächter mehr** ist (verwaistes Siegel, z. B. Wächter abgesetzt). Ein Stufe-1-Siegel von Admins,
   vom Hauptschlüssel oder von einem anderen aktiven Wächter ersetzt er nie. Admins ersetzen Wächter-Siegel wie bisher
   (neueres `iat`). Damit ist bei zwei Wächtern, die gleichzeitig siegeln, das erste im Log das gültige, das zweite
   wird abgelehnt.
7. **Budget**: je Wächter höchstens `seals_per_day` Siegel je Tag (Tag nach Prüfzeit, wie Sperren je Admin); auch
   Verlängerungen zählen. Widerrufe zählen **nicht** (Abstieg muss immer gehen; ein Wächter kann ohnehin nur seine
   eigenen, also höchstens so viele widerrufen, wie er ausgestellt hat).
8. *Nach Prüfung 8* – **Eigene Tabelle, eigener Topf** (vorher füllten Wächter die gemeinsame Tabelle von 10.000
   Siegeln, danach konnte kein Admin mehr siegeln):
   - Siegel, die ein Wächter allein unterschrieben hat, stehen in einer **eigenen Tabelle** mit höchstens
     `limits.members` Plätzen (je Mitglied ein Stufe-1-Siegel, dazu Platz für Mitglieder, die gegangen sind und deren
     Siegel noch läuft). Ist sie voll, wird ein neues Wächter-Siegel abgelehnt (`QUOTA_EXCEEDED`); eine Verlängerung
     passt immer. Die 10.000 Plätze für Siegel von Admins und Hauptschlüssel berührt das nie; ersetzt ein Admin ein
     Wächter-Siegel, wandert es in deren Tabelle (und braucht dort Platz).
   - Einträge von Wächtern – ihre Siegel und die Widerrufe ihrer eigenen Siegel durch einen Unterzeichner ohne
     Admin-Rechte – zählen in einem **eigenen Topf** von `limits.log_entries_per_day` je Tag (gleich groß, Widerrufe
     mit 10 % Reserve), nicht im Topf von Admins und Empfängern.

**Widerruf**: Seine eigenen Siegel widerruft ein Wächter mit `revoke` + `statement` (§3: Unterzeichner der Aussage –
das geht, solange er irgendein aktives Siegel mit Karte hat); fremde nie, `revoke` mit `identity` nie. Admins mit
`seals` und der Hauptschlüssel widerrufen Wächter-Siegel wie jedes Siegel.

**Ende eines Wächters (keine Kaskade)**: Läuft das `watch`-Siegel ab, wird es ersetzt oder widerrufen, bleiben die
Stufe-1-Siegel, die der Wächter ausgestellt hat, bis zu ihrem `exp` gültig (höchstens `seal_s`, Standard 30 Tage) –
wie die Aussagen eines Admins, dessen Delegation endet. Andere Wächter dürfen sie ersetzen (Punkt 6), Admins einzeln
widerrufen. Für einen gestohlenen Wächter-Schlüssel gibt es den Widerruf mit `cascade` (Hauptschlüssel, §3): er
entfernt alles, was der Wächter ausgestellt hat. Begründung: Ein vergessenes Verlängern des Wächter-Siegels ließe sonst
alle Stufe-1-Siegel des Netzes auf einmal fallen (Zuverlässigkeit); der Schaden eines bösen Wächters ist durch
Stufe 1, die Dienst-Liste, das Budget und die Lebensdauer begrenzt.

### 11.3 Regeln im Manifest (`watch`, optional)
```json
"watch":{"member_age_s":604800,"probe_interval_s":300,"node_observe_s":86400,"success_pct":90,
         "fail_limit":3,"seal_s":2592000,"renew_s":604800,"seals_per_day":1000}
```
| Feld | Bedeutung | Grenzen | Standard |
|---|---|---|---|
| `member_age_s` | Mindestalter der Mitgliedschaft (und Abstand zur letzten Sperre) für Mitglieds-Siegel | 1 – 31.536.000 (365 Tage) | 604.800 (7 Tage) |
| `probe_interval_s` | Abstand der Proben je Knoten | 1 – 86.400 | 300 (5 min) |
| `node_observe_s` | Beobachtungszeit: so lange muss ein Knoten bestanden haben, und so lang ist das Fenster für den Anteil | 1 – 2.592.000 (30 Tage) | 86.400 (24 h) |
| `success_pct` | Mindestanteil bestandener Proben im Fenster | 50 – 100 | 90 |
| `fail_limit` | Fehlschläge in Folge bis zum Abstieg | 1 – 100 | 3 |
| `seal_s` | höchste Lebensdauer eines Wächter-Siegels | 60 – 7.776.000 (90 Tage) | 2.592.000 (30 Tage) |
| `renew_s` | verlängert wird, wenn weniger als das übrig ist | 1 ≤ `renew_s` < `seal_s` | 604.800 (7 Tage) |
| `seals_per_day` | Budget je Wächter und Tag | 1 – 10.000, höchstens ¼ von `log_entries_per_day` | 1.000 |

- Streng wie alle Bodies: genau diese acht Felder, alle Pflicht, ganze Zahlen in den Grenzen; sonst ist das Manifest
  ungültig. Ohne das Feld gelten die Standardwerte (ein Siegel mit `watch` ist die bewusste Entscheidung des Owners).
- *Nach Prüfung 8*: `seals_per_day` ist höchstens ein Viertel von `limits.log_entries_per_day` (mindestens 1; beim
  Standard 10.000 also 2.500) – mindestens vier Wächter passen mit vollem Budget in ihren Topf (11.2 Punkt 8), keiner
  verbraucht ihn allein. Sonst ist das Manifest ungültig.
- Ändern wie jede Manifest-Änderung (`rules`, §3). Der Zustand prüft daraus nur `member_age_s`, `seal_s` und
  `seals_per_day` (11.2); die übrigen Felder steuern den Wächter (11.4–11.6) und sind so für alle sichtbar.
- Tests setzen kurze Zeiten über genau dieses Feld (z. B. `member_age_s: 2`, `probe_interval_s: 1`).

### 11.4 Proben (`bridge-node`, nur der Wächter)
- Je angemeldetem Knoten (11.5) frühestens alle `probe_interval_s` eine Probe; der Wächter-Takt läuft alle 10 s
  (Tests 200 ms) und startet je Takt höchstens 16 Proben gleichzeitig.
- Weg: wie jede Knoten-Anfrage (§2) – LAN mit dem Pin `tls` der **angemeldeten** Karte zuerst (wenn der Knoten im LAN
  gesehen wurde), dann ihre `urls`; die erste Adresse, die überhaupt antwortet, zählt. *Nach Prüfung 8*: Die `urls`
  der Anmeldung hat der Knoten selbst gewählt – sie gehen nur an öffentliche IP-Adressen, je Aufruf aufgelöst und
  festgelegt (§2 „Adress-Schutz“; mit `tailnet` auch Tailscale, mit `any` alle). Eine Adresse, die auf den Rechner des
  Wächters oder ins private Netz zeigt, ist eine fehlgeschlagene Probe, ohne dass eine Verbindung aufgebaut wird. Je
  Takt höchstens 16 Proben, je Probe höchstens 4 Adressen (+ 4 im LAN), alles in den 5 s der Probe.
- Eine Probe **besteht**, wenn alles stimmt:
  1. `GET /v4/info`: Karte mit genau der ID des Knotens, Rolle `node`; die Aussage `info` ist von dieser Karte
     signiert, Art `info`, Netz = dieses Netz, ihr `iat` höchstens 5 min von der Uhr des Wächters entfernt (falsche
     Uhren fallen auf, 02 §7 Nr. 14).
  2. `GET /v4/net/{netz}/head`: ein Kopf, dessen Größe n höchstens 64 neben der eigenen Log-Größe s liegt. Für
     n ≤ s + 1 voll geprüft wie beim Folgen (`check_witnessed`), für n ≤ s muss zusätzlich die Wurzel genau die des
     eigenen Logs bei Größe n sein (**konsistent**) und n ≥ (eigene bezeugte Größe − 64) gelten (**nicht weit
     hinten**). Für n > s + 1 (der Wächter hängt selbst hinterher) genügt die gültige Signatur eines Log-Führers der
     aktuellen Regeln.
  3. Beide Antworten zusammen in **höchstens 5 s**.
- Jede Probe wird gespeichert (11.7). `seit` = Zeit der ersten bestandenen Probe nach der Anmeldung bzw. nach der
  letzten Serie von `fail_limit` Fehlschlägen; einzelne Fehlschläge darunter setzen `seit` nicht zurück.

### 11.5 Anmeldung von Knoten
- **Endpunkt** `POST /v4/node/watch` (beim Wächter): `rq` mit `op:"watch"`,
  `body:{"card":<karte des knotens>,"services":[…]}`. Prüfung billig zuerst: dieser Knoten ist Wächter (sonst 403
  `FORBIDDEN`) → `rq` für ihn und frisch → Body genau diese zwei Felder, Karte Rolle `node` mit `id = iss`, 1–4
  `urls`, `iat` der Karte höchstens 5 min voraus; `services` ⊆ {`web`} → Signatur → Nonce einmalig (`REPLAY`) → Rate
  je Identität → Aufrufer ist Mitglied und nicht gesperrt (`NOT_MEMBER`, `BANNED`).
- **Tabelle** (gespeichert): höchstens 1.024 Knoten. Eine erneute Anmeldung verlängert die bestehende und übernimmt
  Dienste und Karte (eine Karte mit älterem `iat` als die gespeicherte wird nicht übernommen). Eine Anmeldung gilt
  24 Anmelde-Takte (Standard 24 × 10 min = 4 h); danach räumt der Wächter sie samt Proben weg.
- *Nach Prüfung 8* – **Volle Tabelle**: Vorher hielten 1.024 Anmeldungen, die nie eine Probe bestehen, jeden neuen
  Knoten draußen. Jetzt nimmt ein neuer Knoten den Platz der Anmeldung, die **nicht besteht** – zuerst ohne `seit`
  (geprüfte vor noch nie geprüften), dann mit Fehlschlägen in Folge –, und darunter der **ältesten** (Zeit der ersten
  Anmeldung, Schema 8); sie geht samt Proben. Knoten, die bestehen, verdrängt niemand; sind alle so, gibt es 429
  `QUOTA_EXCEEDED`.
- *Nach Prüfung 8* – **Grenzen je Absender**: neue Anmeldungen höchstens 16 je Adresse (IPv4, IPv6 je /64) und Stunde
  (gemerkt höchstens 4.096 Adressen; ist das voll und keine Stunde abgelaufen, wird abgelehnt), sonst 429; je Identität
  gilt die Rate für signierte Anfragen. **Keine** Stufe und kein Rätsel für die Anmeldung: Das Tor ist die
  Mitgliedschaft (Beitritt nach Modus des Netzes, in offenen Netzen mit `join.pow_bits`; jede Mitgliedschaft kostet einen
  Log-Eintrag aus `log_entries_per_day`). Wer massenhaft Mitglieder anlegt, um die Tabelle zu leeren, verdrängt nur
  Anmeldungen, die nicht bestehen, und braucht dafür mehr Mitgliedschaften, als das Log je Tag annimmt.
- *Nach Prüfung 8* – **Neue Adressen = neue Beobachtung**: Ändern sich mit einer (neueren) Karte die `urls` oder der
  Pin `tls`, beginnt `seit` neu (Speicher und Datenbank) – die Beobachtungszeit der alten Adressen gilt nicht für die
  neuen.
- **Knoten-Seite**: `bridge-node … --probe web` (bzw. `--probe -` für Stufe 1 ohne Dienste). Alle 10 min (Tests
  500 ms): Ist der Knoten noch kein Mitglied, tritt er bei einem Empfänger aus dem Log bei wie ein Client (§7: Challenge,
  ggf. Rätsel, `POST /v4/net/join` mit seiner Knoten-Karte; ein Einladungscode aus dem Link von `--join-net` wird
  mitgeschickt, er bleibt nur im Speicher). Sonst meldet er sich bei bis zu 8 Wächtern aus dem Log an.

### 11.6 Was der Wächter entscheidet (je Takt)
- **Knoten** (angemeldet): bereit, wenn `jetzt − seit ≥ node_observe_s`, unter den gespeicherten Proben der letzten
  `node_observe_s` mindestens `success_pct` % bestanden sind, die letzte Probe bestanden hat und 11.2 erfüllt ist →
  Siegel Stufe 1 mit der angemeldeten Karte, Dienste = die angefragten (⊆ {`web`}), `exp = iat + seal_s`.
- **Mitglieder**: je Takt höchstens 256 Mitglieder, reihum nach ID; bei diesem Wächter angemeldete Knoten werden dabei
  übersprungen (sie bekommen ein Knoten-Siegel). Bereit, wenn 11.2 (Mitglieds-Siegel) erfüllt ist → Siegel Stufe 1
  ohne Dienste und ohne Karte.
- **Keine Doppelten**: übersprungen wird jeder Inhaber mit einer aktiven Stufe ≥ 2 oder mit einem aktiven
  Stufe-1-Siegel, das nicht von diesem Wächter ist und nicht verwaist (11.2 Punkt 6).
- **Verlängern**: ein eigenes Siegel mit weniger als `renew_s` Rest, wenn der Inhaber weiter bereit ist (Knoten: der
  Anteil im Fenster stimmt und weniger als `fail_limit` Fehlschläge in Folge; Mitglied: 11.2). *Nach Prüfung 8*: Das
  gilt nur für eine **reine Verlängerung** mit derselben Karte (gleiche `urls` und `tls`). Haben sich `urls` oder `tls`
  der angemeldeten Karte gegenüber der im Siegel geändert, wird neu gesiegelt erst, wenn der Knoten mit der neuen Karte
  **bereit** ist (volle Beobachtungszeit seit dem Neubeginn von `seit`, 11.5, Anteil, letzte Probe bestanden) – vorher
  reichte eine einzige bestandene Probe.
- **Abstieg**: `fail_limit` Fehlschläge in Folge → der Wächter widerruft sein Siegel (`revoke` + `statement`, Grund
  „Proben fehlgeschlagen“) und `seit` beginnt neu. Ist der Inhaber eines eigenen Siegels gesperrt oder kein Mitglied
  mehr, widerruft er es ebenso (sonst gälte es nach dem Ende einer Sperre wieder).
- *Nach Prüfung 8* – **Anmeldung abgelaufen**: Ein Knoten konnte seinen Proben ausweichen, indem er sich nicht mehr
  anmeldete – dann wurde er nicht mehr geprüft und behielt sein Siegel bis `exp` (bis 90 Tage). Jetzt widerruft der
  Wächter ein eigenes **Knoten**-Siegel (mit Karte), sobald die Anmeldung des Inhabers abgelaufen (oder verdrängt) ist,
  Grund „Anmeldung abgelaufen“. Entschieden gegen „mit der Karte aus dem Siegel weiter proben“: ein Siegel ohne
  Anmeldung hätte keine Verlängerung und keine Grenze in der Tabelle, und „kein Siegel ohne Anmeldung“ ist einfach zu
  prüfen. Damit ein Neustart des Wächters nach langer Pause nicht alle Siegel auf einmal widerruft, gilt das erst,
  wenn der Wächter seit 2 Anmelde-Takten wieder läuft (die Knoten melden sich bis dahin neu an). Mitglieds-Siegel
  (ohne Karte) betrifft das nicht.
- **Grenzen**: je Takt höchstens 16 Aussagen und nie mehr Siegel als das Budget des Tages noch zulässt (aus dem
  Zustand). Eingereicht wird über `submit` beim aktiven Log-Führer wie bei Admins (Anfrage vom Wächter-Knoten
  signiert); `submit` nimmt dafür auch Wächter an. Eine Ablehnung (z. B. ein anderer Wächter war schneller) wird nur
  protokolliert.

### 11.7 Speichern und Status
- **SQLite, Schema 7** (nur angehängt): `watch_nodes` (je Netz und Knoten: Karte, Dienste, gültig bis, `seit`,
  Fehlschläge in Folge, letzte Probe; *Schema 8, nach Prüfung 8*: Zeit der ersten Anmeldung für die Verdrängung,
  ältere Zeilen 0) und `watch_probes` (Zeit, bestanden, Dauer in ms). Je Knoten höchstens 1.024
  Proben (die neuesten; älter als das Fenster `node_observe_s` werden gelöscht). Ein Neustart verliert nichts: Fenster
  und `seit` laufen weiter.
- `bridge-node net watch-status --data <ordner>` zeigt (aus Datenbank und Log des Ordners, auch während der Knoten
  läuft): ob der Knoten Wächter ist, die Regeln, das heutige Budget, seine Stufe-1-Siegel und die angemeldeten Knoten
  mit Proben, Anteil und Fehlschlägen.

### 11.8 Grenzen und offene Punkte
- Proben stehen nicht im Log: Wer einem Wächter (Stufe ≥ 2 von einem Admin) misstraut, widerruft sein `watch`-Siegel;
  seine Stufe-1-Siegel laufen dann aus (11.2) oder werden einzeln widerrufen. Eine Kaskade nur für Wächter-Siegel durch
  Admins gibt es nicht (nur `cascade` mit dem Hauptschlüssel).
- Ein verwaistes Siegel (Wächter weg) kann nur ein anderer Wächter ersetzen, ein Admin widerrufen oder sein Ablauf
  beenden – ein anderer Wächter kann es nicht widerrufen.
- „Verstöße“ sind bisher nur Sperren. Bürgen (02 §6) fehlen noch.
- Mehrere Wächter teilen die Arbeit nicht auf: jeder probt alle Knoten, die sich bei ihm anmelden.
- In `invite`-Netzen braucht ein Knoten einen Code im Link, in `closed`-Netzen ein Admin, der ihn aufnimmt (dafür gibt
  es noch keinen Befehl).
- Nur `web` als Dienst; `storage`/`compute`/`names` erst mit ihren Proben (Phase 4/5).
- Der Wächter ist (wie der Empfänger) ein Teil von `bridge-node` (Modul `network::watcher`), noch kein Plugin unter
  `services/` (03 §1) – das Plugin-Gerüst fehlt noch; die Regeln liegen ohnehin im Netz-Zustand (`bridge-net`).
- *Nach Prüfung 8*: Das Alter einer Mitgliedschaft zählt ab der Log-Uhr beim Annehmen. In einem Log, in dem lange
  nichts eingetragen wurde, steht die Log-Uhr auf dem letzten Eintrag – um diese Zeit kann ein Empfänger eine
  Mitgliedschaft noch zurückdatieren (nicht weiter). Eine Prüfung „frisch“ beim Log-Führer gibt es dafür noch nicht.
- *Nach Prüfung 8*: Mit `--peer-addresses public` bekommen Knoten, die nur über private oder Tailnet-Adressen
  erreichbar sind, keine Stufe 1 vom Wächter (Proben schlagen fehl) und keine Apps von Knoten, die ihnen nur über eine
  Wächter-Karte folgen – über Tailscale `tailnet` (BridgeControll-Standard), in reinen LAN-Netzen `any` (§2).
