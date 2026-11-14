# 05 – Fahrplan

Kein Zeitdruck. Jede Phase endet erst, wenn ihre **Abnahme** erfüllt ist (Tests grün, Doku aktuell, Paddy hat
freigegeben).

## Phase 1 – Spezifikation (erledigt)
- Grundsätze, Begriffe, Sicherheitsmodell, Architektur, Protokoll v4, Fahrplan (diese Dateien).
- Repo-Gerüst auf Branch `bridge-4`: Ordner, LICENSE, README, CLAUDE.md, Rust-Workspace mit einem Crate pro
  Abteil, CI (GitHub Actions).
- **Abnahme**: Doku freigegeben (inkl. Prüfung durch ChatGPT, eingearbeitet am 09.11.); das Gerüst baut, die Tests
  laufen, CI ist grün.

## Phase 2 – Kern (erledigt)
- `core`: kanonisches JSON, Base32/Base64url, Krypto-Suite B4-1 mit Invariante N1, Schlüsselkarte, Aussagen,
  Umschlag (bauen/prüfen/öffnen), Strom für Großes, Fehler-Codes.
- `store`: SQLite mit Migrationen.
- `guard`: Token-Buckets, Kontingente, Proof-of-Work (optional/unter Last), Prüf-Reihenfolge „billig zuerst“.
- `transport`: Internet (HTTPS); LAN folgt in Phase 3.
- `node` (minimal): Anmelden, Senden, Abholen, Bestätigen, Replay-Schutz.
- **Abnahme**: Zwei Clients schicken sich über einen Knoten verschlüsselte Nachrichten; der Knoten kann sie
  nachweislich nicht lesen. Angriffs-Tests (gefälschte Signatur, verändertes Byte, Replay, abgelaufen, zu groß,
  10.000 Anfragen/s, falsches PoW) werden alle abgewehrt. Nach einem Neustart sind nicht abgeholte Nachrichten noch da.
- **Stand (09.11.2026): erreicht.** Dazu `sdk/rust` (Client) und `tests/e2e` (Abnahme- und Angriffs-Tests über alle
  Abteile). Eine unabhängige Sicherheits-Prüfung (Sub-Agent) fand 9 Punkte; alle sind behoben und haben Tests.
- Bekannte Grenzen von Phase 2 (werden in Phase 3 gelöst):
  - Jeder darf sich anmelden. Mitgliedschaft und Stufen kommen mit `net`; bis dahin begrenzen nur Limits, Kontingente
    und PoW unter Last.
  - Die Schlüsseldatei des Knotens ist unverschlüsselt (Unix: nur für den Besitzer lesbar).
  - Strom-Teile kann man noch nicht beim Knoten abgeben (das Format ist fertig und getestet).
  - Nur ein Knoten, keine Weiterleitung.

## Phase 3 – BridgeNet (in Arbeit)
- `net`: Hauptschlüssel + 24 Wörter (BIP-39), Admin-Delegation, Manifest aus Vorlagen, Mitgliedsausweis, Stufen,
  Siegel, Widerruf, Sperren, Transparenz-Log (Merkle, Zeugen, Gossip); Dienste `gateway` (Empfänger) und `watch`
  (Wächter).
- `transport`: LAN (mDNS + TLS-Pinning) – Netz funktioniert im Heimnetz auch ohne Internet.
- Mehrere Knoten im Netz, Weiterleitung zum Heim-Empfänger, Beitritt per Link/QR.
- BridgeControll v2: Assistent „Neues BridgeNet“, Knoten anlegen, Owner-Dashboard.
- **Abnahme**: Netz per Klick erstellt, zweiter PC tritt per Link bei, Siegel vergeben/entzogen wirkt im ganzen Netz
  unter 60 s, gefälschtes Manifest/Siegel wird erkannt; ein Log-Führer, der zwei verschiedene Log-Versionen zeigt,
  wird entlarvt und abgesetzt; zwei PCs im selben WLAN reden ohne Internet.
- **Stand (09.11.2026)**:
  - Erledigt: `bridge-net` (reine Logik: Manifest/Vorlagen, Delegation, Einladung, Mitglied, Siegel, Widerruf,
    Sperre, Merkle-Log, Köpfe, Zeugen, Beweise, Zustand aus dem Log). Im Knoten (`bridge-node`, Modul `network`):
    Rollen aus dem Log (Log-Führer, Zeuge, Empfänger, Folgen), Speichern in SQLite (Schema 3: Log, Köpfe, Beweise,
    `home`, Ausgang), Gossip + Absetzen per Beweis, Beitritt (Modi, Codes, PoW aus dem Manifest), Login nur für
    Mitglieder, `home` + Austausch, Weiterleitung zwischen Empfängern, alle Endpunkte aus 06 §9. Kommandozeile
    `bridge-node net create|invite|seal|revoke|ban` und `--join-net`. SDK: `Client::join(link)`, `home` beim Login.
  - Abnahme-Tests (`tests/e2e/tests/phase3_net.rs`, `phase3_attacks.rs`, mehrere Knoten in einem Prozess): Netz
    erstellt, zweiter Knoten tritt bei und wird als Empfänger gesiegelt, Clients an verschiedenen Empfängern
    schreiben sich über Weiterleitung (Knoten können nicht mitlesen), Siegel-Widerruf wirkt in wenigen Sekunden,
    gefälschtes Manifest/Siegel und `submit` von Nicht-Admins werden abgelehnt, Split-View wird per Gossip entlarvt,
    der Beweis verbreitet sich, die Köpfe des Log-Führers werden abgelehnt; Nicht-Mitglieder und Gesperrte kommen
    nicht rein; Einladungen (ohne/mit/verbrauchtem Code); Neustart behält Log und Zustand; Angriffe auf die neuen
    Endpunkte (Müll, zu groß, falsches `aud`, Weiterleitung von Nicht-Empfängern/für Fremde/doppelt).
  - **LAN erledigt** (06 §2, §7): `bridge-node --lan <port>` lauscht zusätzlich per TLS mit eigenem Zertifikat
    (`node-tls.pem`, Fingerabdruck als `tls` in der Karte, über Neustarts gleich, kaputte Datei stoppt den Start),
    kündigt sich per mDNS an und erreicht andere Knoten seines Netzes zuerst gepinnt über das LAN (Weiterleitung,
    `home`-Austausch, Log folgen, Gossip, Zeugen; Pin aus der Siegel-Karte im Log), sonst über ihre `urls`.
    Einladungslinks tragen `node` und `tls`; das SDK (`Client::connect_auto`, `Client::join`) sucht den Knoten zuerst
    im LAN und prüft wie bisher (ID, `info`, Netz – dazu: die Karte pinnt genau dieses Zertifikat). Tests
    (`tests/e2e/tests/phase3_lan.rs`): zwei Clients nur über den TLS-Zugang; falscher Fingerabdruck wird im
    TLS-Handshake abgewiesen, bevor etwas beim Knoten ankommt; lügende Ankündigung und manipulierter Link werden
    erkannt; Beitritt nur über das LAN; Neustart behält den Fingerabdruck; kaputte `node-tls.pem` stoppt den Knoten;
    zwei Empfänger, deren öffentliche Adressen ins Leere gehen, laden das Log, tauschen `home` und leiten weiter –
    nur über das LAN (Abnahme „zwei PCs im selben WLAN reden ohne Internet“, in einem Prozess). Echtes mDNS
    (Multicast) läuft mit `cargo test -- --ignored` (CI: nur Ubuntu). Die CI prüft, dass kein aws-lc hineinkommt.
  - **Prüfung 4 umgesetzt** (06 §2, §4, §5, §10; ADR 0012): Folgen ohne DoS – vor dem Laden muss ein Kopf unter den
    aktuellen Regeln bezeugt sein oder die Quelle ein echtes neueres Manifest zeigen (`NetState::may_fetch`);
    `rules_ahead` zählt nur Manifeste mit der nächsten Version, prüft jede Signatur (höchstens 64, sonst Kopf
    abgelehnt) und findet Unterzeichner über alle Karten im Log und in den neuen Einträgen (stimmt mit dem Abspielen
    überein, Eigenschafts-Test); der Zustand liegt als geteilter Schnappschuss vor, Kopie und Abspielen nie unter der
    Sperre (Zähler `state_copies`). Vorbeugung: Manifest-Wechsel nur mit gesiegelten Zeugen/Log-Führer, die Netz-ID
    ist nie Zeuge. Not-Wiederherstellung: ein Manifest allein vom Hauptschlüssel, sein Übergangs-Kopf mit `cosign` des
    Hauptschlüssels; Befehl `bridge-node net rescue` (24 Wörter über die Standard-Eingabe). Karte des neuesten Siegels
    zählt (Pin nach Neu-Siegeln), `net seal` behält Stufe und Dienste. LAN-Verzeichnis: Vergessen je ID, nur IDs mit
    Pin im Log. Tests: `crates/bridge-net/tests/net_review4.rs`, `tests/e2e/tests/phase3_review4.rs`, `lan.rs`.
  - **Prüfung 5 umgesetzt** (06 §2, §5, §6, §9, §10; ADR 0013, Nachträge in 0010/0012): Übergänge beim Aufholen –
    wer beim Folgen einen Wechsel der Log-Regeln überquert, verlangt dessen Übergangs-Kopf unter den alten Regeln
    (bzw. die Not-Form), alle Knoten behalten diese Köpfe (Schema 4) und geben sie über `POST …/head/at` heraus; die
    24 Wörter allein gabeln keinen folgenden Knoten mehr. Vorprüfung vor dem Laden: Zeugen mit noch unbekannter Karte
    zählen als „vielleicht“, Köpfe werden immer geprüft, wenn die Karte ihres Log-Führers bekannt ist, ein Manifest
    zählt nur, wenn das Abspielen es nehmen könnte (`approvals.rules`, Zeit), bekannte Unterzeichner ohne `rules`
    gelten als unbekannt. Karten: die neueste **Karte** zählt (kein Zurückdrehen per Siegel auf Stufe 1). LAN:
    Filter nach Pin schon in der Suche, höchstens 4 Ankündigungen je ID, Adressen reihum. `net rescue` liest die
    Wörter am globalen Eingabe-Puffer vorbei, unter Unix vom Terminal mit Anzeige aus und Wiederherstellung auch bei
    Ctrl+C. Tests: `crates/bridge-net/tests/net_review5.rs`, `tests/e2e/tests/phase3_review5.rs`, `lan.rs`,
    `mdns.rs`, `secret.rs`, `bridge-store` (`net.rs`).
  - **Prüfung 6 umgesetzt** (06 §2, §5, §6, §10; ADR 0014, Nachträge in 0012/0013, 02 §8): Die Not-Form eines
    Übergangs-Kopfes und die Bestätigung eines hängenden Wechsels zählen nur mit dem **ersten** alten Log-Führer – die
    24 Wörter gabeln einen Folgenden auch nicht mehr über einen selbst eingetragenen zweiten Log-Führer (Normal-Form:
    weiter jeder alte Log-Führer mit der alten Zeugen-Mehrheit, begründet in 06 §5). Übergangs-Köpfe kommen von bis zu
    4 verschiedenen Knoten, werden vom neuesten Wechsel an einzeln geprüft (Schluss beim ersten unbestätigten);
    abgelehnte Köpfe, nirgends gefundene Übergangs-Köpfe und die Quelle werden 4 Takte gemerkt (begrenzte Arbeit gegen
    gefälschte Anhänge). Gespeicherte Übergangs-Köpfe werden nach einem Neustart geprüft, kaputte nicht herausgegeben,
    fehlende neu geholt und ersetzt, nicht gespeicherte erneut versucht. Siegel mit einer Karte aus der Zukunft (mehr
    als 5 min nach dem Siegel) sind ungültig, „neueste Karte“ nach `min(iat Karte, iat Siegel)`. LAN: die kanonische
    mDNS-Ankündigung (Instanzname = ID) wird immer aufgenommen. `net rescue` liest unter Windows immer von einer Kopie
    der Standard-Eingabe (hing in Git Bash/MSYS). Tests: `crates/bridge-net/tests/net_review6.rs` (u. a. der Testfall
    des Prüfers als dauerhafter Regressionstest), `tests/e2e/tests/phase3_review6.rs`, `sync.rs`, `mdns.rs`,
    `bridge-store` (`net.rs`).
  - **Wächter gebaut** (06 §11, ADR 0016; Freigabe durch Paddy steht aus): Dienst `watch` (Siegel Stufe ≥ 2) vergibt
    automatisch Stufe 1 – an Mitglieder nach Zeit ohne Sperre, an Knoten (`--probe web`, selbst Mitglied) nach
    bestandenen Proben (`/v4/info` + Kopf, ≤ 5 s, LAN gepinnt oder `urls`); Verlängern, Abstieg per Widerruf nach
    Fehlschlägen in Folge. `bridge-net`: Regeln im Zustand (nur Stufe 1, nur `web`, Inhaber Mitglied, Mindestalter
    und Abstand zur letzten Sperre, Lebensdauer, Budget je Wächter und Tag, nur eigenes oder verwaistes Siegel
    ersetzen), optionales Manifest-Feld `watch`. `bridge-node`: Wächter-Takt, Anmeldung `POST /v4/node/watch`,
    Beitritt als Mitglied für Knoten mit `--probe`, `submit` auch für Wächter, Proben-Geschichte in SQLite (Schema 7).
    Kommandozeile `bridge-node net watch-status`. Tests: `crates/bridge-net/tests/net_watch.rs`,
    `tests/e2e/tests/phase3_watch.rs`, `bridge-store` (`watch.rs`). Offen: 06 §11.8.
  - **BridgeControll v2 gebaut** (ADR 0017, `apps/bridgecontroll`; Freigabe durch Paddy steht aus): lokale Web-App
    (Rust-Programm, Oberfläche nach den freigegebenen Entwürfen N01–N04 auf 127.0.0.1 im Browser, Tauri-Hülle später).
    „Deine Netze“ mit Live-Status je Knoten (Prozess, `/v4/info`, Log, Kopf, Stufe und Rollen), Start/Stop,
    Einstellungen, Protokoll, Löschen (Ordner nach `backup/`); Assistent „Neues BridgeNet“ in vier Schritten (Name und
    Art → die 24 Wörter genau einmal, nur in der Antwort eines POST, Test mit drei Wörtern → Erreichbarkeit mit Prüfung
    → Netz erstellt, Owner-Knoten läuft, Einladungslink mit QR-Code); „Netz beitreten“ per Link (Link geprüft:
    Genesis bis zur Netz-ID, ID des Empfängers, LAN-Hinweis); Owner-Dashboard (Knoten mit Stufe/Rollen, Siegeln mit
    ID-Bestätigung – Knoten dieses PCs oder Knoten-Ausweis –, Siegel entziehen, „Karte veraltet → Neu siegeln“,
    Mitglieder mit Suche/Sperren/Entsperren, Einladungen, Apps mit Sperren, Transparenz-Log mit Beweis-Alarm, Wächter).
    Jeder Knoten ist ein eigener Prozess desselben Programms (`bridgecontroll node --supervised`, Knoten-Läufer aus
    `bin/bridge-node` als Bibliothek) mit Watchdog (1/2/4/8/16 s, höchstens 5 Neustarts in 10 min), sauberem Stopp
    über die Standard-Eingabe und rotierenden Logs. Lokal Zero Trust: Sitzung per Einmal-Link + Cookie, Host- und
    Origin-Prüfung, CSP, keine Inline-Skripte, begrenzte Bodies. Autostart mit dem PC (Windows: Datei im
    Autostart-Ordner). Tests: `apps/bridgecontroll/tests/` (`control.rs` mit echten Knoten-Prozessen: erstellen →
    beitreten → siegeln → Stufe sichtbar → Mitglied sperren → Siegel entziehen wirkt in Sekunden → löschen; LAN-Beitritt
    mit totem `gw` nur über das LAN (`--ignored`); `supervision.rs`; `security.rs`), Playwright-Rauchtest
    `tests/ui/smoke.py` mit Bildschirmfotos.
  - Offen: Abnahme „zwei PCs im selben WLAN“ auf echter Hardware (Paddys PCs, Windows-Firewall/Multicast) – jetzt mit
    BridgeControll v2 per Klick; BridgeControll v2: Tauri-/Tray-Hülle, Tailscale Funnel einrichten, Knoten anderer PCs
    ohne Ausweis finden, Windows-Teile nur von der CI gebaut (ADR 0017 „Grenzen“); LAN-Restpunkte (06 §10: keine
    Zertifikats-Rotation), Wächter-Restpunkte (06 §11.8, u. a. Bürgen), Befehle mit den 24 Wörtern
    (Admin verlängern, `cascade`), GET mit Query-Strings (Transport), Folgen über sehr große Lücken, Test mit
    mehreren Log-Führern (06 §10); Grenzen nach Prüfung 4 (06 §10: verlorener einziger Log-Führer, Wechsel nur von
    später delegierten Admins, erster Kontakt ohne Vorprüfung); Grenzen nach Prüfung 5 (06 §10: Anker beim ersten
    Kontakt nur die Netz-ID, nur die letzten 64 Übergangs-Köpfe, Windows zeigt die Wörter beim Tippen); Grenzen nach
    Prüfung 6 (06 §10: keine Not-Wiederherstellung ohne den ersten Log-Führer, bis zu 63 selbst gelieferte Köpfe je
    gefälschtem Versuch, Merk-Tabellen nur im Speicher, gleichnamige mDNS-Fälscher); `net rescue` unter Windows ist
    nur gelesen geprüft (kein Windows-Ziel in dieser Umgebung – die CI baut es).

## Phase 4a – Dateien und Apps (docs/07, ADR 0015; Paddy 11.11.2026)
- Datei-Übertragung nach Inhalt (Blobs, Teile à 64 KiB, mehrere Quellen, Kontingente).
- Bridge-Apps (Stufe 1, ohne Server-Code): eigener App-Schlüssel, signierte Versionen (App + Owner), Host-Liste vom
  Owner, Hosts holen neue Versionen selbst, Ausliefern unter `/app/<id>/` in abgeschotteter Herkunft.
- **Abnahme**: Owner veröffentlicht eine App auf zwei Hosts; fällt einer aus, liefert der andere weiter; ein Host, den
  der Owner entfernt, hört auf; ein Mit-Host, der Dateien verändert, wird erkannt; eine gesperrte App wird nirgends
  mehr ausgeliefert; ein Download holt Teile von mehreren Hosts und erkennt jeden falschen Teil.
- **Stand (11.11.2026): gebaut, Abnahme-Tests grün** (Freigabe durch Paddy steht aus). Entscheidungen beim Bau:
  docs/07 („Beim Bau festgelegt“, §8, Grenzen §9).
  - `bridge-core`: Blob-ID und Hash-Liste (`blob`), Verschlüsselung privater Dateien (`file`: Stücke zu 65.520 Byte =
    ein Teil, Schlüssel nur intern, N1), App-Manifest (`app`: strenger Body, beide Karten im Body, genau zwei
    Unterzeichner, max. 960 KiB, max. 1 Jahr), Rolle `app`.
  - `bridge-net`: Art `app` (nicht im Log), Prüfung gegen den Netz-Zustand (Owner Mitglied mit `apps.min_level`, App
    und Owner nicht gesperrt, Hosts nur mit `web`-Siegel), optionales Manifest-Feld `apps`.
  - `bridge-store` (Schema 5): Blobs (Hash-Listen, vorhandene Teile, Festhalter mit Owner und Ablauf, wartende
    Hash-Listen je Hochlader), Apps (aktuelle, vorige, wartende Version, gemerkte höchste Version), Dateien in
    `blobs/` (Hex-Namen, `.part` bis vollständig).
  - `bridge-transport`: `OPTIONS`, eigene Antwort-Köpfe, Antworten als Strom (`BodyStream`, bricht bei Fehlern ab).
  - `bridge-node`: Blob- und App-Endpunkte (07 §7), Kontingente je Stufe, enge Lese-Grenze je Adresse, Hosting mit
    Takt (andere Hosts fragen, Version anbieten, parallel holen und prüfen, atomar umstellen, aufhören), Ausliefern
    unter `/app/<id>/` mit Sandbox-Köpfen, CORS für `/v4/…`, Aufräumen im Hausmeister, jeder gelesene Teil geprüft.
  - `sdk/rust`: Hochladen, paralleles Herunterladen mit Prüfung und Fortsetzen, App aus einem Ordner veröffentlichen,
    Version holen und prüfen, Host wählen (LAN zuerst). Kommandozeile `bridge-node app create|publish|hosts`.
  - Tests: `tests/e2e/tests/phase4_apps.rs` (Abnahme: zwei Hosts, der zweite holt selbst, Ausfall, Entfernen,
    manipulierte Teile über einen fälschenden Host und beim Download, Sperre von App und Owner, paralleles Laden,
    Fortsetzen, beschädigte Datei auf der Platte wird nie ausgeliefert und repariert sich), `phase4_attacks.rs`
    (Pfade/Traversal, Typen, zu große Manifeste/Blobs/Teile, Kontingent, nicht gelisteter Host, eine Signatur bzw.
    falscher Unterzeichner, Rollback, gefälschte Hash-Listen und Teile, Müll ohne 5xx, Köpfe auf jeder App-Antwort,
    CORS, Lese-Grenze, Grenze gehosteter Apps, Knoten ohne Netz), Einheits-Tests in allen Abteilen,
    `bin/bridge-node` (`app create|publish|hosts` gegen ein laufendes Netz).
  - Offen: docs/07 §9 (u. a. `Range`/`If-None-Match`, Lese-Grenze auch zwischen Hosts, CLI braucht den Ordner des
    Owner-Knotens, kein automatisches Neu-Signieren vor Ablauf, verwaiste Dateien nach Absturz).
- Stufe 2 später (Phase 5): Daten-Werkzeuge (Ereignis-Log pro App, Kanal, Speicher mit Konflikt-Meldung, Sperren),
  Server-Code in der WebAssembly-Sandbox.

## Phase 4 – Namen, Web, Browser
- Dienst `names` (DNS + Suche), Dienst `web` (Websites von Knoten, auch hinter dem Router), Bridge-Browser.
- **Abnahme**: `shop.meinnetz` im Browser öffnet die Website eines anderen PCs; Suche nach „shop“ liefert eine Liste;
  gefälschter Namens-Eintrag wird abgewiesen.
- **Stand (12.11.2026): Kern gebaut, Abnahme-Tests grün** (docs/08, ADR 0018; Freigabe durch Paddy steht aus). Dazu der
  Missbrauchsschutz nach Paddys Vorgabe vom 10.11. (`NUTZUNGSREGELN.md`, Entwurf – anwaltlich prüfen lassen).
  - `bridge-net`: Manifest-Felder `short`, `contact`, `names`, `adult`, `blocklists`; Aussagen `name` (im Log: wer zuerst
    kommt, Stufe + Kontingent, App-Namen von App-Schlüssel **und** Inhaber, Verwechslungs-Skelett, reservierte Wörter
    ab Stufe 3, 18+-Regel, max. 1 Jahr, Verlängern, Widerruf) und `label` (Admins mit `seals`); Auflösen, Suche mit
    Rang und sicherer Suche, Kennzeichnungs-Vorrang, 18+-gekennzeichnete Apps in `forbidden`-Netzen nicht mehr gültig.
  - `bridge-store` (Schema 9): Meldungen (begrenzt je Mitglied und Knoten, Doppelte, Status, Weitergabe).
  - `bridge-transport`: `Request::host`, `Request::forwarded`. `bridge-guard`: eigene Grenze je Adresse für Namen.
  - `bridge-node`: `/v4/names/info|resolve|search|list|submit`, `/v4/report`, `/v4/node/report`,
    `/v4/admin/reports|report`, Leser für nicht gehostete Apps (nur lokal, geprüft, LRU-Speicher), Weitergabe der
    Meldungen an den Log-Führer. Kommandozeile `name register|list|revoke`, `net label`, `net reports`,
    `net create --contact --short --adult`, `--reader off|local|lan`.
  - Tests: `crates/bridge-net/tests/net_names.rs` (Fälschungen, Regeln, Kennzeichnung, Suche, Abspielen gleich),
    Einheits-Tests (`names.rs`, Manifest, `reports.rs` im Store, Leser, Meldungen), `tests/e2e/tests/phase4_names.rs`
    (Abnahme: App auf einem anderen PC bekommt `shop`, ein eigener Knoten löst `shop.testnetz` auf und lädt sie über
    seinen Leser, Suche; gefälschte Namen; 18+ in sicherer Suche und Kennzeichnung; 18+-Kennzeichnung stoppt eine App;
    Meldungen beim Owner-Knoten, Grenzen, gefälschte Weitergabe; Leser lehnt Fremde und manipulierte Teile ab).
  - **Prüfung 9 (12.11.2026)**: Suche begrenzt und neben der Sperre, Namen mit eigenem Topf und Tagesbudget, Böden statt
    Widerrufs-Tabelle, Kennzeichnung am Inhaber und 18+ gewinnt, App-Schlüssel widerruft, reservierte Schlagworte,
    versiegelte Meldungstexte, Leser `lan`/`tailnet` und `--reader-listen`, `card_verified` (ADR 0018 Nachtrag, ADR 0017
    Nachtrag 3). Tests: `crates/bridge-net/tests/net_review9.rs`, Einheits-Tests in `state.rs`, `names.rs`,
    `reports.rs`, `reader.rs`, `tests/e2e/tests/phase4_review9.rs`, `smoke.py` (Neulade-Schleife).
  - **BridgeControll (12.11.2026)**: Bridge-Browser (Adresse, Suche, sicherer Modus, Schloss mit Warnungen, 18+-Schranke,
    App im Sandbox-`iframe` vom Leser des eigenen Knotens, Melden), im Assistenten Meldeweg (Pflicht), Kurzname und
    18+-Regel, im Owner-Dashboard Namen, Meldungen mit Schnell-Aktionen und „Meldeweg fehlt“, Leser je Knoten in den
    Einstellungen (docs/08 §12, ADR 0017 Nachtrag 2). Tests: `apps/bridgecontroll/tests/browser.rs` (auflösen, suchen,
    Leser liefert die App, Meldung beim Owner, erledigen, Schnell-Aktionen, Meldeweg ändern), `security.rs` (CSP
    `frame-src` nur die Leser dieses PCs, Sandbox ohne `allow-same-origin`, kein HTML aus Daten, Müll an die
    Browser-API), Playwright-Rauchtest bis „Meldung erledigt“.
  - Offen: docs/08 §11 (u. a. Sperrlisten nur als Feld, Leser in großen Netzen, Leser hinter Tailscale Funnel).

## Phase 5 – Speicher und Rechnen
- `storage`: Verschlüsselung beim Client, Erasure Coding, Verteilung auf verschiedene Besitzer, Speicher-Proben,
  Umzug bei Ausfall. `compute`: WebAssembly-Sandbox, Stichproben-Nachrechnen.
- Plugin-Host für fremde Plugins (WASM, Fähigkeiten, Limits, signierte Updates, Not-Aus).
- **Abnahme**: Datei überlebt den Ausfall von 4 von 10 Speicher-Knoten; ein „lügender“ Speicher-Knoten fällt durch die
  Proben und verliert seine Stufe.
- **Stand (12./13.11.2026): gebaut, Abnahme-Tests grün** (Paddy war weg, „entscheide selber“; Freigabe steht aus).
  docs/09, ADR 0019 (Speicher), ADR 0020 (wasmi statt wasmtime). Gebaut:
  - Speicher: `bridge-core::erasure` (Reed-Solomon, Cauchy), SDK `storage` (`store`, `fetch`, `audit`, `repair`,
    `renew`, Karte beim Besitzer), Verteilung auf verschiedene Knoten und Hosts; Wächter-Proben für `storage`
    (`/v4/storage/probe`, Proben-Blob) – wer lügt, verliert das Siegel.
  - Rechnen: neues Abteil `crates/bridge-wasm` (wasmi, Fuel, Speicher-Grenze, keine Gleitkommazahlen bei Rechen-
    Aufträgen), `/v4/compute/run` mit signiertem Ergebnis, SDK `compute`/`run_checked` (Stichproben), Wächter-Probe
    für `compute` (`/v4/compute/probe`, eingebaute Prüf-Aufgabe).
  - Plugins: Aussage `plugin` (Plugin-Schlüssel), Fähigkeiten `kv`/`log`/`caller`, Kontingent, Updates nur höher und
    mit erlaubten Fähigkeiten, Not-Aus lokal und per `ban`; `bridge-node plugin key|sign|install|list|disable|enable`.
  - Apps Stufe 2: Feld `server` im App-Manifest (`server.wasm` im Ordner), `POST /app/<id>/api/…` an Hosts, Ereignis-Log
    je App (signiert je Host, `/v4/app/events`, gleiche Reihenfolge überall). Schema 11/12.
  - Tests: `tests/e2e/tests/phase5_storage.rs` (4 von 10, Reparatur, lügender Knoten, Stufe weg, Proben nur von
    Wächtern), `phase5_compute.rs`, `phase5_plugins.rs`, `phase5_appserver.rs`; Einheits-Tests in `erasure`,
    `bridge-wasm`, `storage`, `blocklist`.
  - Offen: docs/09 §9; API der App-Server-Code nur direkt an Hosts (nicht über den Leser), Speicher in BridgeControll
    (Oberfläche) fehlt noch.

## Phase 6 – SDKs, KI, Wachstum
- SDKs: Python + JavaScript zuerst, dann Java, Luau (Risiko R1).
- KI-Dienste (lokal, gratis), KI-Agenten mit begrenzten Ausweisen, Suche verbessern, Netze verbinden (Föderation).
- **Abnahme** (docs/10 §7): jedes SDK besteht die Testvektoren und den Live-Test gegen Rust; Agenten nur mit ihren
  Rechten, Widerruf/Sperre wirkt sofort; KI-Dienst nur mit lokalem Modell; Föderation nur beidseitig.
- **Stand (13.11.2026): gebaut, Abnahme-Tests grün** (Paddy war weg, „entscheide selber“; Freigabe steht aus).
  docs/10, ADR 0021 (SDKs), 0022 (Agenten-Ausweise), 0023 (Föderation), 0024 (KI-Dienst lokal). Gebaut:
  - SDKs: `sdk/python` (cryptography), `sdk/javascript` (noble eingebettet, Node + Browser), `sdk/java` (nur JDK),
    `sdk/luau` (TweetNaCl-Port + RFC, Lune/Roblox) – Testvektoren `sdk/vectors` aus dem Rust-Kern (deterministisch,
    `tests/e2e/tests/sdk_vectors.rs`), Live-Test gegen `sdk-fixture` (Netz + Rust-Echo-Client + Echo-Agent). CI-Job
    `sdks`.
  - Agenten-Ausweise: Aussage `agent` (bridge-core), Login nur am Heim-Knoten, `send`/`receive`, `to`, `rate`,
    höchstens 30 Tage, 16 je Inhaber und Knoten, Widerruf `/v4/agent/revoke` (Schema 13), Weiterleiten mit Aussage,
    Empfänger sehen den Inhaber (`agents` im Poll). CLI `agent issue|revoke`.
  - KI-Dienst: `services/ai` (bridge-ai), `bridge-plugin-api` Task/Reply, `bridge-node ai` (Ollama/OpenAI, nur Loopback,
    Liste oder Mitglieder, Rate, Warteschlange 16), SDK `request()`.
  - Suche: mehrere Wörter, Umlaute/Akzente gefaltet, ein Tippfehler (Wörter ab 4 Buchstaben), `kind`-Filter.
  - Föderation: Log-Aussage `federation` (nur Hauptschlüssel, beidseitig, ≤ 32 Netze), Umschlag-Feld `dnet`,
    `/v4/fed/relay`, `/v4/fed/card`, Beweise `feds`+`master` beim Abholen; CLI `net federate|unfederate`.
  - Tests: `tests/e2e/tests/phase6_agents.rs`, `phase6_federation.rs`, `bin/bridge-node/tests/ai.rs`,
    `crates/bridge-net/tests/net_federation.rs`, SDK-Tests je Sprache.
  - Offen: docs/10 §8 (SDKs ohne LAN/Ströme/Dateien, Föderation nur Nachrichten, Luau-Krypto ohne fremde Prüfung).

## Phase 7 – Öffentlich, Bridge 3 im Netz, Bridge Login (docs/11, Paddy 13.11.2026)
- Grundsätze: kostenlos ohne Abos (eigene PCs + Tailscale, keine fremden Cloud-Dienste), Bridge 4 ohne eigene Realms
  (ADR 0026), das Netz nutzt sich selbst (Features nur mit passenden Knoten), Bridge gibt Werkzeuge – die App
  entscheidet (z. B. Speicher lokal am Knoten oder im Bridge-Speicher).
- Schritt 1: **Öffentlich** – das Tor (ADR 0025, ein Funnel-Port für alle Netze unter `/bridge4/<netz>/`), „Öffentlich
  machen“ in BridgeControll v2, öffentliche Websites in der Hülle, Startseite, Not-Aus, 18+-Netze nie öffentlich.
- Schritt 2: BridgeControll 3 legt Server unter `/bridge3/<id>` ab (alter Pfad bleibt zum Umstellen).
- Schritt 3: Bridge-3-Server im Netz (`/bridge4/<netz>/bridge3/<id>/`).
- Schritt 4: „Was kann mein Netz?“ (Fähigkeiten-Ampel) und Bridge Login (Passkeys, Nutzer-ID pro App, Daten pro Nutzer).
- Später, optional: eigene Domain.
- **Abnahme** (docs/11 §11): eine Website von Paddys PC ist in einem fremden Browser über die Tailscale-Adresse
  erreichbar, zwei Netze teilen sich einen Port, Not-Aus wirkt sofort, BridgeControll 3 läuft daneben weiter.
- **Stand (13.11.2026)**: Schritt 1 (Tor `crates/bridge-gate`, Leser `public`, Startseite/Hülle, „Öffentlich machen“),
  Schritt 2 (BridgeControll 3: `/bridge3/<id>`, „Pfad umstellen“), Schritt 3 (Bridge-3-Server im Netz) und Schritt 4
  („Was kann mein Netz?“, Bridge Login mit Passkeys an Speicher-Knoten, App-Zeichen für den Server-Code, „Login hier
  einschalten“) gebaut, Tests grün; Paddys Echttest mit Tailscale steht aus.

## Phase 8 – Aufräumen und Komfort (Paddy 13.11.2026, in dieser Reihenfolge)
1. **Apps und Websites löschen** (Paddy: „gerade kann man nur sperren, das ist nervig“): der Inhaber zieht eine App
   zurück – eine signierte Aussage im Transparenz-Log, alle Hosts hören auf und löschen ihre Dateien, der Name wird
   frei. Anders als „Sperren“ (Maßnahme des Admins gegen fremde Inhalte, bleibt sichtbar). In BridgeControll „Löschen“
   neben „Neue Version“; dazu pro Website der Link „Öffentlich ansehen“ (`…/bridge4/<netz>/web/<name>/`).
   **Gebaut 13.11.2026** (docs/07 §10, ADR 0028): Log-Art `retire`, `bridge-node app delete`, „Löschen“ und
   „Öffentlich“ in BridgeControll.
2. **Öffentliche Eingänge auf PCs von Mitgliedern**: erst damit kann ein PC außerhalb des LANs Speicher-Knoten,
   Empfänger oder zweiter Login-Knoten sein; das Tor ohne Neustart neu laden. **Gebaut 13.11.2026** (docs/11 §13):
   „Erreichbar machen“ für Mitglieder-Knoten, Websites nur an Knoten mit Stufe 3 (statt einer Manifest-Regel – Stufe 3
   vergibt ohnehin nur der Owner), Tor lädt Routen neu.
3. **Gerät hinzufügen** (Bridge Login, Paddy 13.11.: ein Konto auf mehreren Geräten ohne Fenster für fremde Geräte):
   mehrere Passkeys je Konto (höchstens 8), jedes Gerät mit eigenem Passkey. Das angemeldete Gerät zeigt einen
   **Kopplungs-Code** (8 Zeichen ohne Verwechsler wie 0/O und 1/I, z. B. `K7QX-M3PA`, 5 Minuten, einmal, nach
   5 Fehlversuchen ungültig) und denselben Code als **QR-Code** (für Geräte ohne Kamera reicht der Code). Das neue Gerät
   gibt ihn ein, legt seinen eigenen Passkey an; beide zeigen dieselbe **Prüfzahl**, das alte Gerät bestätigt mit seinem
   Passkey (signierter Eintrag `add`, jeder Speicher-Knoten prüft die Unterschrift). „Meine Geräte“ zum Entfernen
   (`remove`, ebenfalls signiert). Keine Passwörter. **Gebaut 14.11.2026** (docs/11 §14, ADR 0027 Nachtrag).
4. **BridgeControll aktualisiert sich selbst**: „Update verfügbar“ lädt die neue Version von GitHub, prüft Paddys
   Signatur und ersetzt sich (kein ZIP von Hand mehr); Grundlage dafür, dass Knoten anderer nicht veralten.
   **Gebaut 14.11.2026** (docs/12, ADR 0029): Veröffentlichungs-Schlüssel nur auf Paddys PC, unterschriebene
   Ankündigung `releases/bridgecontroll.json`, Workflow `release.yml` (Tag `bc-v…`), automatisch (abschaltbar),
   zurück zur alten Version, wenn die neue nicht startet. Aktiv ab der ersten Version mit eingetragenem Schlüssel.
5. **Owner-Backup im eigenen Netz**: App-Schlüssel und Einstellungen des Owners, verschlüsselt mit einem Schlüssel aus
   den 24 Wörtern, liegen auf den Speicher-Knoten; auf einem neuen PC stellen die 24 Wörter alles wieder her.
   **Gebaut 14.11.2026** (docs/12 §10, ADR 0030): verschlüsselt für den Empfangs-Schlüssel des Hauptschlüssels (der PC
   braucht die Wörter dafür nicht), als eigene App auf den Web-Hosts, Log-Eintrag `backup`; „Netz wiederherstellen“
   holt den Owner-Knoten (erster Log-Führer) mit allen Schlüsseln zurück.
6. Danach: Bridge Login auch im Bridge-Browser und unter „Ansehen“ (heute nur über die öffentliche Adresse),
   angemeldet bleiben, Zahl der Konten im Dashboard, Helfer im JavaScript-SDK; Speicher-Oberfläche in BridgeControll,
   App-API auch über den Leser; Bridge-3-Server als Name im Netz und auf anderen PCs; öffentliche Status-Seite
   (`…/bridge4/<netz>/status`) und Windows-Benachrichtigung bei neuer Meldung oder ausgefallenem Knoten.
   **Gebaut 14.11.2026**: Status-Seite (docs/11 §15), Zahl der Konten im Dashboard, angemeldet bleiben (HttpOnly-Cookie,
   docs/11 §16), `bridgeLogin` im JavaScript-SDK (docs/11 §17). Offen: Login im Bridge-Browser/„Ansehen“,
   Speicher-Oberfläche, App-API über den Leser, Bridge-3-Server als Name, Windows-Benachrichtigungen.

## Phase 9 – Vorlagen und Design-Plugins (Paddy 13.11.2026)
- **Viele Vorlagen** (Paddy: „ganz wichtig, dass es da viele gibt“): Bridge soll auf vielen Geräten laufen, auch bei
  Freunden, die nicht programmieren können. In „Website hochladen“ fertige, **einstellbare** Vorlagen (z. B.
  Gästebuch, Chat, Umfrage, Terminliste, später viele mehr); der eigene PC hostet sie. Sie nutzen Bridge Login und den
  Server-Code der Apps.
  **Gebaut 14.11.2026** (docs/13, ADR 0031): „Website aus Vorlage“ in BridgeControll mit acht Vorlagen (Visitenkarte,
  Gästebuch, Umfrage, Termine, Anmeldung, Ideen sammeln, Countdown, Rezept), drei Designs, „Bearbeiten“; der eingebaute Server-Baustein `builtin:records` speichert die
  Einträge auf dem Ereignis-Log der App (bei allen Hosts gleich). Nächste Vorlagen: Wunschliste, Pinnwand, Fotoalbum,
  Chat.
- **Design-Plugins** (später): laufen lokal; bei einer Vorlage wählt man als Design ein selbst gemachtes Design-Plugin,
  das das Aussehen der Website übernimmt.
- **Bridge Drive**: geteilte Ordner über die Speicher-Knoten, beim Besitzer verschlüsselt, mit anderen Konten teilbar.
- Danach in Paddys Reihenfolge: Oracle-Dauer-Server, Anbindung an Grove ganz am Ende, eigene Domain nur optional.

## Nebenher
- Bridge 3 läuft weiter (Branch `bridge-3`), bekommt nur noch Fehlerbehebungen.
- Jede größere Entscheidung als ADR in `docs/adr/`.

## Entschieden
- Wiederherstellungs-Wörter: BIP-39 (englische Standard-Liste).
- Sprache: Rust für Knoten, Abteile und BridgeControll (Tauri); Web-Technik für Oberflächen; SDKs in mehreren
  Sprachen (ADR 0003).
- Windows-Programme baut die CI (GitHub Actions) – Paddy braucht keine Rust-Installation.
