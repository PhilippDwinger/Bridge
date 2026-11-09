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
  - Offen: Abnahme „zwei PCs im selben WLAN“ auf echter Hardware (Paddys PCs, Windows-Firewall/Multicast),
    LAN-Restpunkte (06 §10: Neu-Siegeln nach spätem `--lan`, keine Zertifikats-Rotation), BridgeControll v2
    (Assistent „Neues BridgeNet“, „per Klick“), Dienst `watch` (Wächter, Stufe 1), Befehle mit den 24 Wörtern
    (Admin verlängern, `cascade`), GET mit Query-Strings (Transport), Folgen über sehr große Lücken, Test mit
    mehreren Log-Führern (06 §10); Grenzen nach Prüfung 4 (06 §10: verlorener einziger Log-Führer, Wechsel nur von
    später delegierten Admins, erster Kontakt ohne Vorprüfung); Grenzen nach Prüfung 5 (06 §10: Anker beim ersten
    Kontakt nur die Netz-ID, nur die letzten 64 Übergangs-Köpfe, Windows zeigt die Wörter beim Tippen); Grenzen nach
    Prüfung 6 (06 §10: keine Not-Wiederherstellung ohne den ersten Log-Führer, bis zu 63 selbst gelieferte Köpfe je
    gefälschtem Versuch, Merk-Tabellen nur im Speicher, gleichnamige mDNS-Fälscher); `net rescue` unter Windows ist
    nur gelesen geprüft (kein Windows-Ziel in dieser Umgebung – die CI baut es).

## Phase 4 – Namen, Web, Browser
- Dienst `names` (DNS + Suche), Dienst `web` (Websites von Knoten, auch hinter dem Router), Bridge-Browser.
- **Abnahme**: `shop.meinnetz` im Browser öffnet die Website eines anderen PCs; Suche nach „shop“ liefert eine Liste;
  gefälschter Namens-Eintrag wird abgewiesen.

## Phase 5 – Speicher und Rechnen
- `storage`: Verschlüsselung beim Client, Erasure Coding, Verteilung auf verschiedene Besitzer, Speicher-Proben,
  Umzug bei Ausfall. `compute`: WebAssembly-Sandbox, Stichproben-Nachrechnen.
- Plugin-Host für fremde Plugins (WASM, Fähigkeiten, Limits, signierte Updates, Not-Aus).
- **Abnahme**: Datei überlebt den Ausfall von 4 von 10 Speicher-Knoten; ein „lügender“ Speicher-Knoten fällt durch die
  Proben und verliert seine Stufe.

## Phase 6 – SDKs, KI, Wachstum
- SDKs: Python + JavaScript zuerst, dann Java, Luau (Risiko R1).
- KI-Dienste (lokal, gratis), KI-Agenten mit begrenzten Ausweisen, Suche verbessern, Netze verbinden (Föderation).

## Nebenher
- Bridge 3 läuft weiter (Branch `bridge-3`), bekommt nur noch Fehlerbehebungen.
- Jede größere Entscheidung als ADR in `docs/adr/`.

## Entschieden
- Wiederherstellungs-Wörter: BIP-39 (englische Standard-Liste).
- Sprache: Rust für Knoten, Abteile und BridgeControll (Tauri); Web-Technik für Oberflächen; SDKs in mehreren
  Sprachen (ADR 0003).
- Windows-Programme baut die CI (GitHub Actions) – Paddy braucht keine Rust-Installation.
