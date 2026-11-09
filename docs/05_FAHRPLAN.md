# 05 – Fahrplan

Kein Zeitdruck. Jede Phase endet erst, wenn ihre **Abnahme** erfüllt ist (Tests grün, Doku aktuell, Paddy hat
freigegeben).

## Phase 1 – Spezifikation (jetzt)
- Grundsätze, Begriffe, Sicherheitsmodell, Architektur, Protokoll v4, Fahrplan (diese Dateien).
- Repo-Gerüst auf Branch `bridge-4`: Ordner, LICENSE, README, CLAUDE.md, Rust-Workspace mit einem Crate pro
  Abteil, CI (GitHub Actions).
- **Abnahme**: Doku freigegeben (inkl. Prüfung durch ChatGPT, eingearbeitet am 09.11.); das Gerüst baut, die Tests
  laufen, CI ist grün.

## Phase 2 – Kern
- `core`: kanonisches JSON, Base32/Base64url, Krypto-Suite B4-1 mit Invariante N1, Schlüsselkarte, Aussagen,
  Umschlag (bauen/prüfen/öffnen), Strom für Großes, Fehler-Codes.
- `store`: SQLite mit Migrationen.
- `guard`: Token-Buckets, Kontingente, Proof-of-Work (optional/unter Last), Prüf-Reihenfolge „billig zuerst“.
- `transport`: Internet (HTTPS); LAN folgt in Phase 3.
- `node` (minimal): Anmelden, Senden, Abholen, Bestätigen, Replay-Schutz.
- **Abnahme**: Zwei Clients schicken sich über einen Knoten verschlüsselte Nachrichten; der Knoten kann sie
  nachweislich nicht lesen. Angriffs-Tests (gefälschte Signatur, verändertes Byte, Replay, abgelaufen, zu groß,
  10.000 Anfragen/s, falsches PoW) werden alle abgewehrt. Nach einem Neustart sind nicht abgeholte Nachrichten noch da.

## Phase 3 – BridgeNet
- `net`: Hauptschlüssel + 24 Wörter (BIP-39), Admin-Delegation, Manifest aus Vorlagen, Mitgliedsausweis, Stufen,
  Siegel, Widerruf, Sperren, Transparenz-Log (Merkle, Zeugen, Gossip); Dienste `gateway` (Empfänger) und `watch`
  (Wächter).
- `transport`: LAN (mDNS + TLS-Pinning) – Netz funktioniert im Heimnetz auch ohne Internet.
- Mehrere Knoten im Netz, Weiterleitung zum Heim-Empfänger, Beitritt per Link/QR.
- BridgeControll v2: Assistent „Neues BridgeNet“, Knoten anlegen, Owner-Dashboard.
- **Abnahme**: Netz per Klick erstellt, zweiter PC tritt per Link bei, Siegel vergeben/entzogen wirkt im ganzen Netz
  unter 60 s, gefälschtes Manifest/Siegel wird erkannt; ein Log-Führer, der zwei verschiedene Log-Versionen zeigt,
  wird entlarvt und abgesetzt; zwei PCs im selben WLAN reden ohne Internet.

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
