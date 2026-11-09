# 03 – Architektur und Abteile

## 1. Überblick
```
           Clients (Spiele, Bots, Websites, Apps, KIs)  ── SDKs: Python · JavaScript · Java · Luau
                 │  HTTPS, nur der Client fragt (pull-only)
                 ▼
   ┌──────────── Knoten (ein Prozess pro Knoten, viele PCs pro Netz) ────────────┐
   │  Dienste (Plugins): Empfänger · Wächter · DNS/Suche · Speicher · Rechnen ·  │
   │                     Web · Postfach · KI · Brücke …                          │
   │  ─────────────────────────────────────────────────────────────────────────  │
   │  node   – Laufzeit, Sitzungen, Weiterleitung, Plugin-Host (WASM-Sandbox)    │
   │  net    – Netz: Manifest, Mitglieder, Stufen, Siegel, Delegation, Log      │
   │  transport – Internet (HTTPS) · LAN (mDNS + TLS) · später QUIC/WebRTC       │
   │  guard  – jede Anfrage: Rechte, Limits, Proof-of-Work, Ruf                  │
   │  store  – Persistenz (SQLite), Migrationen                                  │
   │  core   – Formate, Krypto-Suite, Identität, Umschlag, Fehler (ohne I/O)     │
   └─────────────────────────────────────────────────────────────────────────────┘
                 ▲
     Apps: BridgeControll (Netz erstellen, Knoten/Dienste per Klick) · Browser · Owner-Dashboard
```

## 2. Abteile
| Abteil | Aufgabe | Besitzt | Darf benutzen |
|---|---|---|---|
| `core` | Datentypen, kanonisches JSON, Krypto-Suite B4-1, Identität/Schlüsselkarte, Umschlag bauen/öffnen/prüfen, Adressen, Fehler-Codes, Zeit | nichts (reine Funktionen) | nur Standardbibliothek + Krypto-Bibliotheken |
| `store` | Speichern und Laden (SQLite, WAL), Migrationen, Datei-Ablage für große Blobs | Datenbank-Dateien eines Knotens | `core` |
| `guard` | Zentrale Prüfung **jeder** Anfrage: Wer ist das, was darf er, Limits, Kontingente, Proof-of-Work, Ruf | Zähler, Ruf-Werte (über `store`) | `core`, `store` |
| `transport` | Verbindungen: Internet (HTTPS-Server/-Client), LAN (mDNS-Suche, TLS mit Schlüssel-Pinning), später weitere; liefert nur Bytes/Umschläge, kennt keine Netz-Logik | offene Verbindungen | `core` |
| `net` | Netz-Logik: Manifest, Mitgliedsausweise, Stufen, Siegel, Delegationen, Widerrufe, Transparenz-Log (Merkle, Zeugen) | Netz-Zustand (über `store`) | `core`, `store`, `guard` |
| `node` | Laufzeit eines Knotens: Sitzungen, Postfächer, Weiterleitung zwischen Knoten, Plugin-Host (Sandbox), Gesundheit | Laufzeit-Zustand | alle darunter |
| `services/*` | Je Dienst-Art ein Plugin: `gateway` (Empfänger), `watch` (Wächter), `names` (DNS + Suche), `storage`, `compute`, `web`, `mailbox`, `ai`, `bridge` (zu anderen Netzen) | eigene Daten (über die Plugin-Schnittstelle) | nur die **Plugin-API** von `node` + `core` |
| `sdk/*` | Client-Bibliotheken je Sprache | – | nur das Protokoll (Doku 04) |
| `apps/*` | BridgeControll, Browser, Dashboard | eigene Einstellungen | SDK + Knoten-Admin-API |

**Regeln**
- Abhängigkeiten nur nach unten (Tabelle). Jedes Abteil ist ein eigenes Rust-Crate – der **Compiler** verbietet
  Abhängigkeiten nach oben (ein Crate kann nur nutzen, was in seiner `Cargo.toml` steht).
- Plugins sehen nur die Plugin-API, nie Interna von `node`, `net`, `store`.
- `core` hat kein I/O, keine Zeitabfrage ohne Übergabe, keinen Zufall ohne Übergabe → komplett testbar.
- Kein globaler Zustand (S3): Alles hängt an einem `Node`-Objekt. Tests starten mehrere Knoten in einem Prozess.

## 3. Repo-Struktur (Branch `bridge-4`)
```
LICENSE                 PolyForm Shield 1.0.0 + Required Notice
README.md               Was ist Bridge, Schnellstart
CLAUDE.md               Arbeitsregeln (Grundsätze, Abteile, Tests) für Claude
Cargo.toml              Rust-Workspace (alle Crates)
docs/                   00–05 + adr/ (Entscheidungen)
crates/                 ein Crate pro Abteil
  bridge-core/  bridge-store/  bridge-guard/  bridge-transport/  bridge-net/  bridge-node/
  bridge-plugin-api/    Schnittstelle für Dienste (auch als WASM-Schnittstelle, WIT)
services/               ein Crate pro Kern-Dienst: gateway/ watch/ names/ storage/ compute/ web/ mailbox/ ai/ bridge/
bin/bridge-node/        das Programm eines Knotens (eine Datei, Windows/Linux/macOS)
sdk/                    rust/ python/ javascript/ java/ luau/
apps/
  bridgecontroll/       Desktop-App (Tauri: Rust + Web-Oberfläche): Netz-Assistent, Knoten & Dienste per Klick, Dashboard
  browser/              Bridge-Browser (Web-App, läuft auf Empfänger-Websites)
tests/                  übergreifende Tests: e2e/ (Crate bridge-tests: Abnahme + Angriffe), später chaos/
.github/workflows/      CI: Format, Lint, Tests auf Linux + Windows, Release-Builds
```

## 4. Laufzeit eines Knotens
- Ein Knoten = ein Prozess = eine Knoten-Identität (eigener Schlüssel) + eine SQLite-Datenbank + aktivierte Dienste.
- Ein PC kann viele Knoten haben (BridgeControll verwaltet sie). Ein Knoten kann in **mehreren Netzen** Mitglied
  sein; Zustand ist pro Netz getrennt.
- **Plugin-Manifest**: Name, Version, Herausgeber + Signatur, Dienst-Art, benötigte Fähigkeiten und Ressourcen,
  **Einstellungs-Schema** → BridgeControll baut daraus automatisch das Formular (ohne Programmieren).

### Plugin-Isolation (ein eigener Prozess allein ist keine Sandbox)
| Klasse | Wer | Wie isoliert |
|---|---|---|
| **Kern-Dienste** | von Paddy signiert (Empfänger, Wächter, Namen, Speicher …) | Rust-Crates im Knoten, gleiche Prüfungen über die Plugin-API; kein direkter Zugriff auf Schlüssel |
| **Fremde Plugins** | alle anderen | **WebAssembly-Komponente** in wasmtime: nur Fähigkeiten aus dem Manifest (bestimmter Ordner, keine Netzwerk-Sockets – Netz nur über die Plugin-API), Speicher- und Rechenzeit-Limit (Fuel/Epochen), Zeitlimit pro Aufruf |
| **Native Sonderfälle** | nur von Paddy signiert (z. B. KI mit GPU) | eigener Prozess mit Betriebssystem-Grenzen: Windows Job Objects (CPU/RAM/Kill-on-Close) + eingeschränktes Token; Linux eigener Benutzer + cgroups + Namespaces/seccomp; nur eigener Daten-Ordner |

- **Schlüssel**: Kein Plugin bekommt Schlüssel. Signieren/Entschlüsseln läuft über die Plugin-API, die prüft, ob das
  Plugin das darf (Z4).
- **Updates**: nur signierte Pakete (Hash + Herausgeber-Signatur), Rollout erst auf einem Teil der Knoten, automatische
  Rücknahme bei Fehlern; alte Version bleibt bis zur Bestätigung liegen.
- **Not-Aus**: Ein Widerruf „Plugin X Version Y“ im Netz-Log → alle Knoten stoppen es sofort, stellen seine Daten in
  Quarantäne und melden es dem Owner. Lokal: Watchdog beendet Plugins, die Limits reißen oder abstürzen.

## 5. Wichtige Abläufe (kurz)
**Netz erstellen** (BridgeControll-Assistent): Hauptschlüssel erzeugen → 24 Wörter anzeigen → Admin-Schlüssel
erzeugen und delegieren → Manifest aus Vorlage → erster Knoten mit Empfänger + Wächter + Namen → Einladungslink/QR.

**Beitreten**: Client öffnet Link (Netz-ID + Empfänger-Adressen) → holt Manifest + Log-Kopf vom Empfänger → prüft
alles bis zum Hauptschlüssel (= Netz-ID) → löst Proof-of-Work (+ ggf. Einladungscode) → bekommt Mitgliedsausweis
(Stufe 0).

**Nachricht senden**: Client baut Umschlag (verschlüsselt für den Empfänger-Client, signiert) → eigener Empfänger
prüft (guard) und leitet an den Heim-Empfänger des Ziels → Ziel-Client holt ab (Long-Poll), prüft Signatur, öffnet.

**Dienst aufrufen**: Name auflösen (DNS, signierte Einträge) → Anfrage-Umschlag an den Dienst → Antwort-Umschlag zurück.
Mehrere Anbieter → Auswahl nach Stufe, Ruf, Last (Erbe von BridgeAgent).

## 6. Persistenz
- Pro Knoten eine SQLite-Datenbank (WAL-Modus), Schema-Versionen mit Migrationen.
- Große Daten (Speicher-Dienst, Websites) als Dateien, adressiert über ihren SHA-256.
- Netz-Zustand (Manifest, Log, Siegel) ist auf mehreren Stufe-3-Knoten repliziert; jeder kann ihn prüfen.
- Ein Neustart verliert nichts Wichtiges. Nur flüchtige Dinge (offene Polls, Caches) liegen im RAM.

## 7. Technik (siehe ADR 0003)
| Bereich | Wahl | Grund |
|---|---|---|
| Knoten + Abteile | **Rust** (tokio) | Speichersicherheit ohne Garbage Collector, schnell genug für sehr große Netze, eine Programmdatei pro Betriebssystem (keine Python-Installation beim Nutzer), Abteile als Crates = Schichten vom Compiler erzwungen, wasmtime für die Plugin-Sandbox |
| HTTP / LAN | axum + rustls; mDNS-Crate | bewährt, kein OpenSSL nötig |
| Datenbank | SQLite (rusqlite, eingebaut) | keine Installation, robust, pro Knoten |
| Krypto | RustCrypto/dalek (`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`, `argon2`) | geprüft, reine Rust-Bibliotheken |
| Plugins | WebAssembly-Komponenten (wasmtime, WIT) | echte Sandbox, Plugins in vielen Sprachen schreibbar |
| Desktop-App | **Tauri** (Rust-Kern + Web-Oberfläche) | gleicher Kern wie der Knoten, kleine Programmdatei, Design-System (HTML/CSS) weiterverwendbar |
| Browser | Web-App (TypeScript) | läuft in jedem Browser, auf den Empfänger-Websites |
| SDKs | Rust, Python, JavaScript/TypeScript, Java, Luau | für jede Plattform, auf der Clients laufen |
| Qualität | cargo test, clippy (streng), rustfmt, `#![forbid(unsafe_code)]` in allen Abteilen, cargo-deny (Lizenzen/Sicherheitslücken der Abhängigkeiten), Fuzzing für Parser | |
| CI | GitHub Actions: Tests auf Linux und Windows, Release-Programme für Windows/Linux/macOS | Paddy braucht keine Rust-Installation |

## 8. Was aus Bridge 3 weiterlebt
| Bridge 3 | in Bridge 4 |
|---|---|
| Realms (public/protected/private, Codes, Rollen) | Netz-Arten, Einladungen, Rollen im Manifest |
| Commands + Host-Wahl | Dienste/Funktionen + Anbieter-Auswahl |
| BridgeExpress (Signaturen, Schemas) | Schnittstellen-Beschreibung der Dienste |
| BridgeAgent (Messung, beste Wege) | Ruf, Anbieter-Auswahl, Routing |
| Vertrauen/Mesh, Backup | Knoten-Verbund, Replikation |
| BridgeFriends | Kontakte über Netzgrenzen (später) |
| BridgeControll, /site, bridge.js | App, Web-Dienst, Browser-SDK |
| Long Polling, safe/compressed | Transport (Doku 04), Strom-Verschlüsselung für Großes |

Bridge 3 bleibt unverändert lauffähig; Bridge 4 spricht ein neues Protokoll (v4) und ist nicht kompatibel.
Eine Brücke für alte Clients ist möglich (Plugin), aber nicht geplant, bis sie gebraucht wird.
