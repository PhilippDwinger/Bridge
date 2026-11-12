# CLAUDE.md – Arbeitsregeln für Bridge 4

Zuerst lesen: `docs/00_GRUNDSAETZE.md` (Zero Trust Z1–Z10, Struktur S1–S6, Checkliste). Sie gelten für jede Änderung.

## Immer
- **Zero Trust**: jede Eingabe prüfen, alles Wichtige signieren, Inhalte Ende-zu-Ende verschlüsseln, überall
  Obergrenzen, kleinste Rechte, im Zweifel ablehnen. Krypto nur in `bridge-core` (Modul `crypto`), Invariante N1
  (ADR 0008).
- **Abteile = Crates**: `bridge-core` → `bridge-store` / `bridge-transport` → `bridge-guard` → `bridge-net` →
  `bridge-node` → `services/*` (z. B. `services/ai`, nur `bridge-plugin-api` + `bridge-core`); `bridge-wasm` (Sandbox,
  ADR 0020) hängt nur von wasmi ab. SDKs in `sdk/` (Rust, Python, JavaScript, Java, Luau) müssen die Testvektoren in
  `sdk/vectors` bestehen (ADR 0021). Abhängigkeiten nur nach unten; Dienste nur über `bridge-plugin-api`.
  Kein globaler Zustand. `#![forbid(unsafe_code)]` überall. `sdk/rust` nutzt nur `bridge-core` + `bridge-transport`;
  `tests/e2e` (Crate `bridge-tests`) testet über alle Abteile.
- Krypto-Bausteine nur über `bridge-core::crypto`; andere Module rufen die Krypto-Bibliotheken nie direkt auf.
  Einzige Ausnahme: TLS-Verbindungen im Abteil `transport` (rustls mit ring, rcgen; ADR 0011).
- **Spezifikation vor Code**: erst `docs/` ändern, dann bauen. Größere Entscheidungen als ADR in `docs/adr/`.
- **Tests**: jede Funktion mit normalen Tests **und** Angriffs-Tests; `cargo fmt`, `cargo clippy -- -D warnings`,
  `cargo test` müssen grün sein.
- Doku auf Deutsch, Code und Kommentare auf Englisch.

## Nie
- Eigene Krypto-Verfahren. Unbegrenzte Listen/Schleifen/Eingaben. Vertrauen in Daten anderer Knoten ohne Prüfung.
- `unsafe` (außer nach ADR). Panics bei fremden Eingaben – Fehler werden zurückgegeben.
- Ordner `Bridge2` ändern. `apps/bridgecontroll/design/` ändern (gehört dem Design-Claude; nur an `FRAGEN.md`
  anhängen).
- Pushen – das macht Paddy. Claude committet nur lokal.

## Projekt
- Repo `PhilippDwinger/Bridge`, Branch `bridge-4`, lokal `C:\Users\phili\Documents\Programmieren\Projekte\Bridge4`.
  Bridge 3 läuft auf `bridge-3` (Ordner `Bridge`) weiter, nur Fehlerbehebungen.
- Lizenz PolyForm Shield 1.0.0 (`LICENSE`).
- Fahrplan und Abnahme-Kriterien: `docs/05_FAHRPLAN.md`.
- Windows-Programme baut die CI (`.github/workflows/`); lokal auf Paddys PC ist kein Rust installiert.
