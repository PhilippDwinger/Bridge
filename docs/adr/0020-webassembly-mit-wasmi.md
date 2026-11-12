# ADR 0020 – WebAssembly mit wasmi (Rechnen, Plugins, Server-Code von Apps)

- **Status**: angenommen (12.11.2026, von Claude entschieden – Paddy war weg; Freigabe steht aus). Ändert ADR 0005
  („wasmtime“) in diesem Punkt.
- **Kontext**: Fremder Code (Rechen-Aufträge, Plugins, Server-Code von Apps) darf nur in einer Sandbox laufen. ADR 0005
  nannte wasmtime.
- **Entscheidung**: **wasmi** (reiner Rust-Interpreter) statt wasmtime, in einem eigenen Abteil `crates/bridge-wasm`.
  - **Deterministisch**: Rechnen wird durch Nachrechnen geprüft (Stichproben, Wächter-Probe) – das braucht auf allen
    Knoten dieselben Ergebnisse. Ein Interpreter ohne JIT liefert das einfacher.
  - **Fuel** zählt Rechenschritte genau; Speicher über `StoreLimits`. Kein JIT = kleinere Angriffsfläche (keine
    ausführbaren Seiten, kein Code-Generator).
  - Reines Rust, baut ohne Zusätze auf Windows und Linux in der CI.
  - Preis: langsamer als JIT (Faktor 10–50). Für Phase 5 genug; ein JIT kann später für große Rechen-Knoten dazukommen
    (eigene ADR).
- **ABI**: einfache Kern-WebAssembly-Schnittstelle (`memory`, `alloc`, Einstieg `(ptr,len) -> i64`), Importe nur aus
  `bridge` je Fähigkeit (docs/09 §10). Kein Komponenten-Modell (später möglich).
- **Folgen**: `bridge-wasm` hängt nur von `bridge-core` ab; Knoten und Dienste nutzen es. Plugins gibt es vorerst nur
  als WebAssembly – native Plugins weiter nur mit Signatur von Paddy (ADR 0005).
