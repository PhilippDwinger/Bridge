# ADR 0005 – Plugin-Isolation

- **Status**: angenommen (09.11.2026; Hinweis aus der ChatGPT-Prüfung: „ein eigener Prozess ist noch keine Sandbox“)
- **Entscheidung**:
  - Kern-Dienste sind von Paddy signierte Rust-Crates.
  - **Fremde Plugins** laufen nur als WebAssembly-Komponente in wasmtime: nur Fähigkeiten aus dem Manifest, kein
    direkter Netz-/Dateizugriff außerhalb des eigenen Ordners, Speicher- und Rechenzeit-Limits.
  - Native Sonderfälle (z. B. GPU-KI) nur mit Signatur von Paddy, in eigenem Prozess mit Betriebssystem-Grenzen:
    Windows Job Objects + eingeschränktes Token, Linux cgroups/Namespaces/seccomp.
  - Kein Plugin hat Zugriff auf Schlüssel.
  - Updates sind signiert und werden gestaffelt ausgerollt; bei Problemen werden sie zurückgerollt.
  - Not-Aus über einen Widerruf im Netz-Log, mit Quarantäne der Plugin-Daten.
- **Folgen**: Fremde Plugins müssen nach WASM kompilieren (Rust, Go, TS, C, Python über componentize-py …).
