# ADR 0003 – Rust für Knoten und Abteile, Web für Oberflächen

- **Status**: angenommen (09.11.2026; Paddy: „Sprache egal, es soll optimal sein“)
- **Kontext**: Bridge 3 ist Python. Für BridgeNet zählen Sicherheit, Größe, einfache Verteilung an Nicht-Programmierer
  und eine echte Plugin-Sandbox. In Bridge 3/BridgeControll war die Python-Installation beim Nutzer eine Fehlerquelle
  (eigene venv neben der Exe).
- **Entscheidung**:
  - Knoten und alle Abteile in **Rust**. Jedes Abteil ist ein Crate, daher sind die Schichten vom Compiler erzwungen.
    In allen Abteilen gilt `forbid(unsafe_code)`.
  - BridgeControll als **Tauri**-App: Rust-Kern + Web-Oberfläche. Das Design-System bleibt nutzbar.
  - Browser und Oberflächen in Web-Technik (TypeScript).
  - SDKs in Rust, Python, JavaScript/TypeScript, Java und Luau.
  - Windows-, Linux- und macOS-Programme baut die CI (GitHub Actions).
- **Folgen**:
  - Kein Python mehr auf Nutzer-PCs nötig (eine Programmdatei).
  - wasmtime ist nativ verfügbar.
  - Speichersicherheit und Leistung für große Netze.
  - Paddy liest den Code seltener selbst; dafür gibt es ausführliche Doku und Tests.
  - Bridge 3 (Python) läuft weiter.
- **Nachtrag (11.11.2026, ADR 0017)**: BridgeControll v2 ist zuerst eine lokale Web-App (Rust-Programm, Oberfläche auf
  127.0.0.1 im Standard-Browser); die Tauri-/Tray-Hülle folgt später und nutzt dieselbe Oberfläche.
