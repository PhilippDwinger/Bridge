# apps – Programme für Menschen

- `bridgecontroll/` – **BridgeControll v2** (ADR 0017): Rust-Programm, Oberfläche auf 127.0.0.1 im Standard-Browser
  (Tauri-/Tray-Hülle später): Assistent „Neues BridgeNet“, Beitritt per Link, ein Prozess pro Knoten mit Watchdog,
  Owner-Dashboard. Ab Phase 3.
  - `src/` Rust (Steuer-API, Knoten-Prozesse, Status, Sicherheit), `ui/` Bildschirme (nach den freigegebenen Entwürfen
    N01–N04, ins Programm eingebaut), `tests/` (Rust-Tests mit echten Knoten-Prozessen, `tests/ui/smoke.py` mit
    Playwright).
  - `design/` gehört dem Design-Claude – nicht ändern, nur an `design/FRAGEN.md` anhängen.
- `browser/` – Bridge-Browser (Web-App) für die Empfänger-Websites. Ab Phase 4.
