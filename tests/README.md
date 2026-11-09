# tests – übergreifende Tests

Unit-Tests liegen in den Crates. Hier liegen Tests über mehrere Abteile:

- `e2e/` (Crate `bridge-tests`): Abnahme von Phase 2 (`tests/phase2_e2e.rs`: zwei Clients, Knoten kann nicht lesen,
  Long-Poll, Neustart) und Angriffe (`tests/phase2_attacks.rs`: gefälschte Signatur, verändertes Byte, Replay,
  abgelaufen, zu groß, 10.000 Anfragen/s, falsches PoW, fremde Identität, Kontingente, Müll-Eingaben …).
- Später: `chaos/` (Ausfälle, langsame Leitungen, falsche Uhren), mehrere Knoten ab Phase 3.

Ausführen: `cargo test --workspace` (alles) oder `cargo test -p bridge-tests`.
