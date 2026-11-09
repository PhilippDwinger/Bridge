# tests – übergreifende Tests

Unit-Tests liegen in den Crates. Hier liegen Tests über mehrere Abteile:

- `e2e/` (Crate `bridge-tests`): Abnahme von Phase 2 (`tests/phase2_e2e.rs`: zwei Clients, Knoten kann nicht lesen,
  Long-Poll, Neustart) und Angriffe (`tests/phase2_attacks.rs`: gefälschte Signatur, verändertes Byte, Replay,
  abgelaufen, zu groß, 10.000 Anfragen/s, falsches PoW, fremde Identität, Kontingente, Müll-Eingaben …).
- Phase 3 (mehrere Knoten in einem Prozess, kurze Takte, Helfer in `src/net.rs`): `tests/phase3_net.rs` (Netz
  erstellen, Beitritt, Siegel, Weiterleitung, Widerruf, Einladungen, Sperren, PoW aus dem Manifest, gefälschte
  Aussagen, Split-View mit Beweis, Neustart) und `tests/phase3_attacks.rs` (Müll, Größen, falsches `aud`,
  Weiterleitung von Nicht-Empfängern/für Fremde/doppelt, Zeugen, Beweise). Gewartet wird immer mit Frist, nie fest.
  `tests/phase3_lan.rs`: LAN (nur TLS-Zugang, falscher Fingerabdruck, lügende Ankündigung, manipulierter Link,
  Beitritt ohne Internet, Neustart, kaputte `node-tls.pem`, zwei Empfänger nur über das LAN). Ohne Multicast finden
  sich Knoten über vorgegebene Adressen (`LanHints`); der echte mDNS-Test ist `#[ignore = "needs multicast"]`.
  Rückfall-Tests der Prüfungen: `tests/phase3_regressions.rs` (Prüfung 3) und `tests/phase3_review4.rs` (Prüfung 4:
  Müll-Quelle lädt und kopiert nichts, ungesiegelte Zeugen abgelehnt, Not-Wiederherstellung, Neu-Siegeln).
- Später: `chaos/` (Ausfälle, langsame Leitungen, falsche Uhren).

Ausführen: `cargo test --workspace` (alles) oder `cargo test -p bridge-tests`; Tests mit echtem Multicast (mDNS):
`cargo test --workspace -- --ignored` (CI: nur Ubuntu, Windows-Runner können Multicast sperren).
