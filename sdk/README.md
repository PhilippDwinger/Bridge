# sdk – Client-Bibliotheken

Sie sprechen nur das Protokoll (`docs/04_PROTOKOLL_V4.md`) und dürfen in eigene Projekte eingebaut werden.

- `rust/` (Crate `bridge-sdk`, seit Phase 2): anmelden (inkl. Proof-of-Work), Karten holen, senden, empfangen
  (prüfen, öffnen, Doppelte verwerfen, bestätigen). `Client::with_seen_file` hält den Replay-Schutz über Neustarts.
- Ab Phase 6: Python, JavaScript/TypeScript, Java, Luau.
