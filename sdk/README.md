# sdk – Client-Bibliotheken

Sie sprechen nur das Protokoll (`docs/04_PROTOKOLL_V4.md`) und dürfen in eigene Projekte eingebaut werden.

- `rust/` (Crate `bridge-sdk`, seit Phase 2): anmelden (inkl. Proof-of-Work), Karten holen, senden, empfangen
  (prüfen, öffnen, Doppelte verwerfen, bestätigen). `Client::with_seen_file` hält den Replay-Schutz über Neustarts.
  Seit Phase 3: `Client::join(identität, link)` tritt einem Netz per Link bei (prüft Netz und Empfänger, löst PoW,
  Einladungscode); jedes `connect` meldet den Knoten als Heim-Empfänger (`home`). Senden an Mitglieder anderer
  Empfänger klappt ohne Zutun – die Empfänger leiten weiter.
  LAN vor Internet: `Client::connect_auto(identität, NodeAddress { node, tls, url }, ConnectOptions)` und `join` mit
  einem Link mit `node` + `tls` suchen den Knoten zuerst per mDNS und verbinden sich nur mit dem gepinnten
  Zertifikat; sonst die Internet-Adresse (`Client::via_lan()` zeigt den Weg, docs/06 §2).
- Ab Phase 6: Python, JavaScript/TypeScript, Java, Luau.
