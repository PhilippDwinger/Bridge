# sdk – Client-Bibliotheken

Sie sprechen nur das Protokoll (`docs/04_PROTOKOLL_V4.md`) und dürfen in eigene Projekte eingebaut werden. Alle
bestehen die gemeinsamen Testvektoren `vectors/vectors.json` (vom Rust-Kern erzeugt, docs/10 §2.2) und einen
Live-Test gegen einen echten Knoten mit Rust-Echo-Client (`cargo build -p bridge-tests --bin sdk-fixture`).

| Sprache | Ordner | Krypto | Tests |
|---|---|---|---|
| Rust | `rust/` (Crate `bridge-sdk`) | `bridge-core` | `cargo test` |
| Python ≥ 3.9 | `python/` (Paket `bridge4`) | `cryptography` | `python -m unittest discover -s tests` |
| JavaScript (Node ≥ 20, Browser) | `javascript/` (`bridge4.js`) | noble, eingebettet mit Prüfsumme | `node --test` |
| Java ≥ 17 | `java/` (`net.bridge4`) | nur JDK | `./run_tests.sh` |
| Luau (Roblox-Server, Lune) | `luau/` | Port von TweetNaCl + RFC (Restrisiko R1) | `tests/run_tests.sh` |

Gemeinsam: Identität und Schlüsseldatei, Beitritt per Link (prüft Netz, Gründungs-Manifest, Empfänger im Log, PoW,
Einladungscode), Karten, Senden, Empfangen (prüfen, öffnen, Doppelte verwerfen, bestätigen), Aufgabe/Antwort
(`request`, z. B. für den KI-Dienst), Agenten-Ausweise (`issue_agent`, Anmelden als Agent, `agent_of`), verbundene
Netze (`net`-Parameter). Nur Rust: LAN (mDNS, gepinntes TLS), Ströme, Dateien/Apps/Speicher/Rechnen.
