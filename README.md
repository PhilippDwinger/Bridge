# Bridge 4

**Bridge** ist die Grundlage für **BridgeNet**: Jeder kann ohne Programmieren ein eigenes Netz erstellen – ein
„Internet im Internet“. Viele PCs bieten darin Dienste an (Websites, Speicher, Rechnen, KI …), Clients nutzen sie von
überall – auch im Heimnetz ohne Internet. Sicher nach dem Zero-Trust-Prinzip: Inhalte sind Ende-zu-Ende
verschlüsselt, alles Wichtige ist signiert, niemand muss einem einzelnen Knoten vertrauen.

> Status: **Phase 1 – Spezifikation und Gerüst.** Noch keine Funktionen. Die laufende Version ist Bridge 3
> (Branch `bridge-3`).

- Doku: [docs/](docs/README.md)
- Aufbau: Rust-Workspace, ein Crate pro Abteil (`crates/`), Dienste (`services/`), Programm (`bin/bridge-node`),
  SDKs (`sdk/`), Apps (`apps/`).
- Bauen und testen: `cargo test --workspace`
- Lizenz: [PolyForm Shield 1.0.0](LICENSE) – Nutzung in eigenen Projekten erlaubt (auch kommerziell), aber kein
  Produkt, das mit Bridge konkurriert. Die Client-Bibliotheken (`sdk/`) dürfen in eigene Projekte eingebaut werden.
