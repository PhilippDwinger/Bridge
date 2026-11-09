# Bridge 4

**Bridge** ist die Grundlage für **BridgeNet**: Jeder kann ohne Programmieren ein eigenes Netz erstellen – ein
„Internet im Internet“. Viele PCs bieten darin Dienste an (Websites, Speicher, Rechnen, KI …), Clients nutzen sie von
überall – auch im Heimnetz ohne Internet. Sicher nach dem Zero-Trust-Prinzip: Inhalte sind Ende-zu-Ende
verschlüsselt, alles Wichtige ist signiert, niemand muss einem einzelnen Knoten vertrauen.

> Status: **Phase 3 – BridgeNet in Arbeit.** Ein Knoten nimmt Ende-zu-Ende verschlüsselte Nachrichten an, hält sie
> bis zur Abholung (auch über Neustarts) und kann sie nicht lesen. Mehrere Knoten bilden ein Netz mit
> Transparenz-Log, Mitgliedern, Siegeln und Weiterleitung zwischen Empfängern – auch im LAN ohne Internet (noch ohne
> BridgeControll v2).
> Die laufende Version für Spiele und Bots ist weiterhin Bridge 3 (Branch `bridge-3`).

## Knoten starten
```
bridge-node --data <ordner> --listen 127.0.0.1:7400 --name "Mein Knoten"
```
Hinter Tailscale Funnel zusätzlich `--trust-proxy 127.0.0.1` (sonst zählen alle Nutzer als eine Adresse).
`--pow-bits 0-28` verlangt immer Proof-of-Work bei der Anmeldung (Standard: nur unter Last).

**Im LAN (auch ohne Internet):** `--lan 7443` – der Knoten lauscht zusätzlich per TLS auf `0.0.0.0:7443`, kündigt
sich per mDNS an und zeigt beim Start den Fingerabdruck seines Zertifikats. Das Zertifikat liegt in
`<ordner>/node-tls.pem` (geheim, nicht löschen – sein Fingerabdruck steht in Siegeln und Links). Einladungslinks
(`net invite`) enthalten dann `node` und `tls`: Clients im selben WLAN finden den Knoten darüber auch ohne Internet.
Unter Windows muss die Firewall den Port und mDNS (UDP 5353) im privaten Netz erlauben.
Das Programm für Windows/Linux baut die CI (GitHub Actions → Artefakte).

## Eigenes Netz (Phase 3, Kommandozeile)
```
bridge-node net create --data netz1 --name "Mein Netz" --url https://<pc>.ts.net:8443/k1 [--template invite]
bridge-node --data netz1 --listen 127.0.0.1:7400 --trust-proxy 127.0.0.1 --lan 7443   # Owner-Knoten
bridge-node --data k2 --listen 127.0.0.1:7401 --url https://<pc2>.ts.net:8443/k2 --lan 7443 --join-net "<link>"
bridge-node net seal --data netz1 --node-url https://<pc2>.ts.net:8443/k2 --node-id <id> --services gateway
bridge-node net invite --data netz1 --uses 5                                      # Link für Clients
```
`net create` zeigt die 24 Wiederherstellungs-Wörter genau einmal – aufschreiben! `net seal` braucht die ID, die k2
beim Start anzeigt (`--node-id`), sonst siegelt es nichts. k2 läuft beim Siegeln schon mit `--lan`, damit andere
Knoten ihn im LAN erkennen. Details: `docs/06_BRIDGENET.md` §2 und §10.

- Doku: [docs/](docs/README.md)
- Aufbau: Rust-Workspace, ein Crate pro Abteil (`crates/`), Dienste (`services/`), Programm (`bin/bridge-node`),
  SDKs (`sdk/`), Apps (`apps/`).
- Bauen und testen: `cargo test --workspace`
- Lizenz: [PolyForm Shield 1.0.0](LICENSE) – Nutzung in eigenen Projekten erlaubt (auch kommerziell), aber kein
  Produkt, das mit Bridge konkurriert. Die Client-Bibliotheken (`sdk/`) dürfen in eigene Projekte eingebaut werden.
