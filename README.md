# Bridge 4

**Bridge** ist die Grundlage für **BridgeNet**: Jeder kann ohne Programmieren ein eigenes Netz erstellen – ein
„Internet im Internet“. Viele PCs bieten darin Dienste an (Websites, Speicher, Rechnen, KI …), Clients nutzen sie von
überall – auch im Heimnetz ohne Internet. Sicher nach dem Zero-Trust-Prinzip: Inhalte sind Ende-zu-Ende
verschlüsselt, alles Wichtige ist signiert, niemand muss einem einzelnen Knoten vertrauen.

> Status: **Phase 3 – BridgeNet in Arbeit, Phase 4a (Dateien und Apps) gebaut.** Ein Knoten nimmt Ende-zu-Ende
> verschlüsselte Nachrichten an, hält sie bis zur Abholung (auch über Neustarts) und kann sie nicht lesen. Mehrere
> Knoten bilden ein Netz mit Transparenz-Log, Mitgliedern, Siegeln und Weiterleitung zwischen Empfängern – auch im LAN
> ohne Internet, per Klick mit BridgeControll v2 oder per Kommandozeile. Dateien werden nach Inhalt übertragen (geprüft, von mehreren Hosts
> zugleich); Bridge-Apps laufen auf mehreren Hosts und im Browser abgeschottet.
> Die laufende Version für Spiele und Bots ist weiterhin Bridge 3 (Branch `bridge-3`).

## BridgeControll v2 (Netze per Klick)
Die Desktop-App für Bridge 4 (`apps/bridgecontroll`, ADR 0017). Starten:
```
bridgecontroll                     # Windows: Doppelklick auf bridgecontroll.exe (CI-Artefakt)
bridgecontroll --data <ordner>     # anderer App-Ordner; --port 7380, --no-browser
```
Der Standard-Browser öffnet sich mit einem Einmal-Anmelde-Link (er steht auch in der Ausgabe); die Oberfläche läuft
nur auf `127.0.0.1`. Ein zweiter Start öffnet nur den Browser der laufenden App. Beenden: „Beenden“ unten links (die
Knoten werden sauber gestoppt). Darin:
- **Neues BridgeNet**: Name und Art → die 24 Wörter (genau einmal, kurzer Test) → Erreichbarkeit (Port, LAN,
  optional Tailscale-Adresse) → Einladungslink mit QR-Code. Der Owner-Knoten läuft dann.
- **Netz beitreten (Link)**: Link einfügen, Name, Erreichbarkeit – dieser PC bekommt einen eigenen Knoten.
- **Dashboard** eines Netzes: Knoten siegeln (Knoten dieses PCs direkt; andere PCs schicken ihren **Knoten-Ausweis**
  und du vergleichst die ersten 12 Zeichen der ID mit ihrem Bildschirm), Siegel entziehen, Mitglieder sperren,
  Einladungen, Apps, Transparenz-Log.
- Jeder Knoten läuft als eigener Prozess (`bridgecontroll node …`) mit Neustart nach Abstürzen; Einstellungen,
  Protokoll und Löschen über „⋯“. „Mit Windows starten“ unten links (aus, bis du es einschaltest).
- **Adressen anderer Knoten** (Einstellungen je Knoten): welche Adressen der Knoten anruft, die ein anderer Knoten
  selbst gewählt hat – „Öffentlich“, „Öffentlich + Tailnet“ (**Standard** in BridgeControll: dazu die Tailscale-Bereiche
  100.64.0.0/10 und fd7a:115c:a1e0::/48, nötig, wenn die Knoten sich über Tailscale erreichen) oder „Alle (unsicher)“
  (auch Heimnetz und dieser PC). Siehe `docs/06_BRIDGENET.md` §2 „Adress-Schutz“.

App-Ordner: `%APPDATA%\BridgeControll2` (Windows) bzw. `~/.local/share/bridgecontroll2` – darin `nodes/<id>/` je
Knoten (Schlüssel, Datenbank; der Owner-Ordner hat `admin-key.json`), `logs/`, `backup/` (gelöschte Knoten). Die alte
BridgeControll (Python) bleibt für Bridge-3-Server. UI-Rauchtest: `python3 apps/bridgecontroll/tests/ui/smoke.py`.

## Knoten starten
```
bridge-node --data <ordner> --listen 127.0.0.1:7400 --name "Mein Knoten"
```
Hinter Tailscale Funnel zusätzlich `--trust-proxy 127.0.0.1` (sonst zählen alle Nutzer als eine Adresse).
`--peer-addresses public|tailnet|any`: welche Adressen der Knoten anruft, die andere Knoten selbst gewählt haben
(Anmeldungen beim Wächter, Karten, die nur ein Wächter gesiegelt hat). Standard `public` (nur öffentliche IPs);
`tailnet` erlaubt zusätzlich Tailscale (100.64.0.0/10, fd7a:115c:a1e0::/48) – im eigenen Tailnet löst MagicDNS
`*.ts.net` zu 100.x auf; `any` prüft nichts (nur LAN-Netze, Tests). `--join-net-file <datei>` statt `--join-net <link>`
hält den Einladungscode aus der Prozessliste.
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

## Bridge-Apps (Phase 4a, Kommandozeile)
```
bridge-node net seal --data netz1 --node-url https://<pc>.ts.net:8443/k1 --node-id <owner-id> --level 3 \
                     --services gateway,log,witness,web                          # Owner-Knoten wird Host
bridge-node net seal --data netz1 --node-url https://<pc2>.ts.net:8443/k2 --node-id <id> --services gateway,web
bridge-node app create  --data netz1 --name "Mein Spiel"                         # zeigt die App-ID
bridge-node app publish --data netz1 --app <app-id> --folder ./spiel --host <owner-id> --host <id>
bridge-node app hosts   --data netz1 --app <app-id> --remove <id>                # neue Version ohne diesen Host
```
Die Befehle laufen im Ordner des Owner-Knotens (mit `admin-key.json`): Der App-Schlüssel liegt in
`netz1/apps/<app-id>.json` (nie auf einen Host kopieren), der Owner ist `netz1/owner-key.json` (wird beim ersten Mal
angelegt und als Mitglied aufgenommen). Hosts brauchen ein Siegel mit Dienst `web`; veröffentlicht wird beim ersten
Host, der auch Empfänger ist, die anderen holen sich die Version selbst. Die App läuft dann unter
`https://<host>/app/<app-id>/` in einer abgeschotteten Herkunft. Details: `docs/07_APPS_UND_DATEIEN.md`.

- Doku: [docs/](docs/README.md)
- Aufbau: Rust-Workspace, ein Crate pro Abteil (`crates/`), Dienste (`services/`), Programm (`bin/bridge-node`),
  SDKs (`sdk/`), Apps (`apps/`, darin `bridgecontroll`).
- Bauen und testen: `cargo test --workspace`
- Lizenz: [PolyForm Shield 1.0.0](LICENSE) – Nutzung in eigenen Projekten erlaubt (auch kommerziell), aber kein
  Produkt, das mit Bridge konkurriert. Die Client-Bibliotheken (`sdk/`) dürfen in eigene Projekte eingebaut werden.
