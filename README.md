# Bridge 4

**Bridge** ist die Grundlage für **BridgeNet**: Jeder kann ohne Programmieren ein eigenes Netz erstellen – ein
„Internet im Internet“. Viele PCs bieten darin Dienste an (Websites, Speicher, Rechnen, KI …), Clients nutzen sie von
überall – auch im Heimnetz ohne Internet. Sicher nach dem Zero-Trust-Prinzip: Inhalte sind Ende-zu-Ende
verschlüsselt, alles Wichtige ist signiert, niemand muss einem einzelnen Knoten vertrauen.

> Status: **Phase 3 – BridgeNet in Arbeit, Phase 4a (Dateien und Apps) und der Kern von Phase 4 (Namen, Suche,
> Browser über den eigenen Knoten, Missbrauchsschutz) gebaut.** Ein Knoten nimmt Ende-zu-Ende
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
- **Neues BridgeNet**: Name und Art, dazu als Betreiber dein **Meldeweg** (Pflicht, z. B. eine E-Mail-Adresse), der
  **Kurzname** für Adressen (`shop.<kurzname>`, aus dem Namen vorgeschlagen) und ob Inhalte ab 18 erlaubt sind
  (Standard: nicht erlaubt) → die 24 Wörter (genau einmal, kurzer Test) → Erreichbarkeit (Port, LAN, optional
  Tailscale-Adresse) → Einladungslink mit QR-Code. Der Owner-Knoten läuft dann.
- **Netz beitreten (Link)**: Link einfügen, Name, Erreichbarkeit – dieser PC bekommt einen eigenen Knoten.
- **Dashboard** eines Netzes: Knoten siegeln (Knoten dieses PCs direkt; andere PCs schicken ihren **Knoten-Ausweis**
  und du vergleichst die ersten 12 Zeichen der ID mit ihrem Bildschirm), Siegel entziehen, Mitglieder sperren,
  Einladungen, Apps, Transparenz-Log. Dazu **Namen** (anmelden für eine App, den Owner-Knoten oder dich, widerrufen),
  **Meldungen** der Mitglieder (lesen, erledigen, Schnell-Aktionen: als 18+ kennzeichnen, App sperren, Namen
  widerrufen – jeweils mit Bestätigung) und der Hinweis „Meldeweg fehlt“ bei älteren Netzen (mit „Meldeweg eintragen“).
- **Bridge-Browser** (Startseite und Dashboard, docs/08 §12): Adresse `shop.meinnetz` eingeben oder suchen
  (**Sicherer Modus** an: keine 18+-Inhalte, keine Namen neuer Inhaber). Vor dem Öffnen zeigt ein „Schloss“, was dein
  Knoten geprüft hat (Netz-Name und ID-Fingerabdruck, Stufe des Inhabers, Meldeweg, Kennzeichnung, Warnungen auf
  Deutsch). Die App läuft in einem abgeschotteten `iframe` (Sandbox ohne `allow-same-origin`), geladen vom **Leser
  deines eigenen Knotens** (`http://127.0.0.1:<port>`), der jede Datei selbst prüft; „In neuem Tab öffnen“ geht auch.
  **Melden** schickt eine Meldung an die Admins des Netzes (signiert mit dem Mitglieds-Schlüssel dieses PCs). Der
  Leser je Knoten in den Einstellungen: „Aus“, „Nur dieser PC“ (Standard), „Heimnetz (LAN)“; ein Knoten mit
  öffentlicher Adresse öffnet keine Apps (er vertraut dem Tailscale-Proxy auf diesem PC).
- Jeder Knoten läuft als eigener Prozess (`bridgecontroll node …`) mit Neustart nach Abstürzen; Einstellungen,
  Protokoll und Löschen über „⋯“. „Mit Windows starten“ unten links (aus, bis du es einschaltest).
- **Adressen anderer Knoten** (Einstellungen je Knoten): welche Adressen der Knoten anruft, die ein anderer Knoten
  selbst gewählt hat – „Öffentlich“, „Öffentlich + Tailnet“ (**Standard** in BridgeControll: dazu die Tailscale-Bereiche
  100.64.0.0/10 und fd7a:115c:a1e0::/48, nötig, wenn die Knoten sich über Tailscale erreichen) oder „Alle (unsicher)“
  (auch Heimnetz und dieser PC). Siehe `docs/06_BRIDGENET.md` §2 „Adress-Schutz“.

App-Ordner: `%APPDATA%\BridgeControll2` (Windows) bzw. `~/.local/share/bridgecontroll2` – darin `nodes/<id>/` je
Knoten (Schlüssel, Datenbank; der Owner-Ordner hat `admin-key.json`), `logs/`, `backup/` (gelöschte Knoten). Die alte
BridgeControll (Python) bleibt für Bridge-3-Server. UI-Rauchtest: `python3 apps/bridgecontroll/tests/ui/smoke.py`.

## Öffentlich machen (Phase 7, docs/11)

Im Netz-Dashboard von BridgeControll v2 unter **„Öffentlich“** → **„Öffentlich machen“**: Websites und Apps des Netzes
sind dann für alle im Internet erreichbar – über Tailscale Funnel, kostenlos. Alle Netze eines PCs teilen sich **einen**
Funnel-Port (Standard 443) über das **Tor**:

```text
https://<gerät>.<tailnet>.ts.net/bridge4/<netz>/                 Startseite des Netzes (öffentliche Websites)
https://<gerät>.<tailnet>.ts.net/bridge4/<netz>/web/<name>/      eine Website (mit Leiste: Netz, Name, Melden)
https://<gerät>.<tailnet>.ts.net/bridge4/<netz>/v4/…             der Knoten (Beitritt, SDKs, andere Knoten)
```

Jede Website im Dashboard hat dann den Knopf **„Öffentlich“** (die öffentliche Adresse mit Bridge Login); eigene
Websites lassen sich mit **„Löschen“** im ganzen Netz entfernen (endgültig, die Adresse wird frei; Kommandozeile:
`bridge-node app delete`).

**Ein PC eines Mitglieds** (eigene BridgeControll, eigenes Tailscale) macht seinen Knoten unter „Übers Internet“ → „Erreichbar machen“ aus dem
Internet erreichbar – dann kann er dem Netz auch außerhalb des Heimnetzes helfen, z. B. als zweiter Speicher-Knoten.
Danach den Knoten-Ausweis an den Owner schicken, der siegelt ihn damit neu. Websites zeigt so ein Knoten erst mit
Stufe 3.

Voraussetzung: Tailscale installiert und angemeldet, Funnel im Tailnet erlaubt. BridgeControll setzt nur den Pfad
`/bridge4` (Einträge von BridgeControll 3 bleiben). **„Websites aus“** ist der Not-Aus (sofort), **„Nicht mehr
öffentlich“** nimmt alles zurück. Netze, die 18+ erlauben, werden nie öffentlich; öffentlich sind nur Apps von Inhabern
ab Stufe 2.

**Bridge-3-Server im Netz** (docs/11 §8): Bridge 4 hat keine eigenen Realms – im Owner-Dashboard unter
**„Bridge-3-Server“** läuft echter Bridge-3-Code (Realms, Topics, Commands, Friends) mit dem Python des PCs. Einmal den
Bridge-3-Ordner einstellen (Branch `bridge-3`), dann „Bridge-3-Server hinzufügen“ (ID, Name, Passwort). Ist das Netz
öffentlich, ist der Server unter `https://<gerät>.<tailnet>.ts.net/bridge4/<netz>/bridge3/<id>` erreichbar – diese
Adresse kommt in die Bridge-3-Extensions (Roblox, Minecraft, Python, JS).

**Was kann mein Netz? und Bridge Login** (docs/11 §9): Das Owner-Dashboard zeigt als Ampel, welche Features das Netz
mit seinen Knoten schafft (Nachrichten, Websites, Speicher, Rechnen, Login, Wächter). **„Login hier einschalten“** macht
den öffentlichen Owner-Knoten zusätzlich zum Speicher-Knoten: Besucher legen dann in der Leiste jeder Website ein Konto
mit **Passkey** an (ohne Passwort, ohne E-Mail, Wiederherstellungs-Code zum Aufschreiben). Mit einem zweiten
Speicher-Knoten (anderer PC, beim Siegeln „Speicher“ ankreuzen) wird die Ampel grün und die Konten liegen doppelt.
**Weitere Geräte** (docs/11 §14): angemeldet auf „Geräte“ → „Gerät hinzufügen“ zeigt einen Code (und QR-Code); auf dem
Handy dieselbe Website öffnen → Anmelden → „Verbinden“, Code eingeben, eigenen Passkey anlegen, auf beiden Geräten
dieselbe Prüfzahl vergleichen und am ersten Gerät bestätigen. Dort lassen sich Geräte auch wieder entfernen.
Eine App fragt die Leiste per `postMessage` und bekommt eine Nutzer-ID nur für sich plus ein Zeichen für ihren
Server-Code:

```js
parent.postMessage({ bridge: "login", ask: true }, "*"); // ask: true öffnet das Anmelde-Fenster
window.addEventListener("message", (event) => {
  if (event.data && event.data.bridge === "login" && event.data.user) {
    // event.data.user, .name; für den Server-Code: fetch("api/…", { headers: { "X-Bridge-Login": event.data.token } })
  }
});
```

**BridgeControll aktualisiert sich selbst** (docs/12): neue Versionen kommen von GitHub, aber nur mit Paddys
Unterschrift (Größe und SHA-256 in `releases/bridgecontroll.json`). Standard: automatisch – die Knoten sind dafür ein
paar Sekunden aus; startet die neue Version nicht, kommt die alte zurück. Unten im Dashboard: „Automatisch
aktualisieren“ und „Nach Updates suchen“. Veröffentlichen: Tag `bc-v<version>` pushen, dann
`bridge-node release sign …` und die Datei committen (docs/12 §6).

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

## Namen, Suche, Melden (Phase 4, Kommandozeile)
```
bridge-node net create --data netz1 --name "Mein Netz" --url https://<pc>.ts.net:8443/k1 --contact abuse@example.org \
                       --short meinnetz                                          # Meldeweg ist Pflicht
bridge-node name register --data netz1 --name shop --app <app-id> --tags laden,kleidung   # → shop.meinnetz
bridge-node name list   --data netz1
bridge-node net label   --data netz1 --target <name|app-id> --category adult     # Kennzeichnung (Recht seals)
bridge-node net reports --data netz1                                             # Meldungen der Mitglieder
bridge-node blocklist key --key herausgeber.json                                 # Sperrlisten (docs/08 §9)
bridge-node net blocklists --data netz1 --set <herausgeber-id>
bridge-node blocklist publish --key herausgeber.json --net <netz-id> --file liste.txt --version 1 --node <adresse>
```
Namen stehen im Transparenz-Log: wer zuerst kommt, ab Stufe 1, begrenzt je Stufe, Schutz vor verwechselbaren Namen
(`sh0p` neben `shop`) und reservierten Wörtern (Bank, Login, PayPal …, erst ab Stufe 3). Jeder Knoten löst Namen aus
seinem eigenen Log auf (`/v4/names/resolve`, `/v4/names/search`) und lädt Apps anderer Hosts als **Leser** für den
Browser seines Besitzers – nur lokal, jeder Teil geprüft (`--reader off|local|lan`). Details: `docs/08_NAMEN_WEB_BROWSER.md`.

## SDKs, KI, Agenten, Netze verbinden (Phase 6, docs/10)
- **SDKs** für Rust, Python, JavaScript (Node + Browser), Java und Luau (Roblox-Server): [sdk/](sdk/README.md) – alle
  bestehen dieselben Testvektoren aus dem Rust-Kern.
```
bridge-node agent issue --owner-key ich.json --agent-key ki.json --node-url <adresse> --to <id> --days 7 --out ausweis.json
bridge-node agent revoke --owner-key ich.json --node-url <adresse> --agent <agent-id>      # Agent sofort sperren
bridge-node ai --key ki.json --join <link> --model llama3.2 --allow-members yes            # KI-Dienst (Ollama auf diesem PC)
bridge-node net federate   --data netz1 --peer <netz-id> --gateway https://<empfänger des anderen netzes>
bridge-node net unfederate --data netz1 --peer <netz-id>                                  # beide mit den 24 Wörtern
```
Agenten (KIs, Bots) bekommen einen **eigenen** Ausweis mit wenigen Rechten (senden/empfangen, nur an bestimmte
Empfänger, Rate, höchstens 30 Tage) statt des Schlüssels ihres Besitzers. Der KI-Dienst fragt nur ein Modell **auf
diesem PC** (Ollama oder OpenAI-kompatibel, nur Loopback) – gratis, die Fragen verlassen den PC nicht. Netze verbinden
sich nur, wenn **beide** Owner es tun; dann schreiben sich ihre Mitglieder Ende-zu-Ende verschlüsselt.

**Nutzungsregeln** (Entwurf): [NUTZUNGSREGELN.md](NUTZUNGSREGELN.md) – wer ein Netz erstellt, ist dessen Betreiber und
verantwortlich; Nachrichten bleiben Ende-zu-Ende verschlüsselt und werden nie durchsucht.

- Doku: [docs/](docs/README.md)
- Aufbau: Rust-Workspace, ein Crate pro Abteil (`crates/`), Dienste (`services/`), Programm (`bin/bridge-node`),
  SDKs (`sdk/`), Apps (`apps/`, darin `bridgecontroll`).
- Bauen und testen: `cargo test --workspace`
- Lizenz: [PolyForm Shield 1.0.0](LICENSE) – Nutzung in eigenen Projekten erlaubt (auch kommerziell), aber kein
  Produkt, das mit Bridge konkurriert. Die Client-Bibliotheken (`sdk/`) dürfen in eigene Projekte eingebaut werden.
  Zusätzlich gelten die [Nutzungsregeln](NUTZUNGSREGELN.md) (ändern die Lizenz nicht).
