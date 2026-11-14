# 12 – BridgeControll aktualisiert sich selbst, Owner-Backup (Phase 8, Schritte 4–5)

Stand 14.11.2026. Reihenfolge und Wünsche: docs/05 (Phase 8). Entscheidung: ADR 0029.

## 1. Ziel (Schritt 4)
Paddy und seine Freunde sollen nie mehr ein ZIP von Hand auspacken. BridgeControll findet neue Versionen selbst, lädt
sie, prüft **Paddys Unterschrift** und ersetzt sich – Knoten anderer veralten so nicht. Wer das Update nicht mag,
schaltet „automatisch“ aus und drückt den Knopf selbst.

## 2. Vertrauensanker: Paddys Veröffentlichungs-Schlüssel
- Ein Ed25519-Schlüssel nur für Veröffentlichungen. Der **private** Teil liegt nur auf Paddys PC (eine Datei, die er
  anlegt und sichert – nicht in GitHub, nicht in der Cloud, nicht in einem Ordner, den Claude liest). Der **öffentliche**
  Teil steht fest im Programm (`RELEASE_KEYS` in `bin/bridge-node/src/release.rs`, BridgeControll nimmt dieselbe Liste;
  mehrere erlaubt – für einen späteren Wechsel).
- Ohne eingetragenen Schlüssel ist das Selbst-Update aus („noch kein Update-Schlüssel“).
- Wer GitHub, die Verbindung oder die Release-Dateien manipuliert, kann **kein** Update unterschieben: das Programm
  nimmt nur Dateien, deren Größe und SHA-256 in einer von Paddy unterschriebenen Ankündigung stehen.
- Schlüssel verloren: ein neuer Schlüssel kommt mit einer Version, die man noch einmal von Hand installiert.

## 3. Die Ankündigung
Datei `releases/bridgecontroll.json` im Branch `bridge-4`, gelesen über
`https://raw.githubusercontent.com/PhilippDwinger/Bridge/bridge-4/releases/bridgecontroll.json` (höchstens 16 KiB):
```json
{"release": {"t": "bridgecontroll", "version": "0.2.0", "at": 1763100000000, "notes": "…",
             "files": [{"platform": "windows-x86_64", "size": 31457280, "sha256": "<64 hex>",
                        "url": "https://github.com/PhilippDwinger/Bridge/releases/download/bc-v0.2.0/bridgecontroll-windows-x86_64.exe"}]},
 "key": "<öffentlicher Schlüssel, Base64url, 32 Byte>", "sig": "<Base64url, 64 Byte>"}
```
- Unterschrift: Ed25519 über `"bridge4/update\n" ‖ kanonisches JSON von release` (Krypto nur in `bridge-core`,
  Modul `release`).
- Felder genau so (keine weiteren); `version` = `a.b.c` (je 0–9999); `notes` ≤ 2.000 Zeichen; 1–4 Dateien, je
  Plattform höchstens eine (`windows-x86_64`, `linux-x86_64`); `size` 1 Byte bis 256 MiB; `at` höchstens 1 Tag in der
  Zukunft.
- `url` nur `https://github.com/PhilippDwinger/Bridge/releases/download/…` (das Format lässt für Tests auf einem PC
  auch `http://127.0.0.1:…` zu, das Programm nicht); beim Laden höchstens 5 Umleitungen, nur `https` und nur zu
  `github.com` oder `*.githubusercontent.com`.
- Ein Update gilt nur, wenn `version` **größer** ist als die eigene – ein Zurückstufen auf eine ältere (auch echt
  unterschriebene) Version geht nicht.

## 4. Suchen und Installieren
- **Suchen**: 1 Minute nach dem Start, dann alle 6 Stunden (± 30 Minuten Zufall); im Dashboard „Nach Updates suchen“.
  Antwort ≤ 16 KiB, Zeitlimit 20 s. Fehler (offline, GitHub weg) zeigen nur einen Hinweis.
- **Automatisch** (Einstellung „Updates automatisch installieren“, Standard **an**, gespeichert in `update.json` im
  App-Ordner): ein gefundenes Update wird sofort geladen und installiert, die Knoten sind dafür ein paar Sekunden aus.
  Eine Version, die schon einmal schiefging (§5), wird nicht automatisch wiederholt.
- **Laden**: nach `<Programm>.new` neben dem laufenden Programm, höchstens `size` Byte, danach Größe und SHA-256 genau
  prüfen; sonst wird die Datei verworfen. Ist der Ordner nicht beschreibbar: Meldung „BridgeControll liegt in einem
  Ordner, in den es nicht schreiben darf – leg es in einen eigenen Ordner (z. B. Dokumente\BridgeControll)“.
- **Ersetzen** (die Knoten laufen weiter, bis das Laden fertig ist):
  1. Die App beendet sich sauber (Knoten, Tor, Bridge-3-Server) und gibt ihre Sperre frei.
  2. `<Programm>` → `<Programm>.old`, `<Programm>.new` → `<Programm>` (Umbenennen geht unter Windows auch, während das
     Programm läuft). Schlägt das fehl, wird zurückbenannt und die alte Version startet wieder.
  3. Die neue Version startet mit denselben Argumenten und `--after-update <alte Version>` (bei automatischen Updates
     ohne Browser). Sie wartet bis 30 s auf die Sperre des App-Ordners.
  4. Die alte Version wartet bis 60 s, bis `instance.json` mit der **neuen** Versionsnummer da ist (die schreibt jede
     gestartete App, jetzt mit `version`), und beendet sich dann.
- Die neue Version löscht `<Programm>.old` beim Start und zeigt „Aktualisiert von 0.1.0 auf 0.2.0“.

## 5. Wenn die neue Version nicht startet
Kommt die neue Version in 60 s nicht hoch (endet sofort, hängt): die alte beendet sie, benennt sie in
`<Programm>.bad` um, holt `<Programm>.old` zurück, startet sich selbst wieder (`--after-update`) und vermerkt in
`update.json` „Update auf 0.2.0 ging schief“ – das Dashboard zeigt es, automatisch wird diese Version nicht mehr
versucht, von Hand schon. Lässt sich eine Datei nicht umbenennen (unter Windows hält ein Virenscanner sie manchmal kurz
fest – jedes Umbenennen wird deshalb bis zu 5 s versucht), bleibt alles beim Alten und die Version gilt nicht als
gescheitert; der nächste Durchlauf versucht es wieder.

## 6. Veröffentlichen (Paddy)
Werkzeug ist `bridge-node.exe` (ein Konsolen-Programm – BridgeControll selbst hat unter Windows kein Konsolenfenster);
es liegt in jedem Release als `bridge-node-windows-x86_64.exe` und in den CI-Artifacts.
1. **Einmalig**: `bridge-node.exe release keygen --out C:\Users\phili\BridgeRelease\release-key.txt` – zeigt den
   öffentlichen Schlüssel; Claude trägt ihn in `RELEASE_KEYS` ein. Die Datei auf einen USB-Stick sichern.
2. Claude erhöht die Version (`Cargo.toml`, `[workspace.package] version`) und committet; Paddy pusht und setzt den
   Tag: `git tag bc-v0.2.0` und `git push origin bc-v0.2.0`.
3. Der CI-Workflow `release.yml` (bei Tags `bc-v*`) prüft „Tag = Version in Cargo.toml“, legt das GitHub-Release
   `bc-v0.2.0` an und lädt `bridgecontroll-windows-x86_64.exe`, `bridgecontroll-linux-x86_64` und die beiden
   `bridge-node-…` hinein.
4. Paddy unterschreibt: `bridge-node.exe release sign --key C:\Users\phili\BridgeRelease\release-key.txt
   --tag bc-v0.2.0 --notes "…" --out C:\Users\phili\Documents\Programmieren\Projekte\Bridge4\releases\bridgecontroll.json`
   – lädt die Dateien des Releases **selbst**, berechnet Größe und SHA-256 und unterschreibt. Dann committen und pushen;
   nach höchstens ein paar Minuten finden alle BridgeControlls das Update.
5. Prüfen (jeder kann das): `bridge-node.exe release verify --file releases\bridgecontroll.json`.

## 7. Schnittstellen
- `GET /api/update` (auch in `/api/overview` als `update`) → `{version, platform, enabled, auto, checking, installing,
  checked_at, available:{version, notes, size}|null, error, last:{from, to, ok, at}|null, failed}`.
- `POST /api/update/check`, `POST /api/update/install` (lädt, prüft, startet neu), `POST /api/update/auto {on}`.
- `instance.json` im App-Ordner hat jetzt auch `version` und `pid`.
- Kommandozeile: `bridge-node release keygen --out <datei>`, `bridge-node release sign --key <datei> --tag
  bc-v<version> [--notes <text>] --out <datei>`, `bridge-node release verify --file <datei> [--public <schlüssel>]`.
- Oberfläche: über den Netzen „BridgeControll 0.2.0 ist da“ mit „Jetzt aktualisieren“ (Dialog), „Aktualisiert von …
  auf …“ (einen Tag lang), „Update auf … ging schief“; unten „Automatisch aktualisieren“ und „Nach Updates suchen“.
  Ohne eingetragenen Schlüssel zeigt die Oberfläche nichts davon.

## 8. Restrisiken
- Wer Paddys Schlüssel-Datei stiehlt, kann Updates für alle unterschreiben – deshalb liegt sie außerhalb aller
  geteilten Ordner. (Später möglich: zwei Schlüssel, beide müssen unterschreiben.)
- Paddy unterschreibt, was die CI gebaut hat; eine manipulierte CI zur Bauzeit sähe er nicht (wie bei jedem Projekt
  ohne reproduzierbare Builds).
- Wer GitHub sperrt, hält Updates zurück (kein Schaden, nur veraltet).
- Ein Update unterbricht die Knoten des PCs für ein paar Sekunden.

## 9. Abnahme Schritt 4
- Kern: Ankündigung unterschreiben/prüfen; Angriffe (fremder Schlüssel, geänderte Felder, falsche Art, zusätzliche
  Felder, kaputte Version, zu groß, Zukunft, URL eines anderen Hosts).
- Transport: Laden mit Umleitungen nur zu erlaubten Hosts, Größe genau, Abbruch bei zu viel.
- BridgeControll (Linux, echtes Programm in einem Testordner, Update-Server lokal): Update gefunden, geladen, Programm
  ersetzt, neue Version läuft; kaputtes Update → zurück auf die alte Version, Vermerk; falsche Unterschrift, falscher
  Hash, ältere Version → nichts passiert. Die Test-Schalter (Adresse, Schlüssel) gibt es nur in Debug-Builds.
- `release keygen` / `sign` / `verify` mit einem lokalen Release (nur die vorhandenen Plattformen, Hash dessen, was
  wirklich geladen wurde, falscher Schlüssel, falscher Tag).
- UI-Rauchtest Bilder 38–39 (Update da, Dialog) mit einer lokalen, echt unterschriebenen Ankündigung.

## 10. Owner-Backup (Schritt 5)
Paddy: „App-Schlüssel und Einstellungen des Owners, verschlüsselt mit einem Schlüssel aus den 24 Wörtern, liegen auf
den Speicher-Knoten; auf einem neuen PC stellen die 24 Wörter alles wieder her.“

### 10.1 Was gesichert wird
Aus dem Ordner des Owner-Knotens: `node-key.json` (Schlüssel des Owner-Knotens – er ist der **erste Log-Führer**; ohne
ihn steht das Log für immer, docs/06 §5), `node-tls.pem`, `admin-key.json`, alle App-Schlüssel `apps/<id>.json`; aus
BridgeControll die Einstellungen dieses Knotens (Name, Ports, Leser, Autostart, öffentlich ja/nein). Nicht: das Log und
die Dateien (die liegen im Netz), Pfade dieses PCs (Website-Ordner). Höchstens 1 MiB.

### 10.2 Verschlüsselt für die 24 Wörter – ohne die Wörter zu kennen
Der PC kennt die 24 Wörter nicht (sie werden nie gespeichert). Er verschlüsselt **für** den Empfangs-Schlüssel des
Hauptschlüssels (X25519, steht in dessen Karte im Genesis-Manifest): X25519 mit einem Einmal-Schlüssel → HKDF-SHA256
(`info = "bridge4/backup\n" ‖ Netz-ID`) → ChaCha20-Poly1305 (`bridge-core::backup`). Öffnen kann es nur, wer die
24 Wörter hat. Format: `B4BACKUP1` ‖ Einmal-Schlüssel (32) ‖ Nonce (12) ‖ Chiffretext.

### 10.3 Wo es liegt: als App, auf die das Log zeigt
- Das Backup ist eine **Bridge-App** mit einer Datei `owner-backup.b4` (eigener App-Schlüssel `backup-app.json` im
  Owner-Ordner, nicht in der Website-Liste). Hosts: der Owner-Knoten und alle anderen Knoten mit Siegel `web` (bis
  zu 8, docs/07). Die App-Maschine der Knoten holt, prüft und hält die Datei – auch wenn der Owner-PC weg ist, bis die
  Version abläuft (1 Jahr).
- Ein neuer Log-Eintrag **`backup`** `{app}` (unterschrieben von einem Admin mit dem Recht `rules`, Laufzeit bis
  1 Jahr) sagt, welche App das Backup ist; es gilt der neueste gültige. So findet ein neuer PC es nur mit den Wörtern
  und einer Adresse des Netzes.
- BridgeControll sichert 2 Minuten nach dem Start des Owner-Knotens und dann stündlich, **wenn sich etwas geändert
  hat** (neue App, neuer Schlüssel, Einstellungen), sonst alle 30 Tage (damit die Version nicht abläuft). Der
  `backup`-Eintrag wird nur neu geschrieben, wenn er fehlt oder älter als 180 Tage ist.

### 10.4 Wiederherstellen auf einem neuen PC
BridgeControll: **„Netz wiederherstellen (24 Wörter)“** – die Wörter und die Adresse eines Knotens des Netzes (ein
Einladungslink oder eine öffentliche Adresse eines Mitglieds-PCs; die eigene alte Adresse, wenn der neue PC in
Tailscale denselben Namen hat).
1. Aus den Wörtern: Hauptschlüssel → Netz-ID. Das Log von der Adresse holen, prüfen (Eintrag 0 = Genesis dieses
   Netzes) und abspielen → neuester `backup`-Eintrag → App → die Datei bei einem ihrer Hosts holen (jedes Stück gegen
   seinen Hash) → mit dem Hauptschlüssel öffnen.
2. Ein neuer Owner-Knoten-Ordner mit den gesicherten Schlüsseln, dazu die Mitgliedschaft (Netz-ID, Start-Adresse =
   die angegebene). Beim Start holt der Knoten das bezeugte Log von dort und ist wieder Log-Führer.
3. Ein Eintrag in BridgeControll mit den gesicherten Einstellungen; der Knoten startet.
Nur, wenn der alte PC **weg** ist: zwei Owner-Knoten mit demselben Schlüssel würden sich widersprechen (der zweite
würde als Log-Führer abgesetzt). BridgeControll fragt das ausdrücklich ab und verweigert die Wiederherstellung, wenn
der Owner-Knoten unter seiner Adresse noch antwortet.

### 10.5 Werkzeuge und Oberfläche
- `bridge-node backup make --data <ordner> [--node <adresse>] [--force yes]` und `bridge-node backup restore --data
  <neuer ordner> --from <adresse>` (fragt die 24 Wörter ab wie `net rescue`); Code: `bin/bridge-node/src/backup.rs`.
- BridgeControll: sichert jeden laufenden Owner-Knoten 2 Minuten nach dem Start und dann stündlich; im
  Owner-Dashboard der Kasten **„Owner-Backup“** („Gesichert am … auf n Hosts“, „Jetzt sichern“ =
  `POST /api/nodes/<id>/backup`); auf der Startseite **„Netz wiederherstellen“** (`POST /api/restore {words,
  address}`; ein Einladungslink zählt als Adresse, wenn er zu den Wörtern passt). Der neue Owner-Knoten bekommt die
  gesicherten Einstellungen (Name, Netzname) und einen freien Port; „Öffentlich machen“ danach neu.
- Hat der Owner-Knoten noch nicht den Dienst `web`, bekommt er ihn fürs Backup (neues Siegel, Stufe 3 – wie bei der
  ersten Website). Die Backup-App steht nicht in der Liste der Apps.

### 10.6 Grenzen
- Einträge, die der alte Owner-Knoten in seinen letzten Sekunden angenommen, aber nicht mehr bezeugt bekommen hat, sind
  verloren.
- Hat der neue PC eine **andere Adresse**, finden die anderen Knoten den Log-Führer erst, wenn sie die neue Adresse
  kennen – am einfachsten: in Tailscale dem neuen PC denselben Gerätenamen geben (dann bleibt die Adresse gleich).
- Ohne erreichbaren Host mit dem Backup (alle Knoten mit `web` aus) geht es nicht; das Backup selbst ist ohne die
  Wörter wertlos.

### 10.7 Abnahme Schritt 5
- Kern: verschlüsseln/öffnen, falsche Wörter, anderes Netz, verändert, abgeschnitten, zu groß.
- `bridge-net`: Eintrag `backup` (nur Admin mit `rules`, Laufzeit, der neueste gilt, Widerruf).
- e2e: Owner sichert, sein Ordner geht verloren, ein neuer Ordner wird aus Wörtern + Adresse eines Mitglieds
  wiederhergestellt, der Knoten läuft wieder als Log-Führer (nimmt Einträge an), die App-Schlüssel gehen (neue Version
  einer Website), falsche Wörter → nichts.
- BridgeControll (zwei Apps = zwei PCs): „Jetzt sichern“ (2 Hosts), falsche Wörter und laufender alter Owner →
  abgelehnt, nichts halb angelegt; nach dem Stopp des alten Owner-Knotens kommt er auf dem neuen PC zurück und ist
  Log-Führer; die Wörter stehen nirgends im App-Ordner. UI-Rauchtest Bilder 40–41.
