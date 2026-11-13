# 11 – Phase 7: Öffentlich, Bridge-3-Server im Netz, Bridge Login

Stand: 13.11.2026 – mit Paddy im Chat besprochen und freigegeben („Mach jetzt weiter“). Entscheidungen: ADR 0025 (das
Tor: öffentlich über einen Tailscale-Port), ADR 0026 (Bridge-3-Server statt eigener Realms).

Ziel: Bridge 4 wird **öffentlich** – Websites, Apps und Knoten eines Netzes sind aus dem Internet erreichbar, mehrere
Netze teilen sich **einen** Tailscale-Port. Ein Netz kann **Bridge-3-Server** enthalten (Realms, Topics, Commands,
Friends wie bisher). Websites bekommen später ein **Bridge Login** mit Konten.

## 0. Grundsätze (von Paddy)
- **Kostenlos, ohne Abos**: Bridge läuft auf eigenen PCs; erreichbar über Tailscale (kostenlos). Keine fremden
  Cloud-Dienste (kein Supabase o. Ä.) – „ich will das selber haben“. Eine eigene Domain kommt höchstens **optional**
  ganz am Ende.
- **Bridge 4 hat keine eigenen Realms**: Bridge 4 ist „riesiger“ und kann viele Bridge-3-Server enthalten; die Dinge
  aus Bridge 3 (Realms, Topics, Commands …) macht man in diesen Servern.
- **Das Netz nutzt sich selbst**: Ein Feature, das Rückhalt braucht (z. B. Konten), wird erst freigeschaltet, wenn das
  Netz die passenden Knoten hat. Fehlen sie, ist das Netz dafür „nicht stark genug“.
- **Bridge gibt Werkzeuge, die App entscheidet**: z. B. wo eine App speichert (lokal auf ihrem Knoten oder im
  Bridge-Speicher) – das legt das Programm selbst fest.
- **Lange Adressen sind egal** – dafür gibt es den Bridge-Browser.

## 1. Überblick

| Schritt | Was | Wo |
|---|---|---|
| 1 | **Öffentlich**: das Tor (ein lokaler Eingang für alle Netze), Knopf „Öffentlich machen“ mit Tailscale Funnel, öffentliche Websites mit Hülle und Startseite, Not-Aus | `crates/bridge-gate`, `bridge-node` (Leser `public`, `/`, `/web/`), BridgeControll v2 |
| 2 | **BridgeControll 3** legt Server unter `/bridge3/<id>` ab (ältere Server: „Pfad umstellen“) | Ordner `BridgeControll` (Bridge 3) |
| 3 | **Bridge-3-Server im Netz**: echte Bridge-3-Server, von BridgeControll v2 gestartet, unter `/bridge4/<netz>/bridge3/<id>/` | BridgeControll v2, Tor, Netz-Eintrag |
| 4 | **Was kann mein Netz?** (Fähigkeiten-Ampel) und **Bridge Login** (Konten mit Passkeys auf den Speicher-Knoten, Nutzer-ID pro App) | `bridge-core::webauthn`, `bridge-net`, Knoten, Hülle, BridgeControll v2 |

## 2. Adressen

Alles auf **einem** Funnel-Port (Standard 443, wählbar 8443 oder 10000 – mehr bietet Tailscale nicht):

| Adresse | Was |
|---|---|
| `https://<gerät>.<tailnet>.ts.net/bridge4/<netz>/` | Startseite des Netzes: Name, Meldeweg, öffentliche Websites |
| `…/bridge4/<netz>/web/<name>/` | Website `<name>` in der **Hülle** (Leiste mit Netz, Name, „Melden“) |
| `…/bridge4/<netz>/app/<app-id>/…` | die App selbst (sandboxed, wie bisher `/app/<id>/` am Knoten) |
| `…/bridge4/<netz>/v4/…` | der Knoten (Protokoll v4: Beitritt, SDKs, andere Knoten) |
| `…/bridge4/<netz>/bridge3/<id>/` | Bridge-3-Server im Netz (Schritt 3) |
| `…/bridge3/<id>/` | Bridge-3-Server aus BridgeControll 3 (Schritt 2) |

- **`<netz>`** (Netz-Schlüssel): der **Kurzname** des Netzes beim Veröffentlichen (z. B. `testnetz`), ohne Kurzname
  die Netz-ID in Kleinbuchstaben. Er bleibt danach fest (Adressen sollen sich nicht ändern, auch wenn der Kurzname
  später wechselt), ist auf dem PC eindeutig und nie `bridge3` oder `bridge4`.
- Die öffentliche Adresse eines Knotens ist `https://<gerät>.<tailnet>.ts.net[:<port>]/bridge4/<netz>` (ohne `:443`).
- Pro Netz und PC ist **ein** Knoten öffentlich.

## 3. Das Tor (Schritt 1, ADR 0025)

Ein eigener Prozess `bridgecontroll gate` (Abteil `crates/bridge-gate`), gestartet und überwacht von BridgeControll
v2 wie die Knoten (Watchdog). Er hält **keine Schlüssel**, kennt keine Sitzungen der Oberfläche und spricht nur mit
den Knoten-Ports dieses PCs auf `127.0.0.1`.

- **Lauscht** nur auf `127.0.0.1:<port>` (ab 7390). Tailscale Funnel leitet `/bridge4` dorthin – **ein** Eintrag für
  alle Netze; ein neues Netz braucht keine Tailscale-Änderung.
- **Routen** aus einer Datei, die BridgeControll schreibt (`gate/routes.json`, nur für den Besitzer lesbar):
  `{"routes":[{"key":"testnetz","port":7401,"web":true}]}` – höchstens 64 Routen, `port` nur `1024–65535`.
  Bei einer Änderung startet BridgeControll das Tor neu (Long-Polls der Clients verbinden sich von selbst neu).
- **Pfad**: höchstens 2.048 Zeichen; nur `/`, `A–Z a–z 0–9 - . _ ~ ! $ & ' ( ) * + , ; = : @ %` und gültige
  `%XX`; abgelehnt werden `.`/`..`-Segmente (auch kodiert), `//`, `%2F`/`%5C` (kodierte Schrägstriche), `%00`.
  Ein führendes `/bridge4` wird entfernt, falls Tailscale es nicht schon abgeschnitten hat (beides funktioniert).
  - `/` → kleine Seite „Bridge 4“ ohne Liste (fremde Netze dieses PCs werden nicht verraten).
  - `/<netz>` → `308` auf `<netz>/` (relativ – funktioniert mit und ohne abgeschnittenes `/bridge4`).
  - `/<netz>/<rest>` → an `http://127.0.0.1:<port>/<rest>` (Abfrage `?…` bleibt). Unbekanntes Netz → `404`.
  - **Not-Aus** (`"web": false`): `/<netz>/`, `/<netz>/web/…`, `/<netz>/app/…` → `503` „Websites dieses Netzes sind
    gerade nicht öffentlich“; `/<netz>/v4/…` bleibt (das Protokoll ist signiert und verschlüsselt, Mitglieder
    unterwegs brauchen es).
- **Methoden**: `GET`, `POST`, `OPTIONS`; sonst `405`. Keine Anfragen in absoluter Form (`GET http://…`).
- **Kopfzeilen**: Hop-by-Hop-Köpfe (`Connection`, `Keep-Alive`, `Proxy-*`, `TE`, `Trailer`, `Transfer-Encoding`,
  `Upgrade`) und `Forwarded`, `X-Forwarded-*`, `X-Real-IP` werden **nie** weitergegeben. Das Tor setzt selbst
  `X-Forwarded-For: <client>`, `X-Forwarded-Proto: https`, `Host: 127.0.0.1:<port>`. `<client>` ist der letzte Eintrag
  von `X-Forwarded-For`, den Tailscale (vom vertrauten `127.0.0.1`) anhängt – sonst die Adresse des Aufrufers.
  Antworten gehen unverändert zurück (ohne Hop-by-Hop-Köpfe).
- **Grenzen**: höchstens 512 Verbindungen, 32 gleichzeitige Anfragen je Client-Adresse (IPv6: je /64), Kopfzeilen in
  10 s, höchstens 64 Köpfe und 16 KiB Kopf; Anfrage-Inhalt höchstens 4 MiB (der Knoten prüft genauer). Antworten
  werden gestreamt (App-Dateien, Long-Polls); die Zeitgrenzen der Antwort setzt der Knoten (docs/04 §7).
- Antworten des Tors selbst: kleine HTML-Seiten auf Deutsch, `no-store`, CSP `default-src 'none'; style-src
  'unsafe-inline'`, `frame-ancestors 'none'`, `nosniff`, kein Referrer.
- **Nie ein offener Proxy**: Ziele nur aus der Routen-Datei, nur `127.0.0.1`.

## 4. Knoten (Schritt 1)

- **Leser `public`** (`--reader public`, docs/08 §8): wie `local`, dazu **jeder** Aufrufer – auch über den vertrauten
  Proxy (das Tor). Nur für einen Knoten hinter dem Tor gedacht; der eigene Browser nutzt weiter den Loopback-Leser
  (`--reader-listen`). Der Leser holt und prüft Apps, die der Knoten nicht selbst hostet, genau wie für den eigenen
  Browser (Bann, Kennzeichnung, Ablauf, gültige Hosts), mit seinen Grenzen (LRU, Ströme je Adresse).
- **`GET /`** (nur wenn der Knoten ein Netz hat): Startseite – Netzname, Meldeweg, bis zu 100 öffentliche Websites
  (Namen der Art `app`, die jetzt auflösen, sichere Suche: kein 18+, Inhaber ab Stufe 2, Sperrlisten beachtet),
  sortiert, Links `web/<name>/`.
- **`GET /web/<name>/`**: die **Hülle** – eine HTML-Seite ohne Skripte: oben eine Leiste (Netzname, `<name>`, „Problem
  melden: <Meldeweg>“, Link „Nur die Seite“), darunter die App im `<iframe sandbox="allow-scripts allow-forms
  allow-popups" src="../../app/<app-id>/">`. CSP `default-src 'none'; style-src 'unsafe-inline'; frame-src 'self'`,
  `frame-ancestors 'none'`. Name, der nicht (mehr) auflöst, nicht auf eine App zeigt oder 18+ ist → `404`-Seite.
  `/web/<name>` ohne `/` → `308` auf `<name>/`.
- Der Meldeweg wird HTML-kodiert; ein `mailto:`-Link nur bei einer einfachen E-Mail-Adresse, ein Link nur bei
  `https://…`.
- Beide Seiten: nur `GET`, `no-store`, keine Cookies, nichts aus Daten wird als HTML ausgeführt.
- **Besucher aus dem Internet** (Anfragen über den vertrauten Proxy, also über das Tor) bekommen Apps – Hülle,
  Startseite und `/app/…`, gehostet oder über den Leser – nur von Inhabern **ab Stufe 2** und nur in Netzen, die 18+
  verbieten (`NetState::public_owner`). Der eigene Browser (Loopback-Leser) sieht alles wie bisher.
- *Phase 8*: Websites zeigt den Besuchern aus dem Internet nur ein Knoten mit **Siegel Stufe 3** (§13).

## 5. BridgeControll v2 (Schritt 1)

- **„Öffentlich machen“** (im Owner-Dashboard – **nur der Owner** entscheidet, ob die Websites seines Netzes ins
  Internet gehen; ein Mitglieds-PC kann das in BridgeControll nicht):
  1. Prüfen: Owner-Knoten, läuft und kennt sein Netz; das Netz **verbietet 18+** (`adult: "forbidden"`) – Netze, die 18+
     erlauben, werden nie öffentlich (ADR 0018, JMStV); kein anderer Knoten dieses Netzes auf dem PC ist öffentlich.
  2. Tailscale fragen (`tailscale status --json`): läuft und angemeldet, `Self.DNSName` (ohne Punkt am Ende).
  3. Tor-Port vergeben (ab 7390), Routen schreiben, Tor (neu) starten.
  4. Falls noch nicht: `tailscale funnel --bg --https=<port> --set-path=/bridge4 http://127.0.0.1:<tor-port>`.
  5. Knoten: Netz-Schlüssel festhalten, öffentliche Adresse setzen, Leser `public`, Loopback-Leser-Port; neu starten.
  6. **Eigener Owner-Knoten**: automatisch **neu siegeln** (gleiche Stufe und Dienste), damit das Netz die neue
     Adresse kennt.
- **„Websites aus“ / „Websites an“** (Not-Aus): nur die Route (`web`), sofort, ohne Knoten-Neustart (das Tor startet
  neu; offene Long-Polls verbinden sich von selbst wieder).
- Das Neu-Siegeln nimmt Stufe und Dienste aus dem **aktuellen Log des Knotens** (nicht aus dem Status-Zwischenspeicher)
  – ein Siegel mit `web` darf dabei nie verloren gehen, sonst hörten seine Apps auf.
- **„Nicht mehr öffentlich“**: Route weg, Adresse zurück auf lokal, Leser zurück auf die vorige Einstellung, Owner-Knoten
  neu siegeln; war es das letzte öffentliche Netz: `tailscale funnel --https=<port> --set-path=/bridge4 off` und Tor
  stoppen.
- **Nur eigene Tailscale-Einträge**: nie `tailscale serve reset`, nie ein anderer Pfad als `/bridge4` – Einträge von
  BridgeControll 3 oder von Hand bleiben unberührt. Programm: `BRIDGECONTROLL_TAILSCALE` (für Tests), sonst
  `C:\Program Files\Tailscale\tailscale.exe` (Windows, wenn vorhanden), sonst `tailscale` im Pfad; feste Argumente,
  keine Shell, Zeitgrenze 40 s; Fehlertexte (z. B. „Funnel ist im Tailnet nicht erlaubt“ mit Link) werden angezeigt.
- **Aufräumen** (jede Statusrunde): erlaubt das Netz inzwischen 18+ → Websites automatisch aus (Not-Aus) und Hinweis.
- **Einstellungen**: `public` in `bridgecontroll.json`: `{"gate_port":7390,"funnel_port":443,"funnel_on":true,
  "host":"pc.tail1234.ts.net"}`; pro Knoten `public_key` (Netz-Schlüssel) und `public_web`. Eine öffentliche Adresse
  von Hand (`public_url` ohne `public_key`) geht weiter wie bisher; solange ein Knoten über das Tor öffentlich ist, ist
  seine Adresse nicht von Hand änderbar.

## 6. Sicherheit (Schritt 1)

| Angriff | Abwehr |
|---|---|
| Alle Websites haben **dieselbe Herkunft** (`<gerät>.ts.net`) – eine böse Seite liest Cookies/Speicher einer anderen | Jede App läuft in einer eigenen undurchsichtigen Herkunft (CSP `sandbox` ohne `allow-same-origin`, docs/07 §5) – sie hat gar keine Cookies und keinen Speicher der Herkunft; die Hülle hat nur Bridges eigenes Login-Skript (§9.4). Login nur über Bridge, nie in der App. |
| Tor als **offener Proxy** | Ziele nur aus der Routen-Datei, nur `127.0.0.1`, nur bekannte Netz-Schlüssel |
| **Gefälschte Kopfzeilen** (`X-Forwarded-For`, `Host`) | werden entfernt und vom Tor neu gesetzt; der Knoten vertraut nur `127.0.0.1` und nur dem letzten Eintrag |
| **Pfad-Tricks** (`..`, kodierte `/`, `\`, Nullbytes) | im Tor abgelehnt, bevor geroutet wird; der Knoten prüft App-Pfade noch einmal (`check_path`) |
| **Überlast** durch Fremde | Grenzen im Tor (Verbindungen, je Adresse) und im Knoten (Wächter-Eimer, Ströme); Not-Aus ohne Neustart |
| **18+** öffentlich | Netze, die 18+ erlauben, werden nie öffentlich; erlaubt ein Netz es später, gehen die Websites automatisch aus |
| **Phishing** über öffentliche Seiten | Hülle zeigt immer Netz und Name und den Meldeweg; Startseite nur sichere Namen (Stufe ≥ 2) |
| Fremde Tailscale-Einträge kaputt machen | nur `/bridge4` auf dem eigenen Port, nie `reset` |
| Internet erreicht die Oberfläche oder Schlüssel | das Tor ist ein eigener Prozess ohne Schlüssel; die Oberfläche bleibt auf `127.0.0.1` mit Host-Prüfung |

Restrisiko: Was ein öffentlicher Knoten hostet, sieht die ganze Welt – der Owner ist dafür verantwortlich
(NUTZUNGSREGELN.md). Tailscale sieht die Verbindungen (TLS endet bei Tailscale auf dem eigenen PC, nicht bei Dritten).

## 7. Schritt 2: BridgeControll 3 auf `/bridge3/<id>` (gebaut 13.11.2026)
- Neue Server: Pfad `/bridge3/<id>` (bisher `/<id>`), Website `/bridge3/<id>/site` (`servers.json`:
  `"path_style": "bridge3"`). Server-IDs `bridge3` und `bridge4` sind gesperrt.
- **Ältere Server** behalten `/<id>` (ihre Adresse ist ihre Identität), bis Paddy beim Server **„Pfad umstellen“**
  klickt: alte Funnel-Einträge raus, Neustart mit `/bridge3/<id>` – laufende Spiele/Mods brechen so nicht ungefragt ab.
  Danach brauchen Clients die neue Adresse; vertraute Server müssen neu vertrauen.
- Weiterhin nur eigene Einträge, nie `reset`, nie `/bridge4`. Tests: `tests/test_bridgecontroll.py` (76 grün).
- Gilt erst nach `BUILD_EXE.bat` (die Bridge-3-BridgeControll läuft als gebaute Exe).

## 8. Schritt 3: Bridge-3-Server im Netz (ADR 0026)
- **Echter Bridge-3-Code** (Branch `bridge-3`, z. B. Paddys Ordner `Bridge`) mit Python des PCs – Realms, Topics,
  Commands, Friends, Express und alle Extensions funktionieren unverändert, nur die Adresse ist neu.
- **Einstellungen** (einmal pro PC, im Dashboard „Bridge-3-Server“): **Bridge-3-Ordner** (muss `main.py` und
  `bridge/server/base_path.py` enthalten) und **Python** (leer = automatisch: `<Ordner>\..\BridgeControll\.venv`,
  `<Ordner>\.venv`, dann `py -3` bzw. `python3`). Geprüft wird, ob dieses Python `fastapi`, `uvicorn`, `argon2`,
  `httpx` laden kann; sonst eine klare Meldung (`pip install -r requirements.txt`).
- **Server** (nur am Owner-Knoten eines Netzes – der Owner entscheidet): ID (`a-z 0-9 -`, 2–40, nicht `bridge3`,
  `bridge4` und nicht die Bridge-Pfade `admin, server, …`), Name, Admin-Passwort (mind. 8 Zeichen), Autostart. Port
  vergibt BridgeControll (ab 7801). Höchstens 32 Server pro PC.
- **Start**: BridgeControll schreibt sein eigenes kleines Startskript (`bridge3/runner.py` im App-Ordner) und startet
  `python runner.py` mit `BRIDGE_CODE_DIR`, `PORT`, `BRIDGE_PASSWORD`, `BRIDGE_PUBLIC_URL`, `BRIDGE_TRUST_PROXY=1`,
  `BRIDGE_TRUST_PROXY_IPS=127.0.0.1,::1`. Das Skript bindet **nur 127.0.0.1** (nicht wie `main.py` alle Adressen –
  aus dem Heimnetz kommt niemand am Tor vorbei) und stoppt sauber, wenn die Standard-Eingabe zugeht (Backup an
  vertraute Server). Watchdog wie bei den Knoten, Protokoll pro Server.
- **Adresse** (= Identität in Bridge 3): ist das Netz öffentlich `https://<gerät>.ts.net[:port]/bridge4/<netz>/bridge3/<id>`,
  sonst `http://127.0.0.1:<port>`. Wird das Netz öffentlich (oder nicht mehr), starten seine Bridge-3-Server mit der
  neuen Adresse neu – am besten das Netz zuerst öffentlich machen, dann Server anlegen.
- **Tor**: die Route des Netzes kennt seine Bridge-3-Server (`"bridge3":[{"id":"spiel","port":7801}]`);
  `/<netz>/bridge3/<id>/…` geht an `127.0.0.1:<port>/…` (Bridge 3 kommt mit und ohne Pfad zurecht). Der Not-Aus der
  Websites betrifft sie nicht (eigenes Starten/Stoppen).
- Sicherheit: Ein Bridge-3-Server hat die Sicherheit von Bridge 3 (Passwort, alles im RAM) – als eigener Prozess
  abgeschottet, ohne Zugriff auf Schlüssel von Bridge 4, nur über das Tor erreichbar. Das Passwort steht in den
  Einstellungen von BridgeControll (nur für den Besitzer lesbar), wie bei BridgeControll 3.
- Später: Eintrag im Netz (Name) und auf der Startseite; Server auf einem anderen PC des Netzes über den öffentlichen PC;
  Server eines Netzes vertrauen sich automatisch; Bridge-4-SDKs sprechen Bridge-3-Server an.

## 9. Schritt 4: Was kann mein Netz? und Bridge Login (ADR 0027, gebaut 13.11.2026)

### 9.1 Was kann mein Netz? (Fähigkeiten-Ampel)
Jedes Feature nennt, was es im Netz braucht; BridgeControll rechnet es aus dem Netz-Zustand aus
(`NetState::abilities`) und zeigt es im Owner-Dashboard als Ampel: grün = bereit, gelb = geht, aber schwach,
rot = fehlt – mit dem, was fehlt. Gezählt werden Knoten mit gültigem Siegel und dem Dienst (Stufe ≥ 2, nicht
gebannt):

| Feature | grün ab | gelb ab | rot |
|---|---|---|---|
| Nachrichten | 2 Empfänger (`gateway`) | 1 | 0 |
| Websites und Apps | 2 Web-Hosts (`web`) | 1 | 0 |
| Speicher | 10 Speicher-Knoten (`storage`, 6+4) | 1 (weniger Ausfallschutz) | 0 |
| Rechnen | 2 Rechen-Knoten (`compute`) | 1 | 0 |
| **Bridge Login (Konten)** | 2 Speicher-Knoten | 1 | 0 – Login ist dann aus |
| Wächter | 1 Wächter (`watch`) | 1 | 0 |

### 9.2 Bridge Login – Grundidee
- **Konten** für Besucher der Websites/Apps eines Netzes. Sie liegen auf den **Speicher-Knoten** des Netzes (Dienst
  `storage`, Stufe ≥ 2 – „ein Knoten zum Speichern, der eine Verifizierung hat“, `NetState::login_nodes`). Ohne einen
  solchen Knoten ist Login aus („das Netz ist dafür nicht stark genug“).
- **Eingang**: Login läuft an einem Knoten, der selbst Speicher-Knoten ist **und** eine öffentliche `https`-Adresse
  hat (für Tests `http://localhost:<port>`). In BridgeControll: „Login hier einschalten“ gibt dem öffentlichen
  Owner-Knoten zusätzlich den Dienst `storage` (Stufe und übrige Dienste bleiben). Andere Knoten sagen bei
  `GET /v4/login/info`, warum Login bei ihnen aus ist, und lehnen den Rest ab (`403`).
- **Passkeys** (WebAuthn) statt Passwörtern: ES256 (P-256, fast alle Geräte) und EdDSA (Ed25519), ohne Attestation.
  Auf dem Netz liegt nur der öffentliche Schlüssel (SPKI aus `getPublicKey()`) – nichts, was man stehlen und benutzen
  könnte. Ein Passwort gibt es nicht, eine E-Mail auch nicht.
- **Wiederherstellungs-Code** beim Anlegen: 15 Byte = 120 Bit, gezeigt als 24 Zeichen Base32 in 6 Blöcken, dazu die
  Konto-ID (32 Zeichen). Nur einmal sichtbar; das Netz kennt nur seinen Hash. Damit bekommt ein Konto einen neuen
  Passkey (Gerät verloren).
- **Eine Nutzer-ID pro App** (`H(Konto, App)`): Apps können Nutzer nicht über Apps hinweg verfolgen.
- **Der Login läuft in der Hülle** (`/web/<name>/`, Bridges eigene Seite), nie in der App: die App fragt per
  `postMessage`, die Hülle antwortet mit Nutzer-ID, Anzeigename und einem **App-Zeichen** (9.4).
- **Relying Party** (WebAuthn): der Host der öffentlichen Adresse des Knotens (z. B. `muttchen.tail91b057.ts.net`);
  erlaubter Ursprung genau `https://<host>[:port]`. Ein Passkey gilt damit für diesen Eingang (Host); weitere PCs als
  Eingänge brauchen eigene Passkeys oder später eine gemeinsame Domain. Weitere Geräte für dasselbe Konto: §14.

### 9.3 Konten-Einträge (selbst-beglaubigt, abgeglichen zwischen Speicher-Knoten)
Ein Konto ist eine Folge von Einträgen; **jeder Speicher-Knoten prüft jeden Eintrag selbst** – ein Knoten kann kein
fremdes Konto übernehmen (`bridge-core::login`):
- `create` (Version 1): `{account, name, credential:{id, alg, key}, recovery:H(code), at}` mit
  `account = H("bridge4/login/account" ‖ key ‖ H(code))` (Base32, 20 Byte). Der Anzeigename (1–40 Zeichen, keine
  Steuerzeichen, Leerzeichen am Rand werden entfernt) ist **nicht** eindeutig.
- `recover` (Version + 1): neuer Passkey und neuer `H(code)`, belegt mit dem **alten Code im Klartext** – danach ist der
  alte Code wertlos, **alle** bisherigen Passkeys ebenso (das Konto hat danach genau ein Gerät, „Gerät 1“).
- `add` / `remove` (Version + 1): ein weiteres Gerät bzw. eines weniger, unterschrieben von einem Passkey des Kontos
  (§14). Ein Konto hat 1–8 Geräte, jedes mit eigenem Passkey.
- Ein Passkey gehört zu genau einem Konto. Gültig ist immer die nächste Version; Speicher-Knoten holen alle paar
  Sekunden bei bis zu 8 anderen Speicher-Knoten die Einträge seit ihrem Stand (`POST /v4/node/accounts`, signierte
  Knoten-Anfrage, Antwort höchstens 200 Einträge) und prüfen jeden. Grenzen: 100.000 Konten je Netz und Knoten,
  Einträge ≤ 16 KiB. Gespeichert in der Datenbank des Knotens (Schema 14: Konten, Einträge in Ankunftsreihenfolge,
  Signatur-Zähler; Schema 15: Tabelle `login_credentials` – welcher Passkey zu welchem Konto gehört).

### 9.4 Anmelden, Sitzung, App-Zeichen
- `GET /v4/login/info` → `{enabled, reason, rp_id, origin, login_nodes}`.
- `POST /v4/login/challenge` → 32 Byte, 2 min gültig, genau einmal (höchstens 10.000 offen, im RAM).
- `POST /v4/login/register` `{name, credential:{id, alg, key}, client_data, auth_data, recovery}` – prüft `type`
  (`webauthn.create`), Challenge, Ursprung, `crossOrigin`, `rpIdHash`, Flag „User Present“ → `create` + Sitzung.
  Höchstens 5 neue Konten je Adresse und Stunde.
- `POST /v4/login/assert` `{credential_id, client_data, auth_data, signature}` – prüft wie oben (`webauthn.get`) +
  Signatur + Zähler (zählt der Authenticator, muss der Zähler steigen – sonst Verdacht auf kopierten Passkey) →
  **Sitzung**: vom Knoten signierte Aussage `t:"session"`, `{account}`, höchstens 12 h.
- `POST /v4/login/recover` `{account, code, credential, client_data, auth_data, recovery}` (Zeremonie
  `webauthn.create` für den neuen Passkey) → `recover` + Sitzung.
- `POST /v4/login/app` `{session, app}` → **App-Zeichen**: vom Knoten signierte Aussage `t:"login"`,
  `{app, user:H(account,app), name}`, höchstens 1 h. Zeichen gehen als Base64url ihrer kanonischen Bytes über die
  Leitung.
- Sitzung und App-Zeichen gelten nur, solange ihr Aussteller ein Speicher-Siegel ab Stufe 2 hat – an jedem Knoten des
  Netzes (die Sitzung von Knoten A gilt auch an Knoten B).
- **Server-Code der App** (docs/09 §13): kommt `POST /app/<id>/api/…` mit dem Kopf `X-Bridge-Login: <App-Zeichen>`
  (höchstens 4 KiB, sonst `400`), prüft der Host das Zeichen (Netz, App, Ablauf, Aussteller mit Speicher-Siegel ab
  Stufe 2, Signatur) und gibt `user` und `name` an den Handler (`{"path","body","user","name"}`); ein falsches Zeichen
  ist `401`. Ohne Kopf läuft der Handler wie bisher ohne Nutzer. Der Browser fragt vorher per `OPTIONS` nach
  (`Access-Control-Allow-Headers: Content-Type, X-Bridge-Login`). Speichern pro Nutzer entscheidet die App selbst
  (lokal am Host oder Bridge-Speicher).
- **Die Hülle** hat jetzt ein Skript – nur Bridges eigenes (`/login.js`; CSP `script-src 'self'`,
  `connect-src 'self'`, keine Inline-Skripte, kein HTML aus Zeichenketten) und `Cross-Origin-Opener-Policy:
  same-origin`. Die Sitzung liegt **nur im Speicher der Seite** (weg beim Neuladen) – andere Seiten desselben
  Ursprungs (andere Netze, Bridge-3-Server) können sie nicht aus dem Browser-Speicher lesen.
- `postMessage` (nur vom eigenen `iframe` angenommen): App → Hülle `{"bridge":"login"}` (wer ist angemeldet?) oder
  `{"bridge":"login","ask":true}` (Anmelde-Fenster öffnen); Hülle → App
  `{"bridge":"login","user":…,"name":…,"token":…,"exp":…}` oder `{"bridge":"login","user":null}` (auch beim
  Abmelden). Die Hülle meldet sich auch von selbst, sobald Login bereit ist und wenn die App (neu) lädt – eine App,
  die zu früh gefragt hat, bekommt so trotzdem ihre Antwort. Die Hülle holt ein neues App-Zeichen 5 Minuten vor Ablauf.

### 9.5 Restrisiken (bewusst)
- **Gemeinsamer Ursprung**: alle Netze und Bridge-3-Server hinter einem Tor teilen `https://<gerät>.ts.net`. Eine
  Seite mit Skript auf diesem Ursprung (z. B. eine Bridge-3-Seite) könnte selbst eine Passkey-Anmeldung anstoßen. Die
  Hülle schützt die Sitzung (nur im Speicher, COOP), Apps laufen ohne `allow-same-origin`. Bridge-3-Server auf dem PC
  gelten als vertrauenswürdig (eigener Code des PC-Besitzers). Abhilfe später: eigene Domain (§10).
- Wer einen Wiederherstellungs-Code an einem bösen Speicher-Knoten einlöst, verrät ihn diesem Knoten (er könnte
  schneller sein) – deshalb nur an einem Eingang des Netzes einlösen, dem man traut.
- Ein böser Speicher-Knoten kann viele Konten anlegen und die Grenze von 100.000 füllen (neue Konten gehen dann nicht
  mehr) oder Konten verweigern. Abhilfe: Siegel entziehen (der Owner).
- Eine App, die sich selbst auf eine fremde Seite umleitet, kann ihr eigenes App-Zeichen dorthin mitnehmen – es gilt
  nur für diese App und höchstens 1 h.
- Der Abgleich merkt sich seinen Stand nur im RAM: nach einem Neustart holt ein Speicher-Knoten alle Einträge noch
  einmal (schon bekannte kosten nur einen Vergleich).

### 9.6 Abnahme Schritt 4
- e2e (`tests/e2e/tests/phase7_login.rs`, Test-Authenticator ES256): registrieren, anmelden, wiederherstellen, Abgleich
  zum zweiten Speicher-Knoten; Angriffe (Challenge zweimal, fremder Ursprung/RP, falsche Zeremonie, fremder Passkey,
  Zähler rückwärts, falsche Signatur, falscher Code, verbrauchter Code, Sitzung eines Fremden, Grenze 5 je Stunde);
  App-Zeichen für den Server-Code (fremde App, kaputt, zu lang, Aussteller ohne Siegel, Preflight); Hülle mit Skript.
- In Chromium mit virtuellem Authenticator geprüft (registrieren → Code → abmelden → mit Passkey anmelden → neuer
  Authenticator → wiederherstellen; die App bekommt Nutzer, Name und Zeichen).
- BridgeControll: Ampel und „Login hier einschalten“ (auch durch das Tor), Ablehnungen; UI-Rauchtest Bilder 34–35.

## 10. Später (optional)
- **Eigene Domain** (eigene Herkunft pro Netz, schönere Adressen) – ganz am Ende und nur optional; Bridge muss ohne
  Kosten funktionieren.
- Das Tor auch hinter anderen kostenlosen Tunneln oder einer Portfreigabe.

## 11. Abnahme Schritt 1
- Tor: Routing (mit und ohne `/bridge4`), Not-Aus, Methoden, Pfad-Angriffe, gefälschte Köpfe, Grenzen, Streaming einer
  großen Datei und eines Long-Polls – Tests mit echten Knoten hinter dem Tor.
- Knoten: Leser `public` nur mit dieser Einstellung; Startseite und Hülle (HTML-Kodierung, 18+, gebannte App, unbekannter
  Name, CSP).
- BridgeControll: „Öffentlich machen“/„Websites aus“/„Nicht mehr öffentlich“ mit einem Tailscale-Ersatz (Befehle,
  Fehler, nie `reset`, nur `/bridge4`), 18+-Netz abgelehnt, Owner-Knoten neu gesiegelt.
- `cargo fmt`, `clippy -D warnings`, alle Tests grün; Sicherheits-Prüfung.

## 12. Offen
- Ob Tailscale den Pfad `/bridge4` abschneidet, hängt von der Version ab – das Tor kann beides; Paddys erster Echttest
  zeigt es.
- ~~Öffentliche Knoten von Mitgliedern~~ und ~~Tor-Neustart bei jeder Änderung~~: gelöst in §13 (Phase 8).
- App-API (`/app/<id>/api/…`) öffentlich nur, wenn der öffentliche Knoten die App selbst hostet (docs/09 §9 bleibt
  offen).

## 13. Phase 8, Schritt 2: Eingänge auf PCs von Mitgliedern (gebaut 13.11.2026)
Damit ein PC außerhalb des LANs dem Netz helfen kann (Speicher, Empfänger, zweiter Login-Knoten), müssen die anderen
Knoten ihn erreichen. Dafür braucht er eine eigene öffentliche Adresse – Websites zu zeigen ist eine andere Sache.
- **Erreichbar machen** (BridgeControll, Knoten eines Mitglieds): derselbe Ablauf wie „Öffentlich machen“ (§5) auf
  dem eigenen PC – Tailscale Funnel `/bridge4` → Tor → Knoten, Adresse `https://<sein gerät>.ts.net/bridge4/<netz>`,
  Leser `public`. Neu siegeln kann nur der Owner: das Mitglied schickt ihm seinen **Knoten-Ausweis** (enthält die neue
  Adresse), der Owner siegelt damit („Knoten von einem anderen PC siegeln“), z. B. mit `storage` auf Stufe 2.
- **Websites nur bei Stufe 3** (die Regel im Knoten, `Node::website_entrance`): Startseite, Hülle, `/login.js` und
  `/app/…` für Besucher aus dem Internet gibt es nur an einem Knoten, dessen Siegel Stufe 3 hat – der Owner-Knoten oder
  ein Knoten, dem der Owner so vertraut (Stufe 3 heißt im Netz „vertraut“). Jeder andere öffentliche Knoten ist nur für
  das **Protokoll** (`/v4/…`) erreichbar; `/` sagt das („Hier gibt es keine Websites“). Bridge Login (`/v4/login/…`)
  läuft auch an solchen Speicher-Knoten – Konten anlegen und anmelden lässt die Hülle aber nur an Website-Eingängen.
  Ein Mitglied, das seinen Knoten von Hand anders startet, umgeht das nur auf dem eigenen PC (er hat die Daten ja);
  das Netz zeigt seine Adresse erst, wenn der Owner sie siegelt.
- **Das Tor lädt seine Routen ohne Neustart**: BridgeControll schreibt die Routen-Datei ganz (umbenennen), das laufende
  Tor nimmt sie binnen einer halben Sekunde (laufende Anfragen behalten ihre Routen); eine kaputte Datei ändert nichts.
  Neu gestartet wird es nur, wenn es nicht läuft.
- Tests: e2e `phase7_public` (Stufe 2 nur Protokoll, mit Stufe 3 Websites), Tor (neue Routen ohne Neustart, kaputte
  Datei), BridgeControll (zweiter PC macht seinen Knoten erreichbar: Protokoll durch sein Tor, keine Websites).

## 14. Phase 8, Schritt 3: Ein Konto auf mehreren Geräten (gebaut 14.11.2026)
Paddy: dasselbe Konto auf PC und Handy – ohne die Windows-/Google-Fenster für Passkeys fremder Geräte. Jedes Gerät
bekommt deshalb **seinen eigenen Passkey**; ein Gerät, das schon angemeldet ist, nimmt das neue ins Konto auf.

### 14.1 Einträge `add` und `remove`
- `add` `{op, v, account, cred:{id, alg, key}, label, at, approval}`: neues Gerät mit Namen (1–40 Zeichen wie der
  Anzeigename), höchstens 8 Geräte, ein Passkey nur einmal (auch nicht in einem anderen Konto).
- `remove` `{op, v, account, target, at, approval}`: der Passkey `target` geht; das letzte Gerät bleibt immer.
- `approval` `{cred, client_data, auth_data, sig}`: eine WebAuthn-Anmeldung (`webauthn.get`) eines **Passkeys, den das
  Konto schon hat**, über die Challenge `H("bridge4/login/approve\n" ‖ kanonischer Eintrag ohne approval)`. Jeder
  Speicher-Knoten prüft selbst: Passkey gehört zum Konto, Zeremonie, Challenge, Flag „User Present“, Signatur. Ursprung
  und Relying Party prüft nur der Eingang, der den Eintrag annimmt (wie bei `create`). Ein Knoten kann also kein Gerät
  in ein fremdes Konto schmuggeln und keines entfernen.
- Gespeicherte Form des Kontos: `devices:[{cred, label, added}]` (die alte Form mit einem `cred` wird weiter gelesen).

### 14.2 Gerät hinzufügen (A: angemeldet, B: neues Gerät)
1. A: **„Geräte“ → „Gerät hinzufügen“** – `POST /v4/login/pair/start {session, link}` → **Kopplungs-Code**: 8 Zeichen
   aus `ABCDEFGHJKMNPQRSTUVWXYZ23456789` (ohne Verwechsler 0/O, 1/I/L), gezeigt als `XXXX-XXXX`, 5 Minuten gültig,
   genau einmal; dazu derselbe Code als **QR-Code** von `<link>#koppeln=<code>`. `link` muss eine Seite des eigenen
   Eingangs sein (≤ 512 Zeichen); der Teil nach `#` geht nie an einen Server.
2. B: öffnet dieselbe Website → Anmelden → **„Konto schon auf einem anderen Gerät? Verbinden“**, gibt den Code ein
   (Groß/klein, Leerzeichen und `-` egal) und einen Gerätenamen – oder scannt den QR-Code, dann steht der Code schon
   drin. `pair/join {code, label}` → Ticket (16 Byte), Challenge, Kontoname. **Falsche Codes: höchstens 5 je Adresse
   in 10 Minuten**, dann `429`.
3. B legt **seinen eigenen Passkey** an (`webauthn.create` mit dieser Challenge, geprüft wie beim Registrieren) –
   `pair/offer {ticket, credential, client_data, auth_data}` → **Prüfzahl**: 3 Ziffern aus
   `H("bridge4/login/pair\n" ‖ ticket ‖ öffentlicher Schlüssel)`.
4. A sieht (`pair/status`) den Gerätenamen und dieselbe Prüfzahl. Stimmt sie, bestätigt A mit **seinem** Passkey
   (`pair/approve`, signiert den `add`-Eintrag) – oder lehnt ab (`pair/cancel`). Die Prüfzahl verhindert, dass jemand,
   der den Code mitgelesen hat, schneller ist und sein eigenes Gerät unterschieben lässt.
5. B fragt alle 2 Sekunden (`pair/wait {ticket}`) und bekommt nach der Bestätigung seine Sitzung – angemeldet. Danach
   meldet sich B mit seinem eigenen Passkey an, A weiter mit seinem.

Alles Offene (Codes, Tickets, Fehlversuche) liegt nur im RAM des Eingangs, höchstens 10.000 je Art; A und B müssen
denselben Eingang benutzen.

### 14.3 Meine Geräte
- `POST /v4/login/devices {session}` → Name und Geräte (Name, hinzugefügt am); die Leiste zeigt „Geräte“ neben
  „Abmelden“ und markiert „(dieses Gerät)“.
- **Entfernen**: `remove/prepare {session, target}` → Challenge (2 min) des `remove`-Eintrags;
  `remove {session, credential_id, client_data, auth_data, signature}` mit einem Passkey des Kontos → Eintrag. Wer
  das eigene Gerät entfernt, ist danach abgemeldet. Ein verlorenes Gerät entfernt man von einem anderen; sind alle weg,
  hilft der Wiederherstellungs-Code (§9.3, danach hat das Konto wieder nur ein Gerät).

### 14.4 Restrisiken
- Wer Code **und** Prüfzahl von einem fremden Bildschirm abliest und A zum Bestätigen bringt, hat ein Gerät im Konto –
  dagegen hilft nur, die Prüfzahl wirklich zu vergleichen; „Meine Geräte“ zeigt jedes Gerät mit Namen und Datum.
- Ein Passkey gilt weiter nur für den Host eines Eingangs (§9.2); für einen zweiten Eingang braucht jedes Gerät dort
  einen eigenen Passkey (später: gemeinsame Domain).

### 14.5 Abnahme Schritt 3
- Kern (`bridge-core::login`): `add`/`remove` nur mit Unterschrift eines Passkeys des Kontos (nicht der neue selbst,
  kein fremder, keine andere Challenge, keine falsche Zeremonie), höchstens 8, letztes bleibt, `recover` wirft alle
  anderen hinaus, alte gespeicherte Form lesbar. Speicher: Passkey → Konto über `login_credentials`, Entfernen gibt ihn
  frei.
- e2e (`tests/e2e/tests/phase8_devices.rs`): koppeln, Prüfzahl, bestätigen, B meldet sich mit eigenem Passkey an, der
  `add`-Eintrag erreicht den zweiten Speicher-Knoten, entfernen, letztes Gerät bleibt, ablehnen; Angriffe (Link eines
  fremden Ursprungs, Code zweimal, der neue Passkey bestätigt sich selbst, ein fremdes Konto bestätigt, Code raten →
  `429`, ohne Sitzung `401`).
- In Chromium mit zwei virtuellen Authenticatoren geprüft (A zeigt Code und QR-Code, B öffnet `#koppeln=…`, gleiche
  Prüfzahl, A bestätigt, beide Apps sehen dieselbe Nutzer-ID, B meldet sich neu an, A entfernt „Handy“).
