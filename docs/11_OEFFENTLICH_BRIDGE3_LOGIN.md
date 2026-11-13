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
| 4 | **Was kann mein Netz?** (Fähigkeiten-Ampel) und **Bridge Login** (Konten mit Passkeys, Daten pro Nutzer) | `bridge-net`, Knoten, BridgeControll v2, SDKs |

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
| Alle Websites haben **dieselbe Herkunft** (`<gerät>.ts.net`) – eine böse Seite liest Cookies/Speicher einer anderen | Jede App läuft in einer eigenen undurchsichtigen Herkunft (CSP `sandbox` ohne `allow-same-origin`, docs/07 §5) – sie hat gar keine Cookies und keinen Speicher der Herkunft; die Hülle hat keine Skripte. Login nur über Bridge (Schritt 4), nie in der App. |
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

## 9. Schritt 4: Was kann mein Netz? und Bridge Login
- **Fähigkeiten-Ampel**: Jedes Feature sagt, was es im Netz braucht (z. B. Bridge Login: 2 Speicher-Knoten mit Siegel
  auf verschiedenen PCs; KI: ein KI-Knoten; öffentlich: ein öffentlicher Knoten). BridgeControll zeigt grün/rot und
  was fehlt; ein Feature ohne Rückhalt ist aus.
- **Bridge Login** (Konten für Websites/Apps): Passkeys (WebAuthn) statt Passwörtern, Passwort nur als Notlösung (stark
  gehasht); Mitglieder melden sich mit ihrem Bridge-Ausweis an; **eine eigene Nutzer-ID pro App** (keine Verfolgung
  über Apps hinweg); Wiederherstellungs-Codes (keine E-Mail); Rechen-Rätsel (PoW) gegen Bot-Anmeldungen; Konten
  verschlüsselt auf den Speicher-Knoten, abgeglichen über das Ereignis-Log (docs/09). Der Login läuft in der Hülle
  (vertrauenswürdige Seite), nie in der App; die App bekommt nur ein Zeichen „Nutzer X dieser App“.
- **Speicher für Apps – die App entscheidet**: (a) **lokal auf ihrem Knoten** (schnell, gut für Websites mit einem
  Host) oder (b) **Bridge-Speicher** im Netz (verteilt, überlebt Ausfälle). Bridge stellt beide Werkzeuge bereit,
  auch pro Nutzer.

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
- Öffentliche Knoten von Mitgliedern (z. B. ein zweiter PC als weiterer öffentlicher Eingang): erst mit einer
  Manifest-Regel, mit der der Owner das erlaubt; bis dahin nur der Owner-Knoten. Mit der Kommandozeile kann jeder seinen
  eigenen Knoten so starten – technisch verhindern lässt sich das nicht, er hat die Daten ja.
- Das Tor startet bei jeder Änderung neu (kurz keine Verbindung); später ggf. Routen ohne Neustart neu laden.
- App-API (`/app/<id>/api/…`) öffentlich nur, wenn der öffentliche Knoten die App selbst hostet (docs/09 §9 bleibt
  offen).
