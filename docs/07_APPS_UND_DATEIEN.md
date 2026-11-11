# 07 – Apps und Dateien (Phase 4a)

*Stand 11.11.2026: gebaut (siehe „Beim Bau festgelegt“ in §3, nach §5 und §8; Grenzen in §9). Nachgeschärft nach
dem 7. Review (Kontingent-Reservierung, Rang-Gedächtnis, Stopp-Signale, Lesefehler, Ströme – „Review 7“ in §3, §5,
§8, §9 und ADR 0015).*

Paddys Idee (11.11.2026): Clients erstellen **Bridge-Apps**. Eine App ist wie eine Website, nur größer, und kann von
**mehreren Hosts** gleichzeitig angeboten werden. Fällt einer aus, läuft sie bei den anderen weiter. Der **Owner**
bestimmt, wer mit-hosten darf. Bridge verteilt Code und Dateien der App selbst. App-**Daten** gleicht die App selbst ab;
Bridge liefert dafür Werkzeuge (Stufe 2, §6).

Stufe 1 (dieses Dokument): Apps **ohne eigenen Server-Code** (Oberfläche + Dateien). Server-Code kommt mit der
WebAssembly-Sandbox (Phase 5). Grundlage für beides ist die **Datei-Übertragung** (§1).

## 1. Dateien (Blobs)
- Eine Datei wird in **Teile à 64 KiB** zerlegt (das letzte kürzer; eine leere Datei hat 0 Teile).
- **Blob-ID** = Base64url(SHA-256(`"bridge4/blob/v1\n"` ‖ Größe als 8 Byte big endian ‖ h₀ ‖ h₁ ‖ …)),
  hᵢ = SHA-256(Teil i). Die ID legt Größe und jeden Teil fest. Wer die ID kennt, kann jede Quelle prüfen.
- **Hash-Liste**: die hᵢ der Reihe nach (max. 65.536 Teile = 4 GiB). Ein Downloader holt zuerst die Hash-Liste,
  prüft sie gegen die ID, dann die Teile – von **beliebig vielen Quellen parallel**, jeden Teil einzeln geprüft,
  fortsetzbar.
- Bridge sieht Blobs nur als Bytes. **Private Dateien** verschlüsselt der Client vorher (Werkzeug in `bridge-core`:
  Datei-Schlüssel 32 Byte Zufall, je Teil ChaCha20-Poly1305 mit Nonce = Zufalls-Präfix 8 Byte ‖ Teilnummer, AAD =
  `"bridge4/file/v1"` ‖ Teilnummer ‖ letztes-Flag; N1 gilt). Der Schlüssel reist im Umschlag (Klartext-Art `data`).
- **Lesen**: Wer die Blob-ID kennt, darf lesen (256 Bit, nicht zu erraten). Vertrauliches ist verschlüsselt.
- **Schreiben**: nur angemeldete Mitglieder. Kontingente je Stufe (Standard: Stufe 0 = 50 MiB, 1 = 1 GiB,
  2+ = 10 GiB; Knoten gesamt einstellbar). Ein Blob bleibt, solange er **festgehalten** wird: vom Hochlader mit
  Ablauf (max. 30 Tage, verlängerbar) oder von einer App-Version, die der Knoten hostet. Sonst räumt der Knoten auf.
- Ablauf Hochladen: `begin` (Größe + Hash-Liste, Kontingent wird reserviert) → `chunk` × n (jeder Teil wird gegen
  seinen Hash geprüft) → fertig, wenn alle Teile da sind. Doppelte Blobs werden nur einmal gespeichert.

## 2. App-Identität
- Jede App hat einen **eigenen Schlüssel** (Rolle `app`); **App-ID** = dessen ID. Der Owner hält den App-Schlüssel
  (Datei im eigenen Datenordner) – nie ein Host.
- Jede Version trägt zusätzlich die Signatur des **Owners** (ein Mitglied des Netzes). So weiß das Netz, wer für die
  App verantwortlich ist (Missbrauch, Meldungen, Sperren).

## 3. App-Manifest (eine Version)
Aussage der Art `app` (04 §3), `net` = Netz-ID, **zwei Signaturen** (`sigs`: App-Schlüssel + Owner):
```json
{"app":"<app-id>","owner":"<mitglied-id>","name":"Mein Spiel","description":"…","version":3,
 "entry":"index.html",
 "files":[{"path":"index.html","blob":"<blob-id>","size":1234,"type":"html"}],
 "hosts":["<knoten-id>","<knoten-id>"],
 "card":<schlüsselkarte des app-schlüssels>,"owner_card":<schlüsselkarte des owners>}
```
- `version` steigt um genau 1. Die höchste gültige Version gilt; `exp` max. 1 Jahr.
- `files`: max. 10.000 Einträge, zusammen max. 4 GiB. `path`: max. 200 Zeichen, nur `a-z A-Z 0-9 . _ - /`, keine
  leeren Teile, kein `.`/`..`, nicht mit `/` beginnend, jeder Pfad nur einmal. `type` aus einer festen Liste
  (html, css, js, json, png, jpg, gif, webp, svg, ico, wasm, woff2, txt, mp3, ogg, mp4, webm, bin).
- `hosts`: 1–64 Knoten-IDs. Ein Host muss im Netz ein gültiges Siegel mit Dienst `web` haben (Stufe ≥ 1), sonst
  zählt er nicht. Die Karte (mit Adressen) kommt aus dem Siegel.
- Gültig ist ein Manifest nur, wenn: beide Signaturen stimmen, der Owner Mitglied ist, nicht gesperrt, mindestens
  die Stufe `apps.min_level` aus dem Netz-Manifest hat (neues optionales Feld, Standard 0), und weder App noch Owner
  gesperrt sind (`ban` im Netz-Log wirkt auch auf App-IDs).
- *Beim Bau festgelegt*: Beide Schlüsselkarten reisen im `body` mit (`card`: Rolle `app`, ID = `app`; `owner_card`:
  Rolle `client` oder `node`, ID = `owner`) – so prüft jeder beide Signaturen ohne weitere Quelle (wie `card` in der
  Delegation). Alle Felder sind Pflicht, unbekannte Felder (auch in `files`-Einträgen: genau `{path, blob, size,
  type}`) machen das Manifest ungültig. `name` 1–64 Zeichen, `description` 0–500 (Zeilenumbruch erlaubt), `files`
  1–10.000, `entry` muss eine der Dateien sein, App-ID ≠ Owner. `type` steht als Kurzname im Manifest (`html`,
  `css`, …); der `Content-Type` beim Ausliefern kommt aus einer festen Zuordnung (§5).
- *Beim Bau festgelegt*: Ein App-Manifest darf bis **960 KiB** groß sein (andere Aussagen 64 KiB, 04 §1) – es muss in
  eine Anfrage (1 MiB) passen. 10.000 Dateien gehen damit nur mit kurzen Pfaden (~100 Byte je Eintrag).
- *Beim Bau festgelegt*: **Versionen**. Der Owner zählt um genau 1 hoch (SDK und Kommandozeile tun das). Ein Host nimmt
  jede **höhere** Version (er kann welche verpasst haben); bei gleicher Version gewinnt der größere Hash der Aussage
  (ohne Signaturen, 06 §3) – so landen alle Hosts bei derselben. Ältere Versionen lehnt er ab (`409 REPLAY`,
  Rollback-Schutz), auch nach dem Aufhören.
- *Beim Bau festgelegt (Review 7)*: **Rang-Gedächtnis**. Rang = (Version, Hash der Aussage). Je App merkt sich ein
  Knoten den höchsten Rang, über den er entschieden hat: angenommen, abgelehnt (Kontingent, Dateien nicht zu
  bekommen, §5) oder die Version, die ihn als Host **entfernt** hat. Angenommen wird danach nur, was **echt höher**
  ist; die gerade ausgelieferte oder wartende Version noch einmal ist `ok` und ändert nichts, alles andere →
  `409 REPLAY`. Das gilt auch nach dem Aufhören – ein entfernter Host lässt sich nicht mit der alten Version
  wiederbeleben; nach einer Sperre, einem Ablauf oder einer Ablehnung veröffentlicht der Owner eine neue Version.
  In der Datenbank wird der Rang nur erhöht (`MAX`), nie gesenkt.
- *Beim Bau festgelegt (Review 7)*: **Beendete Apps** behalten nur App-ID, Owner und Rang (rund 150 Byte, keine
  Manifeste). Vergessen wird ein Eintrag erst **1 Jahr + 1 Tag** nach dem Aufhören – dann ist jede Version, die es
  damals gab, abgelaufen (`exp` max. 1 Jahr), das Vergessen öffnet also keinen Rückweg. Zusätzlich je Owner höchstens
  1.024 beendete Apps auf einem Knoten (darüber seine ältesten: das schwächt nur den Schutz seiner eigenen Apps) und
  je Knoten höchstens 100.000; ist das voll, nimmt der Knoten **keine neue** App an (`429 QUOTA_EXCEEDED`, fail
  closed), bis Einträge alt genug sind.
- *Beim Bau festgelegt*: Die Art `app` steht **nicht** im Log (wie `home`); das Log bleibt der Verwaltung. `blob/v1` und
  `file/v1` sind nur Hash- bzw. AAD-Domänen (nichts wird damit signiert) und kollidieren mit keiner Aussage-Art.
  Schlüssel der Rolle `app` melden sich nie an (`FORBIDDEN`).

## 4. Hosten und Verteilen
- **Veröffentlichen**: Der Owner lädt die Dateien als Blobs zu einem seiner Hosts hoch und gibt dort das Manifest ab
  (`/v4/app/publish`). Ein Knoten nimmt ein Manifest nur an, wenn er selbst in `hosts` steht.
- **Abholen statt schicken**: Jeder Host fragt die anderen Hosts der App alle 30 s nach dem neuesten Manifest
  (`/v4/app/manifest`). Bei einer neuen Version holt er die **fehlenden** Blobs von allen anderen Hosts (parallel,
  geprüft), stellt erst um, wenn alles da und geprüft ist (atomar), und behält die vorige Version als Rückweg.
- **Host entfernen**: neue Version ohne diesen Host. Ein Host, der sich nicht mehr in der neuesten Version findet,
  hört sofort auf auszuliefern und gibt die Blobs frei. Sperrt das Netz die App oder den Owner, hören alle Hosts auf.
- **Grenzen**: max. 64 gehostete Apps pro Knoten (einstellbar), je Owner nach seiner Stufe höchstens 4 / 16 / 64
  (Stufe 0 / 1 / 2+, einstellbar), Speicher über die Kontingente des Owners auf diesem Knoten – bei der Annahme für die
  ganze Version reserviert (§5).

## 5. Ausliefern an Browser
- `GET /app/<app-id>/<pfad>` liefert die Datei der aktuellen Version, `GET /app/<app-id>/` den `entry`.
- **Jede App bekommt eine eigene, abgeschottete Herkunft**: `Content-Security-Policy: sandbox allow-scripts
  allow-forms allow-popups` (ohne `allow-same-origin`). App-Code kommt so weder an andere Apps noch an den Knoten.
  Dazu `X-Content-Type-Options: nosniff`, `Content-Type` nur aus dem Manifest, `Cache-Control` mit der Blob-ID als
  ETag.
- Die Bridge-API (`/v4/…`) erlaubt Aufrufe aus Apps (CORS `*`, nur mit Bearer-Token, keine Cookies).
- Clients wählen einen Host aus `hosts` (LAN vor Internet, dann der schnellste). Fällt er aus, nehmen sie den nächsten.

*Beim Bau festgelegt (§1, §4, §5):*
- **Dateien auf der Platte**: `blobs/<2 hex>/<64 hex>` im Daten-Ordner, benannt nach der Blob-ID in Kleinbuchstaben-Hex
  (Base64url unterschiede sich auf manchen Dateisystemen nur in Groß/Klein). Solange Teile fehlen, heißt die Datei
  `<hex>.part`; ist der letzte Teil da, wird sie gesichert (`fsync`) und umbenannt. Metadaten in SQLite (Schema 5,
  ergänzt in Schema 6): Blob (Größe, Teile, welche da sind), Hash-Liste (Zeilen zu 1.024 Hashes), Festhalter
  (`up:<id>` = Hochlader mit Ablauf, `app:<app-id>` = gehostete App, bis zur Freigabe; seit Schema 6 mit der Größe,
  die er reserviert), Apps (aktuelle, vorige, wartende Version, Zustand, seit Schema 6 der Rang als Version + Hash).
- **Jeder gelesene Teil wird erneut gegen seinen Hash geprüft.** Passt er nicht (kaputte Platte), wird er nie
  ausgeliefert, gilt als fehlend und wird beim nächsten Takt von einem anderen Host geholt.
- *Review 7* – **Lesefehler sind kein Datenverlust**: Als verloren gilt ein Teil nur, wenn sein Hash nicht passt oder
  die Datei zu kurz ist. Jeder andere Lesefehler (Datei gerade weg oder gesperrt, keine Rechte, Platte hängt) →
  `503 UNAVAILABLE`, ohne etwas zu ändern (beim Strom: Verbindung abbrechen). Bevor fehlende Teile der ausgelieferten
  Version von anderen Hosts geholt werden (Reparatur im Takt), prüft der Host die eigene Datei: Teile, die dort
  (wieder) stimmen, zählen sofort wieder als da – so repariert sich auch ein Host ohne andere Quelle.
- **Hochladen**: `begin` braucht die ganze Hash-Liste; über 4.096 Teile (256 MiB) in Seiten zu 4.096 (`from` = 0,
  4.096, …, der Reihe nach). Seiten warten **je Hochlader** (max. 4 Listen je Hochlader, 64 je Knoten, 1 Stunde) – so
  kann niemand eine Blob-ID mit einer falschen Liste für andere besetzen. Erst die vollständige, gegen die ID geprüfte
  Liste legt den Blob an. `keep_days` 1–30 (Standard 1); ein Festhalten wird nie kürzer, nur länger. `chunk` nur von
  einer Identität, die den Blob mit `begin` festhält.
- **Kontingente**: gezählt werden die **verschiedenen** Blobs, die ein Owner festhält (gleich ob als Hochlader oder
  über seine Apps), jeder mindestens mit 4 KiB (gegen Fluten winziger Blobs). Knoten gesamt Standard 20 GiB und
  1.000.000 Blobs. Ein Festhalter einer App zählt mit der Größe aus dem Manifest, auch solange der Blob hier noch
  fehlt (Reservierung, siehe „Kontingent auf dem Host“). Apps gibt es nur im Netz.
- *Review 7* – **Knoten ohne Netz**: Ohne Netz ist jede angemeldete Identität anonym (beliebig viele, je 50 MiB
  würden die Platte füllen). Daher nimmt ein Knoten ohne Netz **standardmäßig keine Blobs an** (`begin`/`chunk` →
  `403 FORBIDDEN`). Einschalten nur bewusst mit einer Obergrenze für alle Blobs zusammen (`Limits::standalone_blobs`,
  Kommandozeile `--standalone-blobs <MiB>`); dann gilt je Identität das Kontingent von Stufe 0 und für den Knoten
  höchstens diese Grenze (und nie mehr als die Knoten-Grenze). Lesen geht immer.
- **Aufräumen**: Der Hausmeister (alle 60 s) löscht abgelaufene Festhalter, Festhalter `app:<id>` von Apps, die dieser
  Knoten nicht (mehr) hostet (Netz gegen Wettläufe beim Aufhören), alte wartende Hash-Listen und dann bis zu 1.000
  Blobs, die niemand mehr festhält (erst die Zeile, dann die Datei). `chunk` zählt nur Festhalter, die noch nicht
  abgelaufen sind.
- **Private Dateien**: Klartext-Stücke zu 65.520 Byte – ein verschlüsseltes Stück (+16 Byte Tag) ist genau ein Teil
  von 64 KiB, Teile lassen sich also einzeln und in beliebiger Reihenfolge öffnen (paralleles Laden). Eine leere Datei
  hat ein Stück (nur der Tag). Der Schlüssel für den Umschlag sind 40 Byte (Schlüssel ‖ Präfix), `FileKey::to_bytes`.
- **Wie der zweite Host von einer Version erfährt**: Ein Host, der bei einem anderen Host der App nichts oder eine
  ältere Version findet, **bietet** ihm seine an: `POST /v4/node/app` mit `{"manifest":<aussage>,"rq":<rq>}` (`op:
  "app"`, `body: {"manifest":"<hash der aussage>"}`, signiert vom anbietenden Host – wie bei der Weiterleitung bindet
  die Anfrage die große Aussage über ihren Hash). Angenommen nur, wenn der Anbieter ein Host mit `web`-Siegel ist,
  in der Version steht, die Anfrage frisch und einmalig ist und die Version für den Empfänger selbst gilt (oder – als
  Stopp-Signal, s. u. – eine echt neuere Version einer App ist, die er hostet). Die Dateien holt der Empfänger danach
  selbst (Abholen statt schicken). Lehnt ein Host ein Angebot ab, bietet der Anbieter ihm dieselbe Version erst nach
  einer Pause wieder an (Takt × 2ⁿ, höchstens 6 Stunden; je App und Host gemerkt, max. 4.096 Einträge).
- **Takt je App** (Standard 30 s, `NetTiming::apps`): gilt die neueste Version noch (Ablauf, Netz-Regeln, dieser Knoten
  ein gültiger Host)? Sonst sofort aufhören. Dann höchstens 8 andere Hosts fragen – *Review 7*: erst die
  **Kopf-Form** (`/v4/app/manifest` mit `{"app","head":true}` → `{"version","hash"}`, ein paar Byte); das ganze Manifest
  (bis 960 KiB) nur, wenn dessen Rang höher ist als alles, worüber dieser Knoten schon entschieden hat. Einer neueren
  gültigen Version folgen (oder aufhören, wenn sie diesen Knoten nicht mehr nennt), Hosts mit einer älteren oder
  keiner Version die eigene anbieten (mit Pause nach Ablehnung, s. o.). Dann fehlende Blobs der wartenden Version:
  Blobs, die hier schon angelegt sind, bekommen ihre fehlenden Teile; für Blobs, die hier noch fehlen, fragt der Host
  **höchstens 64 je Takt** bei bis zu 8 anderen Hosts `/v4/blob/info` und holt die Hash-Liste nur von einem Host, der
  den Blob mit der richtigen Größe hat (erste Liste, die zur ID passt). Teile: 4 Blobs zugleich mit je 8 Teilen parallel über alle anderen Hosts verteilt; ein Host, der einen falschen Teil
  schickt, wird für diesen Blob nicht mehr gefragt, der Teil kommt von einem anderen. Umgestellt wird erst, wenn alle
  Teile da sind – erst in der Datenbank, dann im Speicher; die vorige Version bleibt mit ihren Blobs festgehalten
  (aktuelle ∪ vorige).
- *Review 7* – **Aufgeben mit Pause**: Ein Takt, in dem für die wartende Version kein Teil dazukommt, ist ein
  Fehlversuch; der nächste Versuch kommt erst nach Takt × 2ⁿ (höchstens 16 × Takt, Standard 8 min). Nach **12
  Fehlversuchen in Folge** (Standard rund 70 Minuten ohne jeden Fortschritt) wird die wartende Version verworfen: Rang
  als abgelehnt gemerkt, Reservierung frei; ohne ausgelieferte Version hört der Host ganz auf (sein Platz ist frei).
  Ein Takt mit Fortschritt setzt den Zähler zurück; bleibt dabei Arbeit übrig (Grenze 64 erreicht), folgt der nächste
  Takt sofort. So kostet eine Version, deren Dateien es nirgends gibt, höchstens 12 Holversuche mit je ≤ 64 × 8
  `info`-Fragen (dazu die üblichen ≤ 8 Kopf-Fragen je Takt, solange sie wartet).
- **Kontingent auf dem Host** – *Review 7*: Bei der Annahme **reserviert** der Host die ganze Version auf das
  Kontingent ihres Owners (nach seiner Stufe): jeder Blob der Version wird sofort für die App festgehalten, mit der
  Größe aus dem Manifest, auch wenn er hier noch fehlt – in derselben Transaktion wie die App-Zeile. Gezählt wird wie
  bei Blobs (verschiedene Blobs, je mind. 4 KiB), aktuelle + vorige + neue Version zusammen. Reicht es nicht:
  `429 QUOTA_EXCEEDED`, es wird nichts gespeichert und kein Platz belegt; hostet der Knoten die App schon, merkt er
  sich den Rang als abgelehnt. Holen legt einen Blob nur an, wenn die App ihn dann noch festhält – ein Festhalter
  entsteht nie außerhalb der Annahme (kein Wettlauf mit dem Aufhören). Ist beim Holen der Knoten voll, wird die
  wartende Version verworfen wie oben. Dazu je Owner höchstens 4 / 16 / 64 gehostete Apps (Stufe 0 / 1 / 2+,
  `Limits::max_apps_per_owner`) neben der Knoten-Grenze von 64.
- **Veröffentlichen** geht an einen Host, der zugleich **Empfänger** ist: Anmelden (Sitzung) gibt es nur bei
  Empfängern (06 §7). Antwort `{"ok":true,"version":n,"active":bool}` (`active`: sofort ausgeliefert, sonst holt der
  Host noch Dateien). Ein Host zählt nur mit einem Siegel Stufe ≥ 1 mit Dienst `web`; ein Empfänger ohne `web` lehnt
  ab (`FORBIDDEN`), ebenso ein Knoten, der nicht in `hosts` steht (außer als Stopp-Signal für eine App, die er hostet:
  dann `{"ok":true,"version":n,"active":false}`).
- **Aufhören**: neueste Version nennt diesen Knoten nicht mehr, App oder Owner gesperrt, Owner kein Mitglied mehr oder
  unter `apps.min_level`, Version abgelaufen. Dann sofort nichts mehr ausliefern, Blobs freigeben, Rang merken (bei
  einer neueren Version, die den Knoten nicht nennt: deren Rang). Eine Sperre wirkt beim Ausliefern sofort (jede
  Anfrage prüft den Netz-Zustand), der Takt räumt danach auf.
- *Review 7* – **Stopp-Signal und Host-Wechsel**: Eine gültige, echt neuere Version, die diesen Knoten nicht nennt,
  ist für einen Knoten, der die App hostet, ein **Stopp-Signal** – voll geprüft (beide Signaturen, Netz-Regeln), egal
  ob sie beim Fragen der anderen Hosts kommt, als Angebot (`/v4/node/app`), vom Owner (`/v4/app/publish`) oder von
  irgendwem über `POST /v4/app/update` (ohne Anmeldung, Lese-Grenze; nur für Apps, die der Knoten hostet – sonst
  `404`; die doppelte Signatur ist der Beweis, wer sie bringt, ist egal). Eine neuere Version, die ihn nennt, nimmt
  er dort genauso an wie ein Angebot. Wer zu einer neueren Version wechselt oder wegen einer aufhört, schickt sie
  einmal (bestmöglich, höchstens 4 solche Läufe zugleich) per `/v4/app/update` an die Hosts seiner bisherigen Version,
  die sie nicht mehr nennt. Ein ganz neuer Host kennt die alten Hosts nicht – deshalb gibt die Kommandozeile bzw. das
  SDK (`announce_app`) beim Ändern der Hosts die neue Version auch an die alten Hosts (§8). So hört bei
  v1 [Owner, a] → v2 [b] niemand zu spät auf. Die neuen Hosts müssen die Dateien dann schon haben oder von einem Host
  der neuen Version holen können (ein alter Host, der aufhört, gibt sie frei) – deshalb verlangt die Kommandozeile
  beim Umzug ohne Hochladen, dass ein bisheriger Host bleibt (§8).
- *Review 7* – **Neustart**: Geladen werden höchstens `max_hosted_apps` Apps – die zuletzt geänderten zuerst, bei
  Gleichstand nach App-ID. Weitere (z. B. nach dem Senken der Grenze) werden beendet (Blobs frei, Rang gemerkt). Eine
  Version, die nur abgelaufen ist, wird trotzdem geladen und im ersten Takt ganz normal beendet – der Rang bleibt,
  nichts wird stillschweigend genullt.
- **Ausliefern**: genau diese Köpfe bei jeder Antwort unter `/app/` (auch Fehler und Ablehnungen):
  `Content-Security-Policy: sandbox allow-scripts allow-forms allow-popups`, `X-Content-Type-Options: nosniff`,
  `Access-Control-Allow-Origin: *` (die abgeschottete Herkunft ist `null` – ohne diesen Kopf gingen `fetch` und
  Modul-Skripte der App auf ihre eigenen Dateien nicht; die Dateien sind ohnehin öffentlich), `Referrer-Policy:
  no-referrer`; bei Dateien zusätzlich `Content-Type` aus der festen Zuordnung (`html` → `text/html; charset=utf-8`,
  `js` → `text/javascript; charset=utf-8`, `svg` → `image/svg+xml`, `bin` → `application/octet-stream` …),
  `Cache-Control: no-cache` und `ETag: "<blob-id>"`. Nur `GET`. `/app/<id>` (ohne `/`) → `308` mit relativem
  `Location: <id>/` (geht auch hinter einem Pfad-Präfix) – nur auf einem Knoten mit Netz, sonst `404`. Dateien bis
  64 KiB kommen in einem Stück, größere als Strom (Teil für Teil von der Platte, je Teil geprüft, mit
  `Content-Length`; scheitert ein Teil, wird die Verbindung abgebrochen – nie eine kurze Datei als „fertig“).
- *Review 7* – **Langsame Leser**: Ströme sind begrenzt – höchstens 8 zugleich je Adresse und 128 je Knoten (darüber
  `429 RATE_LIMITED`, `Retry-After: 5`); je Strom gilt eine Mindestrate von 16 KiB/s im Schnitt, geprüft ab 10 s,
  und eine Höchstdauer von 1 Stunde – wer langsamer liest oder länger braucht, wird getrennt. Alles einstellbar
  (`ServerConfig::stream_*`, `max_streams*`) und auch hinter vertrauten Proxys wirksam (dort zählt die
  weitergeleitete Adresse).
- **CORS für `/v4/…`**: jede Antwort mit `Access-Control-Allow-Origin: *` und `Access-Control-Expose-Headers:
  Retry-After`; `OPTIONS` (Vorabfrage) → `204` mit `Access-Control-Allow-Methods: GET, POST`,
  `Access-Control-Allow-Headers: Authorization, Content-Type`, `Access-Control-Max-Age: 600`. Nie
  `Allow-Credentials` – Sitzungen nur per Bearer-Token. `OPTIONS` auf andere Pfade: `404`. Dafür kennt der Transport
  jetzt `OPTIONS`, eigene Antwort-Köpfe und Antworten als Strom (`BodyStream`). *Review 7*: Auch Antworten, die der
  Transport selbst erzeugt (`405`, `413`, `408`, Zeitüberschreitung, zu viele Ströme), tragen diese Köpfe – unter
  `/app/` die Sandbox-Köpfe (`Handler::decorate`).
- **Lese-Grenze**: `/v4/blob/info|hashes|get`, `/v4/app/manifest`, `/v4/app/update` und `GET /app/…` zählen
  zusätzlich in einem Eimer je Adresse (Standard 10/s, kurz bis 40; einstellbar), über der allgemeinen Grenze.

## 6. Stufe 2 (später): Daten-Werkzeuge und Server-Code
Bridge synchronisiert keine App-Daten selbst, liefert aber:
- **Ereignis-Log pro App**: jeder Host hängt signierte Ereignisse an, Bridge verteilt sie geordnet an alle Hosts; die
  App rechnet daraus ihren Zustand (funktioniert für jeden Datentyp).
- **Kanal zwischen den Hosts** einer App, **versionierter Speicher mit Konflikt-Meldung**, **Sperren auf Zeit**.
- **Server-Code** nur als WebAssembly in der Sandbox (03 §4) mit Rechten aus dem Manifest.

## 7. Endpunkte (Phase 4a)
| Endpunkt | Wer | Zweck |
|---|---|---|
| `POST /v4/blob/begin` | Mitglied (Sitzung; ohne Netz nur mit `--standalone-blobs`) | `{"blob","size","hashes":[…],"from"?,"keep_days"?}` → Kontingent reservieren; Antwort `{"size","parts","known","complete","missing":[…]}` (`known`: Hashes angekommen, `missing`: bis 4.096 noch fehlende Teilnummern; erneut aufrufen = Stand abfragen/verlängern, dann ohne `hashes`) |
| `POST /v4/blob/chunk` | Mitglied (Sitzung) | `{"blob","i","data"}` (Base64url, max. 64 KiB) → `{"ok":true,"complete":bool}` |
| `POST /v4/blob/info` | alle | `{"blob"}` → `{"size","parts","complete"}` |
| `POST /v4/blob/hashes` | alle | `{"blob","from","max"}` → `{"from","hashes":[…]}` (max. 4.096 je Antwort) |
| `POST /v4/blob/get` | alle | `{"blob","i"}` → `{"i","data"}` (nur vorhandene, geprüfte Teile) |
| `POST /v4/app/publish` | Owner (Sitzung) | Body = die `app`-Aussage (nur bei gelisteten Hosts mit `web`-Siegel, oder als Stopp-Signal) → `{"ok":true,"version":n,"active":bool}` |
| `POST /v4/app/manifest` | alle | `{"app"}` → `{"manifest":<neueste gültige Version hier>,"hosts":[<karten der gültigen hosts>]}`; Kopf-Form `{"app","head":true}` → `{"version":n,"hash":"<hash der aussage>"}` |
| `POST /v4/app/update` | alle | Body = eine `app`-Aussage einer App, die der Knoten hostet: echt neuer und gültig → wie ein Angebot (nennt sie den Knoten: annehmen, sonst Stopp-Signal) → `{"ok":true,"active":bool,"hosted":bool}`; App hier nicht gehostet → `404`, nicht neuer → `409 REPLAY` |
| `POST /v4/node/app` | Hosts der App | Version anbieten: `{"manifest":<aussage>,"rq":<rq op "app">}` → `{"ok":true,"active":bool}` (§5 „Wie der zweite Host …“; `active:false` auch beim Stopp-Signal) |
| `GET /app/<app-id>/<pfad>` | alle | Datei ausliefern (§5) |
| `OPTIONS /v4/…` | Browser | CORS-Vorabfrage (§5) |

Lese-Endpunkte haben ein eigenes, engeres Limit pro Adresse (wie die Log-Nachweise). Fehler wie 04 §9, u. a.: falsches
Teil oder falsche Hash-Liste → `400 BAD_FORMAT`; Teil ohne `begin` → `404 NOT_FOUND`; Kontingent/Knoten voll oder zu
viele Apps (Knoten oder Owner) → `429 QUOTA_EXCEEDED`; zu viele Ströme → `429 RATE_LIMITED`; nicht gelistet, kein
`web`-Siegel, nicht der Owner, Hochladen auf einem Knoten ohne Netz → `403 FORBIDDEN`; Lesefehler der Platte →
`503 UNAVAILABLE`; ältere oder gleiche, schon entschiedene Version → `409 REPLAY`; eine Signatur fehlt oder falscher Unterzeichner → `401 BAD_SIGNATURE`. Ein Knoten ohne Netz
kennt `/v4/app/…`, `/v4/node/app` und `/app/…` nicht (`404`).

## 8. Kommandozeile und SDK (Phase 4a)
*Beim Bau festgelegt*:
- `bridge-node app create --data <ordner> --name <text>` legt den App-Schlüssel `apps/<app-id>.json` im Daten-Ordner
  an (nur für den Besitzer lesbar, nie auf einen Host kopieren) und zeigt die App-ID.
- `bridge-node app publish --data <ordner> --app <id> --folder <pfad> [--host <knoten-id>]… [--entry index.html]
  [--description <text>] [--node <adresse>]` veröffentlicht den Ordner als nächste Version (Version + 1; ohne
  `--host` die Hosts der letzten Version, sonst der Owner-Knoten).
- `bridge-node app hosts --data <ordner> --app <id> [--add <knoten-id>]… [--remove <knoten-id>]… [--node <adresse>]`
  macht eine neue Version mit denselben Dateien und geänderten Hosts.
- *Review 7*: Fallen dabei Hosts weg (`app hosts --remove`, `app publish --host …` mit anderen Hosts), gibt die
  Kommandozeile die neue Version auch an jeden weggefallenen Host (`/v4/app/update`, ohne Anmeldung) – er hört sofort
  auf; wen sie nicht erreicht, meldet sie (der hört auf, sobald er die Version anders erfährt). Weil `app hosts` keine
  Dateien hochlädt, muss dabei **mindestens ein bisheriger Host bleiben** – von ihm holen die neuen Hosts die Dateien;
  sonst Abbruch mit Hinweis (fail closed). Ganz umziehen: erst `--add`, warten, bis der neue Host ausliefert, dann
  `--remove` – oder `app publish --host <neu>` (lädt die Dateien zum neuen Host hoch).
- *Review 7*: `bridge-node --standalone-blobs <MiB>` erlaubt Hochladen auf einem Knoten ohne Netz (§5), mit dieser
  Obergrenze für alle Blobs zusammen.
- **Owner**: Die Befehle laufen im Daten-Ordner des Owner-Knotens (mit `admin-key.json` aus `net create`). Der Owner
  ist eine eigene Client-Identität `owner-key.json` in diesem Ordner (beim ersten Mal angelegt, nur für den Besitzer
  lesbar); ist sie noch kein Mitglied, nimmt der Admin-Schlüssel sie auf (`member`, 1 Jahr). Die Befehle holen das Log
  vom Owner-Knoten, prüfen, dass jeder Host ein `web`-Siegel hat (sonst Abbruch mit dem passenden `net seal`-Befehl),
  melden den Owner beim ersten Host an, der auch Empfänger ist, laden fehlende Dateien hoch und geben die Version ab.
  Die anderen Hosts holen sie sich selbst. Der Owner-Knoten selbst wird Host mit
  `net seal … --level 3 --services gateway,log,witness,web`.
- **SDK** (`sdk/rust`, Modul `apps`): `Client::upload_blob`/`upload_file` (Hash-Liste in Seiten, dann nur fehlende
  Teile), `download_blob` (in eine Datei, von mehreren Quellen parallel, jeder Teil geprüft, `<ziel>.part` wird beim
  nächsten Mal fortgesetzt) und `fetch_blob` (in den Speicher, mit Obergrenze), `Client::publish_folder` (Ordner
  einlesen – keine symbolischen Links, max. 16 Ebenen, Pfade nach §3, Typ nach Endung, Unbekanntes = `bin` – Dateien
  hochladen, mit App-Schlüssel und Owner signieren, abgeben), `Client::sign_app` + `publish_app`, `fetch_app`
  (Version holen und beide Signaturen prüfen; die mitgelieferten Host-Karten nur, wenn die Version sie nennt),
  `pick_host`/`reachable_hosts` (je Host erst LAN mit dem Pin aus seiner Karte, dann seine Adressen; der nächste Host,
  wenn einer ausfällt). *Review 7*: `announce_app(quelle, aussage)` gibt eine neuere Version an einen Host
  (`/v4/app/update`) – so erfährt ein alter Host beim Host-Wechsel davon. Eine Quelle, die Unsinn antwortet (keine
  Größe, kaputte Hash-Seite), wird beim Herunterladen übersprungen; die nächste wird gefragt.

## 9. Grenzen und offene Punkte von Phase 4a
- Kein `Range` und kein `If-None-Match` beim Ausliefern (der `ETag` ist da; Videos spielen, Springen geht noch nicht).
- Die Lese-Grenze je Adresse gilt auch, wenn Hosts voneinander holen (Standard 10 Teile/s ≈ 640 KiB/s je Paar);
  große Apps verteilen sich entsprechend langsam (einstellbar).
- Welche Hosts gelten, sagt ein Client nicht selbst nach (er hat das Log nicht): die Karten aus `/v4/app/manifest` sind
  das Wort des Knotens (nur Karten, die die Version nennt; Adresse und ID prüft der Client beim Verbinden).
- Eine Version gilt max. 1 Jahr; ein automatisches Neu-Signieren vor Ablauf gibt es noch nicht (`app publish` erneut).
- Die Kommandozeile braucht den Ordner des Owner-Knotens (Admin-Schlüssel); Owner ohne eigenen Knoten → später
  BridgeControll bzw. das SDK.
- Stürzt ein Knoten zwischen dem Löschen der Zeile und der Datei ab, bleibt eine verwaiste Datei in `blobs/` (wird
  nicht mehr ausgeliefert; Aufräumen verwaister Dateien folgt).
- Hochladen schickt die Teile nacheinander (Herunterladen ist parallel).
- *Review 7*: Eine verworfene wartende Version (12 Fehlversuche ohne Fortschritt, Knoten voll, Kontingent) bleibt auf
  diesem Host abgelehnt, auch wenn ihre Dateien später auftauchen – der Owner veröffentlicht eine neue Version. Das
  ist bewusst streng (kein Wiederholungs-Sturm), kostet aber Verfügbarkeit, wenn alle Quellen über eine Stunde aus
  waren.
- *Review 7*: Fehlt eine Blob-Datei dauerhaft (z. B. von Hand gelöscht), antwortet der Host `503` – ein Lesefehler ist
  kein Beweis für Verlust. Erkennen und Neu-Holen dauerhaft fehlender Dateien folgt mit dem Aufräumen verwaister
  Dateien.
- *Review 7*: Die Mindestrate gilt nur für Ströme. Kleine Antworten (≤ 1 MiB) an einen Leser, der nicht liest, halten
  eine Verbindung, bis die Verbindungs-Grenzen greifen (32 je Adresse, 1.024 je Knoten; hinter einem vertrauten Proxy
  nur die Knoten-Grenze).
- *Review 7*: Die vorige Version zählt im Kontingent mit: Wer eine App mit lauter neuen Dateien aktualisiert, braucht
  Platz für aktuelle + vorige + neue Version.
- Daten-Werkzeuge und Server-Code: Stufe 2 (§6).
