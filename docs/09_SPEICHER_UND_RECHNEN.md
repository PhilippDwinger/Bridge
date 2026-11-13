# 09 – Speicher und Rechnen (Phase 5)

Stand: 12.11.2026 (Paddy weg, „entscheide selber“). Grundlage: 00 (Zero Trust), 06 (BridgeNet, Wächter §11),
07 (Dateien und Apps), ADR 0019 (Speicher), ADR 0020 (WebAssembly mit wasmi).

## 1. Grundsätze
- **Der Speicher-Knoten sieht nur Chiffretext.** Der Client verschlüsselt jede Datei selbst (07 §1, `bridge-core::file`)
  und behält den Schlüssel. Kein Knoten kann eine Datei lesen, keiner allein sie verlieren lassen.
- **Kein Knoten wird geglaubt**: Jedes Stück ist ein Blob (Inhalts-Adresse, jeder Teil gegen seinen Hash geprüft).
  Ob ein Knoten wirklich speichert, zeigen **Proben** (zufällige Teile, geprüft gegen die Hash-Liste).
- **Wer lügt, verliert seine Stufe**: Die Stufe 1 für Speicher und Rechnen vergibt der Wächter nur nach bestandenen
  Proben – und entzieht sie nach `fail_limit` Fehlschlägen in Folge (06 §11).
- **Fremder Code nur in der Sandbox**: Rechen-Aufträge, Plugins und Server-Code von Apps laufen als WebAssembly mit
  festen Grenzen (Rechenschritte, Speicher, Ein-/Ausgabe) und nur mit den Fähigkeiten, die ausdrücklich gegeben sind.

## 2. Datei → Stücke (Erasure Coding)
- Ablauf beim Speichern: Datei → `encrypt_file` (zufälliger Schlüssel, 07 §1) → Chiffretext → Reed-Solomon mit `k`
  Daten- und `m` Paritäts-Stücken (`bridge-core::erasure`, GF(2^8), Cauchy-Matrix, systematisch) → `n = k + m` Stücke
  gleicher Länge → jedes Stück ist ein Blob auf einem **anderen** Speicher-Knoten.
- Standard `k = 6`, `m = 4`: Die Datei überlebt den Ausfall **beliebiger 4 von 10** Knoten und kostet das 1,67-fache.
  Erlaubt: `1 ≤ k`, `k + m ≤ 64`.
- Grenzen: ein Streifen je Datei, ein Stück höchstens 64 MiB (bei `k = 6` also Dateien bis 384 MiB). Größere Dateien:
  später mehrere Streifen.

## 3. Speicher-Karte (bleibt beim Besitzer)
`StorageMap` (JSON, nur für den Besitzer lesbar abgelegt – sie enthält den Schlüssel):
`{"v":1,"t":"storage-map","net","size","cipher","k","m","shard","key","shards":[{"i","blob","node","urls"}],
"created","renewed"}`. `key` ist der Datei-Schlüssel (`FileKey::to_bytes`, Base64url), `cipher` die Länge des
Chiffretexts, `shard` die Länge eines Stücks. Die Karte wird streng geprüft (Felder, Grenzen, `i` = 0..n−1 genau einmal,
verschiedene Knoten).

## 4. Speicher-Knoten und Verteilung
- Ein **Speicher-Knoten** hat ein aktives Siegel (Stufe ≥ 1) mit dem Dienst `storage` – vom Admin oder vom Wächter
  (§6). Er nimmt Blobs von Mitgliedern an wie jeder Knoten (07 §1: Kontingent nach Stufe, Anheften bis 30 Tage).
- **Verteilung**: jedes Stück auf einen anderen Knoten; zusätzlich **nie zwei Stücke auf Knoten mit demselben Host**
  ihrer ersten Adresse (verschiedene PCs/Besitzer – das Netz kennt Besitzer von Knoten nur über ihre Adressen;
  Grenze §9). Reichen die Knoten nicht, bricht das Speichern ab (fail closed), statt Stücke zu häufen.
- **Verlängern**: Der Besitzer heftet seine Stücke vor Ablauf erneut an (`renew`, wieder bis 30 Tage).

## 5. Proben des Besitzers (Audit)
Je Stück: die Hash-Liste vom Knoten (geprüft gegen die Blob-ID), dann **ein zufälliger Teil** (`/v4/blob/get`), geprüft
gegen seinen Hash. Ergebnis je Stück: `ok`, `missing` (nicht erreichbar oder nicht da) oder `false` (falsche Daten).
Kein Knoten erfährt vorher, welcher Teil gefragt wird.

## 6. Wächter-Proben für `storage` und `compute` (Stufe verlieren)
- Der Wächter (06 §11) darf jetzt Knoten-Siegel der Stufe 1 mit den Diensten `web`, `storage` und `compute` geben
  (`WATCH_SERVICES`). Ein Knoten bittet darum wie bisher (`--probe web,storage,compute`).
- **Speicher-Probe**: Bei der ersten Probe legt der Wächter einen **Proben-Blob** (40 KB Zufall – er reist in einer
  signierten Anfrage, höchstens 64 KiB) beim Knoten ab – `POST /v4/storage/probe`, op `storage-probe`; der Knoten nimmt
  sie nur von einem Wächter des Netzes an, höchstens einen je Wächter (ein neuer ersetzt den alten), angeheftet 30 Tage
  unter `probe:<wächter>`, außerhalb der Kontingente. Der Wächter merkt sich die Hash-Liste (nur im Speicher; nach
  einem Neustart legt er einen neuen Proben-Blob ab). Jede weitere Probe holt den Blob (`/v4/blob/get`) und prüft ihn.
  Falsch oder fehlend = Probe nicht bestanden. Grenze: Ein Knoten, der nur den Proben-Blob behält und die Stücke der
  Mitglieder wegwirft, besteht die Proben – das finden die Proben der Besitzer (§5) und ihre Meldungen.
- **Rechen-Probe**: Der Wächter schickt eine kleine eingebaute Prüf-Aufgabe (WebAssembly, §10) mit zufälliger Eingabe
  an `POST /v4/compute/run` und rechnet sie selbst nach. Anderes Ergebnis = Probe nicht bestanden.
- `fail_limit` Fehlschläge in Folge → der Wächter **widerruft sein Siegel**: Stufe weg, kein Speicher-/Rechen-Knoten
  mehr (Clients wählen ihn nicht mehr, §4).

## 7. Umzug bei Ausfall (Reparatur)
`repair`: Das Audit findet fehlende oder falsche Stücke → aus beliebigen `k` guten Stücken werden alle `n` wieder
berechnet → die schlechten gehen auf **neue** Speicher-Knoten (nach den Regeln von §4) → neue Karte. Die Datei bleibt so
lange lesbar, wie `k` Stücke da sind.

## 8. Endpunkte (Speicher)
| Endpunkt | Eingabe | Antwort |
|---|---|---|
| `POST /v4/storage/probe` | signierte Anfrage eines Wächters, op `storage-probe`, Body `{"data":"<b64, ≤40 KB>"}` | `{"blob":"<id>"}` |
Alles andere sind die Blob-Endpunkte von 07 §7.

## 9. Grenzen und offene Punkte (Speicher)
- „Verschiedene Besitzer“ heißt im Netz: verschiedene Knoten **und** verschiedene Hosts der ersten Adresse. Ein
  Betreiber mit vielen Adressen kann mehrere Stücke bekommen – Abhilfe später: Besitzer-Angabe im Siegel.
- Ein Knoten könnte ein Stück bei Bedarf aus `k` anderen Stücken zurückrechnen, statt es zu halten – das kostet ihn
  `k`-fachen Verkehr bei jeder Probe; Zeitgrenzen für Proben kommen später.
- Die Karte liegt nur beim Besitzer (BridgeControll: im App-Ordner). Geht sie verloren, ist die Datei verloren –
  Sicherung der Karte (verschlüsselt im Netz) später.

## 10. Die Sandbox (`bridge-wasm`)
- WebAssembly mit **wasmi** (Interpreter, deterministisch, Rechenschritte als „Fuel“; ADR 0020).
- **Schnittstelle (ABI)**: Das Modul exportiert `memory`, `alloc(len: i32) -> i32` und die Einstiegsfunktion
  (`run` bzw. `handle`) `(ptr: i32, len: i32) -> i64` = `ptr << 32 | len` der Ausgabe. Importe nur aus dem Modul
  `bridge` und nur die gegebenen Fähigkeiten; ein Modul, das etwas anderes importiert, startet nicht.
- **Grenzen** je Aufruf: Fuel (Standard 100 Mio. Schritte, höchstens 10 Mrd.), Speicher höchstens 16 MiB (256 Seiten),
  Modul höchstens 4 MiB, Eingabe und Ausgabe je höchstens 1 MiB, eine Instanz, keine Tabellen über 10.000 Einträge.
  Jede Überschreitung ist ein Fehler (`LIMIT`), nie ein Absturz des Knotens. Läuft in einem Blocking-Thread.

## 11. Rechnen (`compute`)
- Ein Knoten mit Siegel `compute` (oder mit `--compute` ohne Netz) nimmt Aufträge an:
  `POST /v4/compute/run` (Sitzung, Mitglied) `{"module":"<b64>","input":"<b64>","fuel"?}` → `{"output","fuel",
  "result"}`. `result` ist eine vom Knoten signierte Aussage `compute` (`{"module","input","output","fuel"}` als
  SHA-256), so kann der Auftraggeber beweisen, was der Knoten geantwortet hat. Reine Funktionen: keine Importe.
- **Stichproben** (`run_checked` im SDK): Mit Wahrscheinlichkeit `rate` (Standard 0,1; 1 = immer) rechnet ein zweiter
  Knoten denselben Auftrag. Weichen die Ergebnisse ab, sind beide signierten Ergebnisse der Beweis; das SDK meldet
  beide Knoten (Meldung an die Admins, 08 §6) und gibt den Fehler `MISMATCH` zurück.
- Begrenzt je Adresse (wie Lesen) und auf höchstens 2 gleichzeitige Aufträge je Knoten.

## 12. Plugins fremder Herausgeber
- Ein Plugin = WebAssembly-Modul + Aussage `plugin` (`{"plugin","card","name","version","module","capabilities",
  "limits"}`), signiert vom **Plugin-Schlüssel** (eigener Schlüssel je Plugin, wie bei Apps; seine ID ist die
  Plugin-ID). `module` = SHA-256 der `.wasm`-Datei.
- **Fähigkeiten**: `kv` (eigener Schlüssel-Wert-Speicher, höchstens `limits.kv_bytes`, Standard 16 MiB), `log`
  (Protokollzeile), `caller` (ID des aufrufenden Mitglieds). Nichts sonst – kein Netz, keine Dateien, keine Schlüssel.
- **Installieren** nur durch den Betreiber des Knotens: `bridge-node plugin install --data <ordner> --manifest
  <plugin.json> --wasm <plugin.wasm>` → `plugins/<id>/`. **Updates**: höhere Version, derselbe Plugin-Schlüssel; mehr
  Fähigkeiten als bisher nur mit `--allow-new-capabilities yes`.
- **Aufruf**: `POST /v4/plugin/<id>/call` (Sitzung, Mitglied) `{"input":"<b64>"}` → `{"output"}`; Einstieg `handle`.
- **Not-Aus**: `bridge-node plugin disable` (lokal) und ein `ban` der Plugin-ID im Netz-Log – jeder Knoten startet das
  Plugin dann nicht mehr. Die Daten (`kv`) bleiben in Quarantäne liegen.

## 13. Apps Stufe 2: Server-Code und Ereignis-Log
- Das App-Manifest bekommt das optionale Feld `server`: Pfad einer `.wasm`-Datei der Version. Jeder Host führt sie für
  `POST /app/<id>/api/<pfad>` aus (Sandbox, Einstieg `handle`, Eingabe `{"path","body"}`, Ausgabe
  `{"status","type","body"}`), mit den Fähigkeiten `events` und `log`. Mit einem gültigen Bridge-Login-App-Zeichen im
  Kopf `X-Bridge-Login` kommen `"user"` (Nutzer-ID nur für diese App) und `"name"` dazu (docs/11 §9.4).
- **Ereignis-Log pro App** (07 §6): Der Server-Code hängt Ereignisse an (`event_append`, höchstens 4 KiB); jedes
  Ereignis wird vom Host signiert (`appevent` `{"app","host","seq","data"}`). Hosts holen die Ereignisse der anderen gültigen
  Hosts der App je App-Runde (`POST /v4/app/events {"app","host","after"}`, höchstens 256 je Antwort), prüfen jede
  Signatur und Folge (`seq` lückenlos) und ordnen alle nach `(iat, host, seq)`. Der Server-Code liest sie
  (`event_count`, `event_read`) und rechnet daraus seinen Zustand – Bridge synchronisiert Ereignisse, keine Daten.
- Grenzen: höchstens 10.000 Ereignisse je App und Host und 50.000 je App, je Aufruf höchstens 16; je Lauf höchstens
  1.000 Aufrufe von Host-Funktionen (`MAX_HOST_CALLS`, auch für Plugins).
