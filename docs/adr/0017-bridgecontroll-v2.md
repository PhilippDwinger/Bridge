# ADR 0017 – BridgeControll v2: lokale Web-App, ein Prozess pro Knoten

- **Status**: angenommen beim Bau (11.11.2026; Paddy hat den UI-Entwurf N01–N04 freigegeben und gesagt „mach einfach
  so weiter wie du meinst“ – die Details hier hat Claude entschieden, Freigabe durch Paddy steht aus)
- **Kontext**: Die Abnahme von Phase 3 verlangt „Netz per Klick erstellt, zweiter PC tritt per Link bei, Siegel
  vergeben/entzogen wirkt im ganzen Netz“. Bisher gab es dafür nur die Kommandozeile (`bridge-node net …`, 06 §10).
  ADR 0003 plante BridgeControll als Tauri-App. Die alte BridgeControll (Python) verwaltet Bridge-3-Server.
- **Entscheidung**:
  1. **Ort**: `apps/bridgecontroll/`, Crate `bridgecontroll`, Mitglied des Workspace. Die Python-BridgeControll bleibt
     für Bridge 3; v2 ist nur für Bridge 4.
  2. **Lokale Web-App jetzt, Tauri-Hülle später** (wie v1): ein Rust-Programm zeigt seine Oberfläche nur auf
     `127.0.0.1` und öffnet den Standard-Browser. Eine Tauri-/Tray-Hülle kommt später und nutzt dieselbe Oberfläche.
     Grund: keine webkit-/Tauri-Abhängigkeiten – baut und testet überall (CI, Linux ohne Bildschirm), die Oberfläche ist
     mit Playwright testbar. Unter Windows hat das Programm kein Konsolenfenster (`windows_subsystem = "windows"`), sein
     Log steht in `bridgecontroll.log`; beendet wird es über „Beenden“ in der Oberfläche (oder Strg+C im Terminal).
  3. **Ein Prozess pro Knoten** (Zuverlässigkeit): dasselbe Programm im Knoten-Modus
     (`bridgecontroll node --supervised --data … [Optionen von bridge-node]`). Der Knoten-Läufer von `bin/bridge-node`
     ist dafür als Bibliothek nutzbar (`bridge_node_cli::run_node`, `run_cli`); das Programm `bridge-node` verhält sich
     unverändert.
     - **Watchdog**: Endet ein Knoten, ohne dass er sollte, startet er nach 1, 2, 4, 8, 16 s neu; nach mehr als fünf
       Neustarts in zehn Minuten gibt der Watchdog auf („Abgestürzt“, wie v1). Starten von Hand beginnt neu.
     - **Sauberer Stopp**: Die App schließt die Standard-Eingabe des Knotens; mit `--supervised` ist das sein Signal,
       sich selbst sauber zu beenden (Dienste, mDNS-Abschied, Zugänge). Das geht auf jedem System gleich und braucht
       keine Signale (kein `unsafe`). Nach 10 s wird er hart beendet. Endet die App, enden ihre Knoten (keine
       unbewachten Knoten); der Autostart bringt sie wieder.
     - **Logs**: Ausgabe jedes Knotens zeilenweise in `logs/<id>.log`, Zeilen ≤ 4.096 Zeichen, Dateien rotieren bei
       2 MiB (höchstens 4 Dateien je Knoten).
  4. **App-Ordner**: `%APPDATA%\BridgeControll2` (Windows), sonst `~/.local/share/bridgecontroll2` (bzw.
     `$XDG_DATA_HOME`); `--data` wählt einen anderen. Darin `bridgecontroll.json` (Knoten: Name, Rolle, Ports, LAN-Port,
     öffentliche Adresse, Autostart, Einladungslink bis zum geladenen Log; streng geprüft, atomar geschrieben, nur für
     den Besitzer lesbar, beschädigt = Start bricht ab statt zu überschreiben – *nach Prüfung 8* nur, wenn es gar keine
     Einstellungsdatei ist; ein kaputter Eintrag wird mit Warnung übersprungen), `nodes/<8 Hex-Zeichen>/` (Daten-Ordner
     je Knoten – kein Pfad steht in der Datei), `logs/`, `backup/`, `instance.json`, `instance.lock`, `login.html`.
  5. **Zero Trust auch lokal**:
     - Nur `127.0.0.1`. Sitzung: 256 Bit Zufall beim Start, übergeben mit einem **Einmal-Link** (`/login/<code>`,
       einmal gültig, 5 Minuten) als Cookie `HttpOnly; SameSite=Strict`. Jede API und jeder Bildschirm braucht sie;
       öffentlich sind nur das Design-System und die Seite „Nicht angemeldet“. Vergleich über SHA-256 (keine
       Zeit-Hinweise). Der gute Einmal-Link antwortet mit einer kleinen Seite (200, Cookie, `meta refresh` auf `/`)
       statt einer Umleitung: Der Browser öffnet ihn von der Datei-Seite `login.html` aus, und ein Strict-Cookie geht
       in einer Umleitungs-Kette, die eine fremde Seite begonnen hat, nicht mit („Nicht angemeldet“ beim ersten Start,
       Paddy 12.11.2026). Den Schritt von der eigenen Seite aus schickt der Browser mit Cookie.
     - **Host-Prüfung** vor allem anderen (`127.0.0.1:<port>` oder `localhost:<port>`, sonst 403) gegen DNS-Rebinding.
     - **CSRF**: jeder `POST` braucht `Origin` dieser App und `Content-Type: application/json`; kein CORS.
     - Kopfzeilen: CSP `default-src 'self'` (keine Inline-Skripte oder -Styles: die Layouts der Entwürfe stehen
       deshalb in `ui/app.css`, nur mit `var(--…)`), `frame-ancestors 'none'`, `nosniff`, kein Referrer, `no-store`.
     - Bodies ≤ 64 KiB (auch bei falscher Länge), nur `GET`/`POST`, höchstens 64 Verbindungen. Dateien nur aus einer
       festen Liste im Programm (genaue Pfade, kein Datei-System dahinter).
     - Keine Geheimnisse in Logs (keine Bodies, Tokens, Links).
     - **Zweiter Start**: `instance.json` (nur für den Besitzer lesbar) enthält Port und einen Startschlüssel; ein
       zweiter Start fragt damit `POST /api/launch` nach einem neuen Einmal-Link, öffnet den Browser und endet
       (*nach Prüfung 8*: mit exklusiver Sperre und bewiesenem Schlüssel statt gesendetem, siehe Nachtrag).
  6. **Die 24 Wörter** (06 §1): Schritt 2 des Assistenten erzeugt sie und schickt sie **nur in der Antwort dieses
     POST** (von Hand gebaut, ohne Kopien in JSON-Werten). Nie gespeichert, nie geloggt, nie in einer URL. Bis Schritt 4
     liegen sie nur im Speicher (`Mnemonic`, beim Freigeben gelöscht), höchstens 30 Minuten und höchstens vier
     Assistenten zugleich. Weiter geht es erst nach einem Test mit drei zufälligen Wörtern und dem Häkchen „auf
     Papier“ – geprüft im Programm, nicht nur im Browser. Danach entfernt die Seite die Wörter aus dem DOM. Schritt 4
     erstellt das Netz mit genau diesen Wörtern (`admin::create_network_with_words`, neu); scheitert er, bevor etwas
     erstellt ist (z. B. Port belegt), bleiben sie für einen neuen Versuch. „Zurück“ in Schritt 2 heißt: neue Wörter.
  7. **Admin-Aktionen wie die Kommandozeile**: `AdminClient` mit `admin-key.json` des Owner-Ordners; gesprochen wird
     mit dem Owner-Knoten über seine lokale Adresse. Einladungslinks tragen die Adresse aus der **geprüften Karte** des
     Knotens (seine öffentliche Adresse), seine ID und – mit LAN – seinen TLS-Fingerabdruck.
  8. **Siegeln mit ID-Bestätigung** (wie `--node-id`):
     - Knoten dieses PCs: die Karte kommt vom Knoten selbst (lokaler Port, `fetch_node_card` prüft das Netz), die ID
       ebenso.
     - Knoten anderer PCs: der **Knoten-Ausweis** `bridge4://node?card=<Base64url der kanonischen Karte>` (höchstens
       4.096 Zeichen; selbst-signierte Karte, Rolle `node`, mit Adresse) plus mindestens die **ersten 12 Zeichen der
       Knoten-ID**, abgelesen am anderen PC (60 Bit – eine untergeschobene Karte mit passendem Anfang ist praktisch
       nicht zu erzeugen). Grund: In einem Netz nur im LAN kann der Owner die Karte nicht über `http` holen (06 §10);
       der Ausweis braucht keine Verbindung. Neu: `AdminClient::seal_card` (`seal` nutzt es).
     - „Siegel entziehen“ widerruft alle aktiven Siegel des Knotens – nie beim Owner-Knoten, nie bei Log-Führern oder
       Zeugen des aktuellen Manifests (sonst stünde das Log).
     - Neue Adresse oder LAN nach dem Siegeln: das Dashboard zeigt „Karte veraltet“ und „Neu siegeln“ (06 §10).
  9. **Status**: Je laufendem Knoten alle 2 s `/v4/info` (Karte und Info geprüft), das Log ab dem Ende des Caches
     (Eintrag 0 bis zur Netz-ID geprüft, abgespielt mit `bridge-net` wie in jedem Knoten; höchstens 262.144 Einträge),
     der neueste bezeugte Kopf und die Beweise. Das Owner-Dashboard rechnet aus dem Zustand des Owner-Knotens; Namen
     von Mitgliedern, gehostete Apps und den Wächter-Status liest es aus dessen Datenbank (nur lesend:
     `admin::known_cards`, `hosted_apps`, `watch_status`).
  10. **QR-Code**: `qrcodegen` (reines Rust, ohne Abhängigkeiten); das SVG baut das Programm (ein Pfad,
      `currentColor`, Ruhezone 4 Module) – die Farbe kommt aus den Tokens.
  11. **Autostart** (aus, bis man ihn einschaltet): Windows eine `.cmd`-Datei im Autostart-Ordner des Benutzers, Linux
      ein XDG-Eintrag, macOS noch nicht. Verworfen: Registry-`Run` mit `winreg` – hier weder baubar noch testbar; die
      Datei braucht nur die Standard-Bibliothek. Der Eintrag startet mit `--autostart` (kein Browser); Knoten mit „Mit
      BridgeControll starten“ laufen an. Pfade mit Anführungszeichen, `%` oder Zeilenenden werden abgelehnt.
  12. **Löschen** nur nach Eintippen des Namens; der Ordner wird nach `backup/<id>-<zeit>/` verschoben –
      Schlüssel-Dateien werden nie still gelöscht.
  13. **Design**: Das Design-System liegt einmal kopiert in `apps/bridgecontroll/design/` (gehört dem Design-Claude,
      nie ändern, nur `FRAGEN.md` anhängen). Die Bildschirme liegen in `ui/` und sind ins Programm eingebaut
      (`include_bytes!`), keine Datei zur Laufzeit.
- **Nachtrag (Prüfung 8, 12.11.2026)** – Befunde der Sicherheitsprüfung, von Claude entschieden (Freigabe durch Paddy
  steht aus):
  1. **Einstellungen können die App nicht mehr aussperren** (vorher: der Name `" "` eines fremden Netzes kam ungeprüft in
     `bridgecontroll.json`, die App schrieb eine Datei, die sie beim nächsten Start ablehnte): Netz-Namen aus dem
     Manifest werden nur übernommen, wenn sie gültige Namen sind (sonst bleibt der alte); `save` prüft jeden Eintrag und
     schreibt nichts Ungültiges; `load` überspringt einen kaputten Eintrag (auch doppelte ID/Port) mit einer Warnung
     auf der Startseite und legt die alte Datei vorher unverändert nach `backup/bridgecontroll-<ms>.json`. Eine Datei,
     die gar keine Einstellungsdatei ist (kein JSON, andere Version), stoppt den Start weiter (Punkt 4).
  2. **Keine Geheimnisse auf Befehlszeilen** (lesbar für alle Benutzer des PCs): Der Browser bekommt nicht mehr den
     Anmelde-Link, sondern den Pfad von `login.html` im App-Ordner (nur für den Besitzer lesbar, leitet weiter, nach
     2 Minuten gelöscht). Der Knoten bekommt den Einladungslink nicht mehr als `--join-net <link>`, sondern als
     `--join-net-file <knoten-ordner>/join-link.txt` (nur für den Besitzer; gelöscht, sobald der Link nicht mehr
     gebraucht wird). Neu in `bridge-node`: `--join-net-file`.
  3. **Eine App je App-Ordner**: Die laufende App hält ihr ganzes Leben eine exklusive Sperre auf `instance.lock`
     (Crate `fs4`: flock bzw. LockFileEx, ohne eigenes `unsafe`; `File::lock` der Standard-Bibliothek gibt es erst ab
     Rust 1.89, MSRV ist 1.85). Das System gibt sie mit dem Prozess frei, auch nach einem Absturz – eine alte
     `instance.json` stört nie. Ein zweiter Start ohne Sperre fragt die laufende App (bis 5 s) nach einem Anmelde-Link:
     Er beweist den Startschlüssel, statt ihn zu senden (`X-Launch-Nonce` + MAC), jede Nonce gilt einmal, und die
     Antwort trägt einen MAC über Nonce und Pfad – geöffnet wird nur, was die echte App beantwortet hat (MAC:
     `bridge_core::crypto::mac`, HKDF-SHA256). `instance.json` hat jetzt `v: 2`.
  4. **Autostart unter Windows**: Die `.cmd`-Datei beginnt mit `@chcp 65001>nul` (UTF-8, Pfade mit Umlauten);
     Pfade bleiben in Anführungszeichen, `%`, `"` und Zeilenenden weiter abgelehnt.
  5. Kleineres: Die 24 Wörter bleiben bis zum Senden in ihrem löschenden Puffer (`Bytes::from_owner`, keine einfache
     Kopie); das Owner-Dashboard rechnet den Wächter-Status aus dem Zustand, den es ohnehin hält (vorher spielte es alle
     3 s das ganze Log aus der Datenbank ab; neu `admin::watch_registered`); die %-Dekodierung der Suche nimmt nur
     genau zwei Hex-Ziffern (`%+1` war Byte 1).
  6. **Adressen anderer Knoten** (Entscheidung mit Paddy, der alles über Tailscale Funnel betreibt): BridgeControll
     startet seine Knoten mit `--peer-addresses tailnet` (öffentlich + 100.64.0.0/10 + fd7a:115c:a1e0::/48, 06 §2) –
     sonst prüfte ein Wächter auf einem Tailnet-PC die Funnel-Adressen der anderen eigenen Knoten nicht (MagicDNS →
     100.x). Je Knoten in den Einstellungen: „Öffentlich“ / „Öffentlich + Tailnet“ / „Alle (unsicher)“
     (`peer_addresses` in `bridgecontroll.json`: `public`/`tailnet`/`any`; fehlt das Feld in einer älteren Datei, gilt
     `tailnet`). `bridge-node` selbst bleibt bei `public`.
- **Nachtrag 2 (Phase 4 in BridgeControll, 12.11.2026)** – Bridge-Browser, Namen, Meldungen (docs/08 §12); Paddy hat
  mit „mach einfach weiter“ übergeben, die Details hat Claude entschieden (Freigabe durch Paddy steht aus):
  1. **Browser in der App, App im `iframe`**: Die Seite zeigt fremde Apps in `<iframe sandbox="allow-scripts
     allow-forms allow-popups">` (nie `allow-same-origin`, Sandbox vor der Adresse gesetzt), geladen direkt vom **Leser
     des eigenen Knotens** auf `http://127.0.0.1:<port>` – nicht durch BridgeControll durchgereicht (der Knoten prüft
     jede Datei und setzt die Sandbox-CSP selbst; BridgeControll bleibt ohne fremde Inhalte). Die CSP von `/` erlaubt
     in `frame-src` genau diese Herkünfte (je Knoten mit Leser und ohne öffentliche Adresse), alle anderen Antworten
     `frame-src 'none'`. Verworfen: Proxy der App durch BridgeControll (fremde Inhalte im eigenen Ursprung) und
     `frame-src http://127.0.0.1:*` (zu weit).
  2. **Daten nur als Text**: Namen, Beschreibungen, Schlagworte und Meldungstexte kommen nur mit `textContent` ins
     DOM; die Antworten der Knoten prüft BridgeControll streng (Felder, Grenzen, Netz-ID) und öffnet nur `open` =
     `/app/<ziel>/` eines App-Namens mit passendem Owner. Warnungen übersetzt das Programm (Deutsch), nicht die Seite.
  3. **Wer meldet**: der Mitglieds-Schlüssel des PCs im Ordner des Knotens (`owner-key.json`, derselbe wie für
     `app publish`), mit Sitzung bei einem Empfänger. Verworfen: mit dem Knoten-Schlüssel melden (eine Anmeldung mit
     Client-Karte und `home` würde die Karte und das Postfach des Knotens beim Empfänger überschreiben). Folge: Ein
     Mitglieds-Knoten in einem Einladungs-Netz kann nicht selbst melden – die Antwort nennt den Meldeweg (docs/08 §11).
  4. **Betreiber-Schlüssel Stufe 2**: Namen von Apps und vom Betreiber gehören dem Mitglieds-Schlüssel des Owner-Ordners;
     BridgeControll siegelt ihn vor dem ersten Namen mit Stufe 2 ohne Dienste (kleinste Stufe, mit der die sichere
     Suche seine Namen zeigt; Stufe 3 für reservierte Wörter bleibt eine bewusste Admin-Entscheidung über die
     Kommandozeile). Er erscheint als „Du (Betreiber)“ unter den Mitgliedern, nicht unter den Knoten (die Knoten-Liste
     zeigt nur Siegel mit Knoten-Karte).
  5. **Meldungen holen** kostet eine signierte Admin-Anfrage: alle 15 s und nach jeder Aktion, nicht bei jeder
     Status-Runde. Schnell-Aktionen spielen das Log des Owner-Knotens frisch ab (nicht die Sicht der letzten Runde).
  6. **Ein PC, eine Adresse**: Alles auf dem PC erreicht die Knoten von `127.0.0.1` und teilt deren Grenzen je Adresse;
     Admin-Aktionen und Namens-Abfragen werden bei `RATE_LIMITED` wiederholt (höchstens dreimal, eine Sekunde Abstand;
     eine abgelehnte Anfrage hat nichts verändert, jede Wiederholung ist neu signiert).
  7. **Leser je Knoten** in den Einstellungen (`reader`: `off`/`local`/`lan`, Standard `local`, ältere Dateien
     `local`); Knoten mit öffentlicher Adresse öffnen keine Apps (vertrauter Proxy, docs/08 §11).
  8. **Assistent**: Meldeweg ist Pflicht (geprüft, bevor Wörter erzeugt werden), Kurzname aus dem Namen vorgeschlagen
     (`POST /api/wizard/short`), 18+ Standard „nicht erlaubt“; erstellt mit `admin::create_network_with_options`.
  9. **Bibliothek statt Kopie**: Namen über `bridge_node_cli::names` (jetzt öffentlich, ebenso `apps`), Admin-Aktionen
     über `AdminClient`; neu nur `apps::list`, `apps::admit_owner`, `names::refusal` (öffentlich) und
     `ReaderAccess::as_str`.
- **Nachtrag 3 (Prüfung 9, 12.11.2026)** – Befunde zu Phase 4 in BridgeControll, von Claude entschieden (Freigabe durch
  Paddy steht aus; docs/08 §12):
  1. **Keine Neulade-Schleife**: Eine App im Rahmen, die ihn auf beliebige Ports von `127.0.0.1` lenkte, löste je Port
     eine CSP-Verletzung und damit ein Neuladen der Seite aus. Jetzt lädt die Seite nur neu, wenn die blockierte
     Herkunft in `frames` von `GET /api/browser` steht und nicht in der eigenen CSP (`originalPolicy`), höchstens einmal
     je Laden und nie zweimal für dieselbe Herkunft (Playwright-Test: sechs fremde Ports → kein Neuladen).
  2. **„App sperren“ nur für Apps**: angeboten und vom Server angenommen nur für das Ziel eines App-Namens im Log oder
     einen App-Schlüssel des Owner-Ordners; nie für Netz, Log-Führer, Zeugen, Wächter, Empfänger, Admins (die Rolle
     gewinnt). Zeile und Bestätigung nennen die Art der ID.
  3. **Leser-Port für Knoten mit öffentlicher Adresse** (ersetzt Nachtrag 2 Punkt 7 „öffnen keine Apps“): eigener Port ab
     7601 (`reader_port`), Start mit `--reader-listen 127.0.0.1:<port>`; der Browser rahmt, löst auf und sucht dort.
     Ältere Einstellungen bekommen den Port beim Start (gespeichert mit der nächsten Änderung).
  4. **Melden**: Der Text geht an den ersten Log-Führer versiegelt hinaus; ohne dessen Karte im Log keine Meldung mit
     Text. Ein an einen anderen Log-Führer versiegelter Text erscheint als solcher.
  5. **Leser „Tailnet“** in den Einstellungen; Warnung „Karte nicht geprüft“ (`card_unverified`) im Schloss.
- **Folgen**:
  - Phase 3 hat ihr „per Klick“: Assistent, Beitritt per Link, Siegeln/Entziehen, Sperren, Einladungen mit QR-Code.
  - Getestet: Steuer-API mit echten Knoten-Prozessen (erstellen → beitreten → siegeln → Stufe sichtbar → Mitglied
    sperren → Siegel entziehen → löschen), Watchdog (Absturz → Neustart, Aufgeben), Sicherheit (Sitzung, Host, Origin,
    Pfade, Größen, Kopfzeilen, Startschlüssel, eine App je Ordner); Oberfläche mit Playwright
    (`apps/bridgecontroll/tests/ui/smoke.py`).
- **Grenzen** (offen):
  - Browser statt eigenem Fenster, kein Tray-Icon (kommt mit der Tauri-Hülle).
  - Knoten anderer PCs sieht der Owner erst mit ihrem Ausweis; Wächter-Anmeldungen zeigen keine Karten.
  - Mitglieder-Namen nur, wenn ihre Karte beim Owner-Knoten bekannt ist (Anmeldung dort oder `home`-Austausch).
  - Tailscale Funnel wird nicht eingerichtet – nur die Adresse eingetragen.
  - Die Wörter liegen kurz im Speicher von Browser und Programm (wie bei `net create` im Terminal); ein Browser kann
    Seiten im Speicher behalten, bis der Tab geschlossen ist.
  - Admin-Verlängerung, `cascade` und Not-Wiederherstellung (24 Wörter) gibt es weiter nur über die Kommandozeile.
  - Phase 4 in der App: kein Hochladen von Apps (weiter `bridge-node app publish`), Melden von Mitglieds-Knoten in
    Einladungs-Netzen nur über den Meldeweg (docs/08 §11). (Leser hinter Tailscale Funnel: gelöst, Nachtrag 3.)
  - Windows-Teile (Autostart-Datei, kein Konsolenfenster, `CREATE_NO_WINDOW`) baut die CI; ausgeführt wurden sie hier
    nicht.
