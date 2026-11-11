# ADR 0015 – Apps mit mehreren Hosts, Dateien nach Inhalt

- **Status**: angenommen (11.11.2026, Paddy: „Ok dann fang an!“)
- **Kontext**: Paddy will Bridge-Apps: wie Websites, aber von mehreren Clients gehostet, der Owner bestimmt die Hosts.
  Dateien sollen über Bridge übertragen werden. Das Synchronisieren der App-Daten soll die App selbst machen.
- **Entscheidung**:
  1. **Code und Dateien verteilt Bridge** – das ist für jede App gleich (Dateien + Hashes) und sicherheitskritisch.
     **App-Daten** gleicht die App selbst ab; Bridge liefert Werkzeuge (docs/07 §6, später).
  2. **Dateien werden über ihren Inhalt adressiert** (Blob-ID über die Hash-Liste der 64-KiB-Teile). Jede Quelle ist
     prüfbar, Downloads gehen parallel von mehreren Hosts und lassen sich fortsetzen.
  3. **App = eigener Schlüssel + signierte Versionen** (App-Schlüssel **und** Owner signieren). Die Host-Liste steht in
     der Version; die neueste gültige gilt.
  4. **Abholen statt schicken**: Hosts holen neue Versionen selbst und stellen erst nach vollständiger Prüfung um.
  5. **Stufe 1 ohne Server-Code**. Fremder Code auf fremden PCs nur später in der WebAssembly-Sandbox.
  6. Jede App läuft im Browser in einer **eigenen, abgeschotteten Herkunft** (CSP `sandbox` ohne `allow-same-origin`).
- **Folgen**: Ein böser Mit-Host kann nichts verändern, nur ausfallen. Apps unterliegen den Netz-Regeln (Sperren,
  Mindest-Stufe). Speicher wird über Kontingente begrenzt.
- **Nachtrag beim Bau (11.11.2026)**:
  - *Anbieten, dann abholen*: Ein Host kennt eine App erst, wenn er eine Version von ihr hat. Damit ein neu
    gelisteter Host davon erfährt, **bietet** ein Host, der bei einem anderen Host nichts oder eine ältere Version
    findet, ihm seine Version an (`POST /v4/node/app`, signierte Anfrage, die Aussage über ihren Hash gebunden). Der
    Empfänger prüft sie wie eine Veröffentlichung und holt die Dateien selbst – geschickt wird nur das doppelt
    signierte Manifest, nie Dateien.
  - *Versionen*: Hosts nehmen jede höhere Version (sie können welche verpasst haben); bei gleicher Version gewinnt der
    größere Hash; ältere werden abgelehnt, die höchste bleibt auch nach dem Aufhören gemerkt (Rollback-Schutz).
  - *Prüfen beim Lesen*: Jeder Teil wird nicht nur beim Schreiben, sondern bei **jedem** Lesen von der Platte gegen
    seinen Hash geprüft; ein beschädigter Teil wird nie ausgeliefert und von anderen Hosts neu geholt.
  - Genaues: docs/07 („Beim Bau festgelegt“, §8, Grenzen §9).
- **Nachtrag nach dem 7. Review (11.11.2026)** – Grundsatz: Wer einen Knoten Arbeit machen lässt, bezahlt sie vorher;
  was entschieden ist, bleibt entschieden.
  - *Kontingent vorab*: Eine Version reserviert bei der Annahme ihre volle Größe auf das Kontingent des Owners (auch
    für Dateien, die hier noch fehlen), dazu je Owner höchstens 4 / 16 / 64 Apps je Knoten nach Stufe. Eine Version
    mit Dateien, die es nirgends gibt, kostet so Platz des Owners statt freier Plätze des Knotens, und sie wird nach
    12 Takten ohne Fortschritt (mit wachsender Pause) verworfen. Gefragt wird sparsam: erst die Kopf-Form des
    Manifests, Hash-Listen nur bei Hosts, die den Blob haben, höchstens 64 neue Blobs je Takt.
  - *Rang-Gedächtnis statt Versions-Zahl*: Je App merkt sich der Knoten den höchsten entschiedenen Rang (Version +
    Hash) – auch den der Version, die ihn entfernt hat, und abgelehnter Versionen – und nimmt nur echt Höheres. Für
    beendete Apps bleiben nur ID, Owner und Rang; vergessen wird erst nach einem Jahr (dann ist jede damalige Version
    abgelaufen), nicht nach Menge. Verworfen: „die ältesten zuerst vergessen“ (öffnete den Rückweg für Fluten).
  - *Stopp-Signal*: Eine voll geprüfte, neuere Version, die den Knoten nicht nennt, beendet das Hosten – egal, wer
    sie bringt (`/v4/app/update` ohne Anmeldung: die doppelte Signatur ist der Beweis). Hosts geben neue Versionen an
    die Hosts der vorigen weiter; Kommandozeile und SDK tun es beim Host-Wechsel, weil ein ganz neuer Host die alten
    nicht kennt.
  - *Lesefehler ≠ Verlust*: Nur ein falscher Hash oder eine zu kurze Datei macht einen Teil „verloren“; andere
    Fehler sind `503`. Vor dem Neu-Holen wird die eigene Datei geprüft.
  - *Langsame Leser*: Ströme mit Mindestrate, Höchstdauer und Zahl-Grenzen je Adresse und Knoten (im Transport,
    auch hinter Proxys). *Ohne Netz* keine Blobs, außer bewusst eingeschaltet mit Obergrenze.
  - Genaues: docs/07 (Abschnitte „Review 7“, §7–§9).
