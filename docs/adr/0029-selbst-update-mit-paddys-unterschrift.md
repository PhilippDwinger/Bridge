# ADR 0029 – BridgeControll aktualisiert sich selbst, mit Paddys Unterschrift

- **Status**: angenommen (14.11.2026; Fahrplan Phase 8, Schritt 4: „‚Update verfügbar' lädt die neue Version von
  GitHub, prüft Paddys Signatur und ersetzt sich – kein ZIP von Hand mehr“).
- **Kontext**: BridgeControll ist ein einziges Programm (App, Knoten, Tor). Bisher holt Paddy jede Version als ZIP aus
  den GitHub-Actions-Artifacts; Freunde ohne Programmier-Kenntnisse würden veralten. GitHub ist kostenlos und schon da,
  aber nicht Teil des Vertrauens (Zero Trust): ein Konto oder eine Datei dort kann manipuliert werden.
- **Entscheidung**: Ein eigener **Veröffentlichungs-Schlüssel** (Ed25519), privat nur auf Paddys PC, öffentlich fest im
  Programm. Eine kleine, unterschriebene **Ankündigung** (`releases/bridgecontroll.json` im Repo, Version, Größe und
  SHA-256 je Plattform) sagt, welche Datei aus dem GitHub-Release gilt; Paddy unterschreibt sie auf seinem PC mit
  `bridge-node release sign`, das die Dateien selbst lädt und hasht. Das Programm nimmt nur höhere Versionen,
  prüft Größe und Hash, ersetzt sich per Umbenennen (`.new` → Programm, Programm → `.old`), startet die neue Version
  und geht bei einem Fehlstart automatisch zurück. Updates laufen standardmäßig automatisch (abschaltbar).
- **Alternativen**: Schlüssel als GitHub-Secret und Unterschrift in der CI (bequemer, aber dann ist GitHub doch der
  Vertrauensanker); nur HTTPS ohne Unterschrift (dasselbe); Updates über das BridgeNet verteilen (jedes Netz bräuchte
  Paddys Dateien – später möglich, die Ankündigung bleibt dieselbe); Windows-Installer/MSIX (Code-Signing-Zertifikat
  kostet Geld).
- **Folgen**: Kein ZIP mehr von Hand – ab der ersten Version mit eingetragenem Schlüssel. Paddy muss die Schlüssel-Datei
  sichern (verloren: einmal von Hand aktualisieren). Ein Release braucht zwei Schritte von Paddy (Tag pushen,
  unterschreiben + pushen). Debug-Builds haben Test-Schalter für Adresse und Schlüssel, Release-Builds nicht.
  Einzelheiten: docs/12.
