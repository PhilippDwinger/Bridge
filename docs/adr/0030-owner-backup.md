# ADR 0030 – Owner-Backup: für die 24 Wörter verschlüsselt, als App im eigenen Netz

- **Status**: angenommen (14.11.2026; Fahrplan Phase 8, Schritt 5: „App-Schlüssel und Einstellungen des Owners,
  verschlüsselt mit einem Schlüssel aus den 24 Wörtern, liegen auf den Speicher-Knoten; auf einem neuen PC stellen die
  24 Wörter alles wieder her“).
- **Kontext**: Der Owner-Knoten ist der **erste Log-Führer**; geht sein Schlüssel verloren, hilft auch die
  Not-Wiederherstellung nicht (docs/06 §5) – das Netz stünde für immer. Admin- und App-Schlüssel gibt es nur auf dem
  Owner-PC. Die 24 Wörter kennt der PC nicht (sie werden nie gespeichert).
- **Entscheidung**:
  - Verschlüsselt wird **für** den Empfangs-Schlüssel des Hauptschlüssels (X25519 in seiner Karte im Manifest; HKDF,
    ChaCha20-Poly1305, `bridge-core::backup`) – der PC kann sichern, nur die Wörter öffnen. Für bestehende Netze ohne
    Einrichtung.
  - Gesichert werden die Schlüssel-Dateien des Owner-Ordners (Knoten, TLS, Admin, Owner-Mitglied, App-Schlüssel) und
    wenige Einstellungen – nicht das Log (das haben alle Knoten).
  - Abgelegt als **eigene Bridge-App** (eine Datei) auf dem Owner-Knoten und bis zu 7 weiteren Web-Hosts: die
    vorhandene App-Maschine holt, prüft und hält sie bis zu einem Jahr, auch ohne den Owner-PC. Ein neuer Log-Eintrag
    **`backup`** `{app}` (Admin mit `rules`) zeigt darauf – so findet ein neuer PC das Backup mit den Wörtern und einer
    Adresse.
  - Wiederherstellen schreibt die Schlüssel in einen neuen Ordner; der Knoten holt das bezeugte Log von der Adresse und
    ist wieder Log-Führer. Verweigert, solange der alte Owner-Knoten noch antwortet.
- **Alternativen**: Erasure Coding über die Speicher-Knoten (docs/09) – Stücke laufen nach 30 Tagen ohne Verlängerung
  ab, das Backup muss aber gerade den Ausfall des Owner-PCs überdauern; Schlüssel aus den Wörtern ableiten (der PC hat
  sie nicht); das ganze Log mitsichern (unnötig, wird groß); ein Name im Netz als Zeiger (öffentlich sichtbar, wäre im
  Bridge-Browser eine „Website“).
- **Folgen**: Ohne Einrichtung gesichert, sobald BridgeControll läuft. Der Owner-Knoten bekommt dafür den Dienst `web`.
  Grenzen: Einträge der letzten Sekunden vor dem Ausfall können fehlen; mit neuer Adresse finden andere Knoten den
  Log-Führer erst, wenn sie die neue kennen (gleicher Tailscale-Name hilft). Ältere Knoten kennen `backup` nicht und
  überspringen den Eintrag. Einzelheiten: docs/12 §10.
