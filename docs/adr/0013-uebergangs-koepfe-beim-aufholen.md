# ADR 0013 – Übergangs-Köpfe beim Aufholen: jeder Wechsel der Log-Regeln braucht die alte Besetzung

- **Status**: angenommen (09.11.2026, nach Prüfung 5; Paddy schläft, „entscheide selber“)
- **Kontext**: Nach ADR 0010 gilt für einen Kopf der Größe n die Besetzung (Log-Führer, Zeugen, Schwelle) nach den
  ersten n − 1 Einträgen. Ein Knoten, der hinter einem Wechsel stand, prüfte beim Aufholen aber nur den **neuesten**
  Kopf – gegen die Regeln, die die neuen Einträge selbst festlegen. Den Übergangs-Kopf (Größe j + 1, noch von der
  alten Besetzung bezeugt) verlangte er nie. Prüfung 5 (Befund 1) zeigte: Wer allein die 24 Wörter hat (oder die
  `approvals.rules` Admins), erfindet einen Anhang – eigenen Log-Führer und Zeugen siegeln, Manifest auf sie
  umstellen, Kopf von ihnen – und ein nachhängender Knoten nimmt ihn (Gabelung). Die Aussage in ADR 0012 („ein
  Fälscher braucht die Wörter **und** den Schlüssel des Log-Führers“) stimmte so nicht.
- **Entscheidung**:
  1. Für **jeden** Wechsel an Index j, den ein Knoten beim Aufholen überquert, muss er den Übergangs-Kopf der Größe
     genau j + 1 haben und prüfen: signiert von einem Log-Führer der Regeln **vor** j, bezeugt von deren
     `witness_threshold` Zeugen – bei einem Manifest allein vom Hauptschlüssel auch in der Not-Form (alter Log-Führer
     + `cosign` des Hauptschlüssels, ADR 0012). Die geladenen Einträge [0, j + 1) müssen genau seine Wurzel ergeben.
     Ohne Zeit-Prüfung (alte Köpfe laufen ab, ihre Aussage bleibt). Erst dann gelten die neuen Regeln weiter vorn.
  2. Ausnahme Not-Wiederherstellung während eines hängenden Wechsels: Wurde der Übergangs-Kopf von j nie bezeugt und
     ist der nächste Eintrag (j + 1) ein Wechsel allein vom Hauptschlüssel, bestätigt dessen (bestätigter)
     Übergangs-Kopf auch j – nur wenn er von einem Log-Führer der Regeln vor j signiert ist (*nach Prüfung 6*: vom
     ersten, ADR 0014).
  3. Jeder Knoten behält die Übergangs-Köpfe samt `cosign` für immer (die letzten 64 Wechsel, wie die gemerkten
     Regel-Wechsel; SQLite-Schema 4, nur angehängt) und gibt sie über `POST /v4/net/{netz}/head/at` `{"size":n}`
     heraus (`NOT_FOUND`, wenn er keinen hat; Rate-Grenze wie die Nachweise). Folgende Knoten holen sie bei ihrer
     Quelle, dann bei bis zu drei weiteren Quellen (*nach Prüfung 6*: verschiedene **Knoten**, nicht Adressen; neuester
     Wechsel zuerst, Schluss beim ersten nicht bestätigten; nach einem Neustart wird jeder gespeicherte Kopf erneut
     geprüft – ADR 0014).
  4. Mehr als 64 Wechsel auf einmal: Ein Folgender nimmt den Kopf nicht (fail closed). Der erste Kontakt prüft die
     letzten 64.
- **Folgen**:
  - Eine Gabelung eines Knotens, der schon folgt, braucht jetzt die Wörter **und** den Schlüssel des alten
    Log-Führers (Not-Form) – oder die Admins mit `rules` bzw. die Wörter **und** den alten Log-Führer **und** die alte
    Zeugen-Mehrheit. Das bisherige Restrisiko „Kopf von einem Log-Führer, den nur die neuen Einträge nennen“ ist weg.
    *Genauer nach Prüfung 6 (ADR 0014)*: „der alte Log-Führer“ in der Not-Form (und bei Punkt 2) ist der **erste** der
    alten Regeln (`logs[0]`). Vorher genügte irgendeiner – und einen zweiten konnte man mit den Wörtern allein vorher
    im echten Log eintragen. Präzise braucht ein Fälscher jetzt: einen alten Log-Führer **und** die alte
    Zeugen-Mehrheit, oder die 24 Wörter **und** den Schlüssel des ersten alten Log-Führers.
  - Ehrliche Wechsel (Zeugen, Log-Führer, Not-Wiederherstellung, auch mehrere hintereinander) bleiben nachholbar:
    Die Köpfe gibt es bei allen Knoten, die den Wechsel gesehen haben.
  - Kosten: ein kleiner Abruf je Wechsel beim Aufholen, eine Tabelle mit höchstens 64 Zeilen je Netz.
  - Nicht gelöst: Ein ganz neuer Knoten (erster Kontakt) hat als Anker nur die Netz-ID – wer die Wörter hat, kann ihm
    ein ganz anderes Log ab Eintrag 0 zeigen (docs/06 §10).
