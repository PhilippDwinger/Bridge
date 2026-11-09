# ADR 0014 – Not-Form nur mit dem ersten Log-Führer; Aufholen begrenzt und von verschiedenen Knoten

- **Status**: angenommen (09.11.2026, nach Prüfung 6; Paddy schläft, „entscheide selber“)
- **Kontext**: Prüfung 6 (Befund 1) zeigte, dass die 24 Wörter allein einen folgenden Knoten weiter gabeln konnten –
  in zwei Schritten: (a) im **echten** Log einen eigenen Knoten A siegeln und als **zweiten** Log-Führer eintragen
  (`logs = [O, A]` – sieht aus wie die empfohlene Vorsorge); (b) dem Folgenden einen Anhang zeigen, dessen nächster
  Eintrag ein Manifest allein vom Hauptschlüssel ist (`logs = [A]`, eigener Zeuge), mit einem Übergangs-Kopf von A
  und dem `cosign` des Hauptschlüssels. Die Not-Form (ADR 0012) und die Bestätigung eines hängenden Wechsels über die
  Not-Wiederherstellung danach (ADR 0013, Punkt 2) nahmen **irgendeinen** Log-Führer der alten Regeln. Daneben:
  Übergangs-Köpfe wurden bei vier *Adressen* statt vier *Knoten* gesucht (Befund 2), gespeicherte Übergangs-Köpfe nach
  einem Neustart kaum geprüft (Befund 3), und ein gefälschter Anhang kostete je Quelle und Runde einen ganzen
  Download samt Abspielen und Abrufen (Befund 4).
- **Entscheidung**:
  1. **Not-Form** (Übergangs-Kopf eines Manifests allein vom Hauptschlüssel ohne Zeugen-Mehrheit) und **Bestätigung
     eines hängenden Wechsels** über die Not-Wiederherstellung direkt danach zählen nur, wenn der Kopf vom **ersten**
     Log-Führer der alten Regeln (`logs[0]`) signiert ist – dem, der nach `operator_for_head` die Köpfe ausstellt.
     Beweise gegen ihn werden dabei nicht berücksichtigt: Sie liegen nicht bei jedem Knoten vor, die Entscheidung
     muss überall gleich sein (deterministisch, wie das Abspielen). `net rescue` wartete schon immer genau auf den Kopf
     dieses Log-Führers.
  2. **Normal-Form bleibt**: Mit `witness_threshold` alten Zeugen zählt der Kopf **jedes** Log-Führers der alten
     Regeln. Die Zeugen bezeugen nur, was zu ihrem eigenen Log und ihrem zuletzt bezeugten Kopf passt – gleich, wer
     den Kopf signiert hat –, die Zeugen-Mehrheit ist hier der Anker. Den ersten Log-Führer auch hier zu verlangen,
     nähme dem zweiten die Übernahme nach einem Beweis gegen den ersten.
  3. **Aufholen**: Übergangs-Köpfe werden bei bis zu 4 **verschiedenen Knoten** gesucht (der Knoten der Quelle zuerst,
     je Knoten seine LAN- und öffentlichen Adressen), die Wechsel einzeln vom neuesten zum ältesten geprüft
     (`Transitions::endorsement`), Schluss beim ersten, der sich nicht bestätigen lässt. Ein abgelehnter Kopf wird
     4 Folge-Takte lang von keiner Quelle mehr geladen, die Quelle so lange übersprungen, ein nirgends gefundener
     Übergangs-Kopf so lange nicht erneut erfragt (je höchstens 64 gemerkt).
  4. **Gespeicherte Übergangs-Köpfe** werden nach jedem Neustart wie beim Aufholen geprüft (Regeln und Karten der
     Zeit des Wechsels, Wurzel des eigenen Logs); was nicht passt, wird nicht herausgegeben und bei anderen Knoten neu
     geholt (höchstens 8 Versuche mit wachsenden Pausen); ein geprüfter Kopf ersetzt die kaputte Zeile; was sich nicht
     speichern ließ, wird wieder versucht.
- **Folgen**:
  - Was ein Fälscher braucht, um einen Knoten, der schon folgt, zu gabeln (am ersten abweichenden Wechsel): einen
    Log-Führer der alten Regeln **und** die alte Zeugen-Mehrheit – **oder** die 24 Wörter **und** den Schlüssel des
    **ersten** alten Log-Führers. Die Wörter allein oder die Admins mit `rules` reichen nicht, auch nicht über einen
    vorher eingetragenen zweiten Log-Führer. Wer sich mit den Wörtern zum ersten Log-Führer macht, braucht dafür ein
    von der alten Zeugen-Mehrheit bezeugtes Manifest im echten Log – sichtbar für alle, eine Übernahme statt einer
    heimlichen Gabelung.
  - Ist der erste Log-Führer für immer weg oder abgesetzt **und** die alte Zeugen-Mehrheit auch, gibt es keinen Weg
    mehr zurück (Netz neu erstellen). Vorher half in diesem Fall ein zweiter Log-Führer – genau das war die Lücke.
  - Ein Fälscher kann hinter seinem gefälschten Wechsel weitere Wechsel unter eigenen Regeln anhängen; deren Köpfe
    prüft ein Folgender (je ein kleiner Abruf), bevor er beim gefälschten aufhört – begrenzt auf 64 je Versuch und
    einen Versuch je Quelle und 4 Takte.
  - Ändert die Zustands-Regel für Karten (Befund 6, docs/06 §2/§6): Ein Siegel mit einer Karte, die mehr als 5 min
    nach dem Siegel ausgestellt ist, ist ungültig; „neueste Karte“ heißt größtes `min(iat der Karte, iat des Siegels)`.
    Gespeicherte Logs mit solchen Siegeln spielen anders ab (Phase 3 ist noch nicht im Einsatz).
