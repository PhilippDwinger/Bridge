# ADR 0010 – Identität einer Aussage ohne Signaturen, Log-Regeln nach Kopf-Größe

- **Status**: angenommen (09.11.2026, nach Prüfung 3; Paddy schläft, „entscheide selber“)
- **Kontext**: Die Prüfung fand zwei Lücken im Netz-Protokoll (docs/06):
  1. Der Hash einer Aussage lief über die ganzen Bytes **mit** Signaturen. Bei Mehr-Augen-Aussagen (`sigs`) ließ
     sich dieselbe gültige Aussage umordnen oder auffüllen und bekam einen neuen Hash – ein widerrufenes Siegel
     wurde so wieder gültig.
  2. Änderte ein Manifest `logs`, `witnesses` oder `witness_threshold`, wandte der Log-Führer es sofort an; Zeugen
     und folgende Knoten kannten es noch nicht. Das Netz fror für immer ein.
- **Entscheidung**:
  1. Jede Aussage hat genau eine Byte-Form: `sigs` streng aufsteigend nach `iss`, jeder Eintrag genau `{iss, sig}`.
     Die **Identität** (Hash) einer Aussage ist SHA-256 der kanonischen Bytes **ohne** `sig`/`sigs`. Sie zählt für
     Widerruf, Ersetzen, Doppelte und `cosign`. Nur die Blätter des Merkle-Baums hashen die ganzen Bytes.
  2. Für einen Kopf der Größe n gelten die Log-Regeln nach den ersten n − 1 Einträgen: Der Kopf, der mit einem
     Manifest-Wechsel endet, wird noch gegen die alten Regeln geprüft, jeder größere gegen die neuen. Der Log-Führer
     stellt diesen Übergangs-Kopf sofort aus und nimmt nichts mehr an, bis er bezeugt ist. Zeugen und folgende
     Knoten entscheiden nach derselben Regel; wer hinter einem gültig signierten Wechsel steht, spielt die Einträge
     auf einer Kopie ab, bevor er einen Kopf annimmt.
- **Folgen**:
  - Andere Unterzeichner für denselben Inhalt sind dieselbe Aussage (widerrufen bleibt widerrufen). Alte Hashes in
    gespeicherten Logs ändern sich (Phase 3 ist noch nicht im Einsatz).
  - Zeugen und Log-Führer lassen sich per Manifest wechseln, ohne dass das Netz stehen bleibt; das Übergangs-Fenster
    gibt niemandem einen Kopf mit der falschen Besetzung. Knoten merken sich die letzten 64 Wechsel.
  - Eine Kopie des Zustands kostet Speicher; sie entsteht nur hinter echten (signierten) Manifest-Wechseln.
- **Nachtrag (Prüfung 5, ADR 0013)**: „Wer hinter einem gültig signierten Wechsel steht, spielt die Einträge auf einer
  Kopie ab“ reichte nicht – ein nachhängender Knoten prüfte nur den neuesten Kopf gegen die Regeln aus den neuen
  Einträgen, den Übergangs-Kopf nie. Wer die 24 Wörter (oder die Admins mit `rules`) hatte, konnte ihn so gabeln. Jetzt
  muss jeder überquerte Wechsel durch seinen Übergangs-Kopf unter den alten Regeln bestätigt sein (Knoten behalten
  und verteilen diese Köpfe). Eine Gabelung braucht damit den Schlüssel des alten Log-Führers und die alte
  Zeugen-Mehrheit – oder die Wörter und den alten Log-Führer (Not-Form, ADR 0012).
