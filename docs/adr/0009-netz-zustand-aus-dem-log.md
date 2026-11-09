# ADR 0009 – Netz-Zustand nur aus dem Log, Absetzen per Beweis

- **Status**: angenommen (09.11.2026, Phase 3; Paddy schläft, „entscheide selber“)
- **Kontext**: Wer ist Mitglied, wer Admin, wer hat welches Siegel? Das muss in allen Knoten gleich ausfallen. Kein
  Knoten darf das anders sehen, weil ihm jemand etwas Anderes erzählt hat (Z3).
- **Entscheidung**:
  1. Der Netz-Zustand entsteht **nur durch Abspielen des Transparenz-Logs der Reihe nach** (docs/06 §6). Alle Knoten
     rechnen selbst.
  2. Rechte werden zum Zeitpunkt des Eintrags geprüft. Ungültige Einträge werden übersprungen statt das Log zu
     stoppen – ein böser Log-Führer kann so nichts erzwingen, nur Lücken lassen. Lücken fallen durch Zeugen und
     Gossip auf.
  3. Köpfe und Zeugen-Signaturen stehen **nicht** im Log. Sie beglaubigen es von außen (wie Certificate Transparency).
  4. Zwei unvereinbare Köpfe desselben Log-Führers sind ein **Beweis**. Jeder Knoten, der ihn prüfen kann, setzt den
     Log-Führer sofort **lokal** ab und gibt den Beweis weiter. Das endgültige Entfernen macht eine Manifest-Änderung.
  5. Häufig wechselnde Angaben (Heim-Empfänger, `home`) kommen nicht ins Log. Sie sind vom Mitglied selbst signiert
     und werden zwischen Empfängern ausgetauscht.
- **Folgen**:
  - Das Log wächst nur mit Verwaltungs-Aussagen, nicht mit Nachrichten oder Anmeldungen.
  - Alle Knoten halten das ganze Log (klein) und können jeden Kopf nachrechnen.
  - Ohne bezeugten Kopf gilt nichts Neues. Fällt der Log-Führer aus, friert der Zustand ein, aber nichts geht
    kaputt.
