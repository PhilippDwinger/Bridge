# ADR 0022 – Agenten-Ausweise statt geliehener Schlüssel

- **Status**: angenommen (13.11.2026, von Claude entschieden – Paddy war weg; Freigabe steht aus).
- **Kontext**: KIs und Bots sollen für Mitglieder handeln. Mit dem Schlüssel des Mitglieds könnten sie alles, was das
  Mitglied kann; ein Leck (Prompt-Injection, Fehler im Bot) wäre der ganze Ausweis.
- **Entscheidung**: Aussage `agent` (nicht im Log), vom Inhaber signiert, für einen **eigenen** Schlüssel des Agenten:
  - nur die Rechte `send`/`receive`, optional nur an bestimmte Empfänger (`to`), Rate pro Stunde, Heim-Knoten fest,
    höchstens 30 Tage, jederzeit widerrufbar (gespeichert am Heim-Knoten);
  - der Agent ist kein Mitglied: alles außer Senden/Abholen/Karten ist für ihn verboten (Standard: verboten);
  - gilt nur, solange der Inhaber Mitglied und nicht gesperrt ist – Sperre des Inhabers trifft seine Agenten sofort;
  - Empfänger sehen „Agent im Auftrag von Inhaber“ (die Aussage reist mit und wird im SDK geprüft).
- **Warum nicht im Log**: Agenten sind kurzlebig und privat; das Log bliebe sonst voll von Wegwerf-Ausweisen. Der Schutz
  hängt an der Mitgliedschaft des Inhabers (im Log) und am Heim-Knoten (Widerruf).
- **Folgen**: Neuer Heim-Eintrag-Typ im Heim-Austausch; Sitzungen kennen Rechte; Schema 13 (Widerrufe). Spätere Rechte
  (Dateien, Rechnen) brauchen eine neue Spezifikation – unbekannte Rechte machen eine Aussage ungültig.
