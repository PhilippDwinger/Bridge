# 00 – Grundsätze von Bridge 4

Gilt für **jede** Entscheidung, jede Zeile Code, jede Doku. Wer an Bridge arbeitet (Paddy, Claude, später andere),
prüft sich hieran.

## Ziel
Bridge 4 ist die Grundlage für **BridgeNet**: Jeder kann ohne Programmieren ein eigenes Netz erstellen, ein „Internet
im Internet“. Ein Netz besteht aus vielen PCs, die Dienste anbieten: Websites, Speicher, Rechnen, KI usw. Clients
nutzen sie von überall. Bridge muss sehr groß werden können und dabei **sicher und zuverlässig** bleiben.

## 1. Zero Trust – niemandem vertrauen müssen
Jeder Knoten, jeder Client und jede Leitung kann böse oder kaputt sein. Das System ist so gebaut, dass das wenig
Schaden anrichtet.

| Regel | Bedeutung im Alltag |
|---|---|
| **Z1 Verschlüsseln** | Inhalte sind Ende-zu-Ende verschlüsselt. Knoten sehen nur, was sie zum Weiterleiten brauchen. |
| **Z2 Signieren** | Jede Aussage, auf die sich jemand verlässt (Nachricht, Siegel, Namens-Eintrag, Regel), ist signiert. |
| **Z3 Prüfen, nicht glauben** | Jede Eingabe wird geprüft: Signatur, Hash, Format, Größe, Zeit, Berechtigung. Auch Daten von „eigenen“ Knoten. |
| **Z4 Kleinste Rechte** | Jede Identität, jeder Schlüssel, jedes Plugin, jede KI darf nur das Nötigste – mit Ablaufdatum. |
| **Z5 Grenzen überall** | Jede Liste, jeder Speicher, jede Schleife, jede Anfrage hat eine Obergrenze (Anzahl, Bytes, Zeit, Rate). |
| **Z6 Kein einzelner Punkt** | Nichts hängt an einem einzigen Knoten oder Schlüssel: mehrere Empfänger, Kopien, Mehr-Augen bei Kritischem. |
| **Z7 Vertrauen verdienen** | Neue Identitäten starten mit wenig Rechten (Stufe 0) und steigen durch Prüfungen und Zeit auf. |
| **Z8 Fehler sind sicher** | Im Zweifel ablehnen (fail closed). Ein Fehler darf nie zu mehr Rechten führen. |
| **Z9 Nachvollziehbar** | Sicherheitsrelevante Änderungen (Siegel, Sperren, Regeln) stehen im Transparenz-Log. |
| **Z10 Keine eigene Krypto** | Nur bekannte Verfahren und geprüfte Bibliotheken; Krypto-Code nur an einer Stelle (`bridge-core`, Modul `crypto`). |

## 2. Struktur – Abteile mit klaren Grenzen
| Regel | Bedeutung |
|---|---|
| **S1 Abteile** | Jedes Abteil hat eine Aufgabe, eigene Daten, eine schmale öffentliche Schnittstelle (siehe 03_ARCHITEKTUR). |
| **S2 Schichten** | Abhängigkeiten nur nach unten. Jedes Abteil ist ein eigenes Crate – der Compiler erzwingt das. |
| **S3 Kein globaler Zustand** | Zustand lebt in Objekten (`Node`-Kontext) und in der Datenbank, nicht in globalen Variablen. Mehrere Knoten in einem Prozess (Tests) gehen. |
| **S4 Erweitern über Plugins** | Neue Dienst-Arten (Speicher, KI …) sind Plugins mit Manifest – der Kern bleibt klein. Fremde Plugins nur in der WASM-Sandbox. |
| **S5 Eine Wahrheit** | Jede Regel/Konstante an genau einer Stelle; Protokoll-Formate nur in `core` definiert. |
| **S6 Spezifikation vor Code** | Erst in `docs/` beschreiben, dann bauen. Entscheidungen als ADR (`docs/adr/`). |

## 3. Qualität
- **Jede Funktion hat Tests** – auch **Angriffs-Tests**: Was passiert bei gefälschter Signatur, Wiederholung, zu
  großer Eingabe, 10 Mio. Anfragen?
- **Chaos-Tests**: Knoten fallen aus, Leitungen werden langsam, Uhren gehen falsch.
- **Compiler und Linter**: Rust mit clippy (streng), rustfmt, `forbid(unsafe_code)`; cargo-deny für Abhängigkeiten. Kein Merge mit roten Tests.
- **Zuverlässigkeit**: Neustarts verlieren nichts Wichtiges (Persistenz). Alles ist idempotent und wiederholbar.
- **Lesbarkeit**: kurze Funktionen, sprechende Namen, Kommentare erklären *warum*.

## 4. Arbeitsweise
- Bridge 3 (Branch `bridge-3`) läuft weiter, bis Bridge 4 es ersetzt. Bridge 4 entsteht auf Branch `bridge-4` im
  selben Repo `PhilippDwinger/Bridge`.
- Doku auf Deutsch, Code und Code-Kommentare auf Englisch (wie bisher).
- Sprachen nach Sinn, nicht nach Gewohnheit: Rust für Knoten und Abteile, Web-Technik für Oberflächen, SDKs in den
  Sprachen der Clients (ADR 0003).
- Fremde Meinungen (z. B. Prüfungen durch andere KIs) werden ernst genommen, geprüft und mit Begründung übernommen
  oder verworfen.
- Lizenz: PolyForm Shield 1.0.0.
- Kein Zeitdruck: Es dauert so lange, wie es dauert. Lieber richtig als schnell.

## Checkliste für jede neue Funktion
1. Wer darf das (Stufe, Rolle, Schlüssel)? → Z4
2. Was wird geprüft (Signatur, Format, Größe, Zeit)? → Z3
3. Welche Grenzen gelten (Anzahl, Bytes, Rate, Dauer)? → Z5
4. Was sieht ein böser Knoten auf dem Weg? → Z1
5. Was passiert, wenn ein Beteiligter ausfällt oder lügt? → Z6, Z8
6. Muss es ins Transparenz-Log? → Z9
7. In welches Abteil gehört es, und ändert sich eine Schnittstelle? → S1, S2
8. Welche Tests (normal, Angriff, Chaos)?
