# ADR 0008 – Invariante N1: (Schlüssel, Nonce) wiederholt sich nie

- **Status**: angenommen (09.11.2026; Hinweis aus der ChatGPT-Prüfung zur festen Nonce)
- **Entscheidung**: N1 ist eine Protokoll-Invariante und wird doppelt abgesichert:
  1. `bridge-core` erzeugt Wegwerf-Schlüssel immer selbst (die API nimmt keine von außen).
  2. Die Nonce ist zusätzlich zufällig (96 Bit) und steht im Umschlag.
  3. Bei Strömen gilt: Zufalls-Präfix + Zähler ohne Überlauf.
  4. Tests: keine Duplikate bei Millionen Umschlägen, Neustart-Test, gleicher Klartext ergibt anderen Geheimtext.
- **Folgen**: 12 Byte mehr pro Umschlag. Ein einzelner Fehler (kaputter Zufall, VM-Schnappschuss) bricht die
  Verschlüsselung nicht.
