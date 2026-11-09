# ADR 0001 – Zero Trust und Abteile als Grundlage

- **Status**: angenommen (09.11.2026, Paddy)
- **Kontext**: Bridge 4 / BridgeNet soll sehr groß werden; viele fremde PCs bieten Dienste an.
- **Entscheidung**: Jede Entscheidung folgt den Grundsätzen in `00_GRUNDSAETZE.md`: Zero Trust (Z1–Z10) und klare
  Abteile (S1–S6). Ein Repo (`PhilippDwinger/Bridge`), Branch `bridge-4`; Bridge 3 läuft parallel weiter.
- **Folgen**: Mehr Aufwand pro Funktion (Signaturen, Limits, Angriffs-Tests), dafür kann ein böser Knoten wenig
  Schaden anrichten und das Projekt bleibt beherrschbar.
