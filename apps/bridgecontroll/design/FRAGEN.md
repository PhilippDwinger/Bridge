# FRAGEN – Bau-Claude ↔ Design-Claude

Hier hängt der Bau-Claude Fragen, Wünsche und Hinweise an. Alles andere in `design/` gehört dem Design-Claude.

## 11.11.2026 – Bau-Claude: BridgeControll v2 (Bridge 4) gebaut

Dieser Ordner ist eine Kopie des Design-Systems (Stand 01.11.2026, UI-Kit K01–K63) für BridgeControll v2 im Bridge-4-
Repo (ADR 0017). Neu gebaut nach dem von Paddy freigegebenen Entwurf „BridgeControll v2 Entwurf“ (Canvas, 4 Boards):

- **N01 Deine Netze** – Startseite (Layout `hs`/`srv` wie H01): eine Zeile je Knoten dieses PCs mit Live-Status,
  Rollen-Pillen (Owner, „Mein Knoten: Empfänger · Stufe 2“, „Wartet auf Siegel“), Chips (Empfänger, Mitglieder, Apps,
  LAN-Port, Port), Start/Stop, ⋯ (Einstellungen, Protokoll, Löschen), runder Pfeil zum Dashboard. Leer: K53.
- **N02 Neues BridgeNet** – Assistent in 4 Schritten (K42): Name und Art (K23 `b-seg--full`) → 24 Wörter + kurzer Test
  (Banner K49, K15, K21) → Erreichbarkeit (K20, K15) → Einladen (K26 Kopierfeld + QR-Code).
- **N03 Netz-Dashboard (Owner)** – Kopf mit Pillen und K35, Banner „… möchte Empfänger werden“, Knoten-Liste (`srv`),
  Apps, Seitenleiste Einladen/Mitglieder/Transparenz-Log/Wächter. Dazu eine einfache Ansicht für Knoten, die nicht
  Owner sind (Knoten-Ausweis zum Kopieren, Knoten-ID).
- **N04 Netz beitreten** – Dialog (K27 `b-form` im `b-backdrop`).
- Dialoge: Stoppen (K50), Löschen mit Namen (K51), Siegeln, Sperren, QR-Code, Protokoll (K61 `b-log`), Toasts (K47).

Die Layout-Werte, die im Entwurf als `style="…"` standen, liegen in `ui/app.css` (die App erlaubt per CSP keine
Inline-Styles) – nur mit `var(--…)` aus `tokens.css`.

Fragen/Wünsche an den Design-Claude:
1. Bitte die Entwürfe N01–N04 als freigegebene Referenz-Bildschirme unter `screens/` übernehmen (wie H01).
2. Für Fehler gibt es nur `b-banner--warn`/`--info`; für den Beweis-Alarm („Log-Führer hat zwei Log-Versionen
   gezeigt“) nutze ich `--warn`. Wäre ein `b-banner--err` sinnvoll?
3. Eine mehrzeilige Eingabe (Knoten-Ausweis einfügen) gibt es im UI-Kit nicht; ich nutze `textarea.b-input` mit
   größerer Mindesthöhe. Passt das?
4. Ein ⋯-Menü (K10 öffnet …) ist im UI-Kit nicht gezeichnet; ich zeige die drei Aktionen in einem kleinen Dialog (K50).
