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

## 12.11.2026 – Bau-Claude: Phase 4 in BridgeControll v2 (Bridge-Browser, Namen, Meldungen)

Neue Bildschirme, gebaut nur aus UI-Kit-Bausteinen (Layout-Werte in `ui/app.css`, nur `var(--…)`); Bildschirmfotos
macht der Rauchtest (`tests/ui/smoke.py`, Bilder 02 und 15–22):

- **Bridge-Browser** (`#/browser`, von der Startseite und aus jedem Dashboard): Kopf wie N03 (`bc-hero`), Netz-Wahl
  (K23 `b-seg`, bei einem Netz ein K31-Chip mit ID-Fingerabdruck), Adresszeile K19 (`b-wrap` mit Globus-Icon, Eingabe
  ohne eigenen Rahmen) + Primärknopf „Öffnen“ + K20 „Sicherer Modus“. Treffer als `srv`-Zeilen (Name, Beschreibung,
  Chips/Pillen, runder Pfeil K11). Geöffnete Seite: links die App in einem gerahmten `iframe`, darüber Adresse, „In
  neuem Tab öffnen“ (Ghost) und „Melden“ (K04 Gefahr); rechts eine Karte „Schloss“ (Schloss-Icon + „Geprüft“ grün /
  „Vorsicht“ amber-braun / „Nicht geöffnet“ rot, Fakten-Liste, Warnungen als kleine `--warn-bg`-Kästen). Schranken
  (18+, neuer Inhaber) als Karte an Stelle der App.
- **Melden** (Dialog K27): Gründe als K22 `b-radio`, Text als `textarea.b-input`, Hinweis, an wen die Meldung geht.
- **Namen** (Owner-Dashboard, Hauptspalte): `srv`-Zeilen mit Adresse (Sora, 22 px), Pillen „Gilt“/„Löst nicht auf“,
  Chips; „Name anmelden“ (Dialog: Name als K18 mit Nachsatz `.kurzname`, Ziel als K23, App als K25 `b-selectwrap`).
- **Meldungen** (Owner-Dashboard, Hauptspalte): Filter K24 `b-seg--sm`, je Meldung eine Zeile mit Grund-Pille (err für
  Phishing/illegal, sonst warn), Ziel, Status, Text (Zeilenumbrüche erhalten), Schnell-Aktionen als kleine
  Sekundär-Knöpfe, „Erledigt“ als Ghost; Banner K49 „Meldeweg fehlt“ mit Knopf; Seitenleiste „Regeln für Namen“.
- **Assistent Schritt 1**: zweite Karte „Du bist der Betreiber“ (Meldeweg, Kurzname als K18 mit Vorsatz `shop.`, 18+
  als K23).
- **Einstellungen**: „Leser für den Bridge-Browser“ als K23.

Fragen/Wünsche an den Design-Claude:
1. Für das „Schloss“ (Sicherheits-Status einer Seite) gibt es keinen Baustein; ich nutze eine `bc-card` mit Icon in
   `--ok`/`--warn`/`--err`. Wäre ein eigener Baustein „Sicherheits-Karte“ (wie ein Browser-Schloss) sinnvoll?
2. Warnungen in der Karte sind kleine Kästen in `--warn-bg`/`--warn` – ähnlich `b-banner--warn`, aber kleiner. Passt
   das, oder soll es ein `b-banner--sm` geben?
3. Der Rahmen um die App (`iframe`) ist eine Fläche `--surface` mit `--r-l` und Linie – bitte prüfen, ob sich die
   fremde App genug von BridgeControll abhebt (eine Kopfleiste „Diese Seite gehört nicht zu BridgeControll“?).

