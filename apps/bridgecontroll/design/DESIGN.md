# Bridge-App – Design

Dieser Ordner `design/` ist die **einzige Quelle für das Aussehen** der Bridge-App (BridgeControll).

## Wer macht was
- **Design-Claude** (Chat mit Paddy, Design-Canvas „Bridge App Design“): schreibt **nur** in `design/`.
- **Bau-Claude** (baut die App in `BridgeControll/`): schreibt **alles außer** `design/`.
  - In `design/` nur lesen. Einzige Ausnahme: **`design/FRAGEN.md`** – dort unten anhängen (Fragen, Wünsche, welche Daten es gibt).
  - `design/` ist als `/design` in FastAPI gemountet → Änderungen hier wirken sofort.
- Paddy entscheidet. Was hier unter „Entschieden“ steht, hat er bestätigt. Neue Design-Teile zeigt der Design-Claude Paddy erst auf dem Canvas; nur Freigegebenes landet hier.

## Entschieden
| Thema | Entscheidung |
|---|---|
| Markenfarbe | **Bridge-Blau `#3369FF`** (`--bridge-blue`), Skala 50–950 in `tokens.css` |
| Bildmarke | `logo/bridge-bildmarke.svg` – blauer Brückenbogen als Sticker + kleiner Amber-Punkt |
| Wortmarke | `logo/bridge-wortmarke.svg` – „br.“ (Sora Bold als Pfad), Sticker-Kontur |
| App-Icon | `logo/bridge-app-icon.svg` |
| Schriften | **Sora** (Überschriften, Namen) · **IBM Plex Sans** (Text) · **IBM Plex Mono** (Nummern, Ports, Commits). Lokal in `fonts/`. |
| Grundton | **Hell**. Dunkelmodus noch nicht entschieden. |
| Startbildschirm eines Servers | **Entwurf 09 „Großschrift-Liste“** → `screens/start.html` |
| Erste Seite der App | **H01 Hosting-Bildschirm** (alle Server) → `screens/hosting.html` |
| Bausteine | **UI-Kit K01–K63** (am 01.11.2026 komplett freigegeben) → `components.css`, Übersicht mit Markup: `screens/ui-kit.html` |

## Seitenfluss
```
hosting.html  (alle Server, Start/Stop/Update, „Server hinzufügen“)
   └─ Klick auf Server-Name oder runden Pfeil
      start.html  (die 9 Bereiche dieses Servers, Tasten 1–9)
         ├─ Übersicht, Vertraute Server, Backup, Einstellungen → echte Seiten (folgen als nächster Design-Schritt)
         └─ Clients, Realms, Nachrichten, Freunde, Logs → kommt-noch.html (bis Bridge die Daten liefert)
```

## Einbinden
```html
<link rel="stylesheet" href="/design/tokens.css">
<link rel="stylesheet" href="/design/components.css">
<body class="b-page">
```
Alle Bausteine heißen `b-…` (Block `b-pill`, Teil `b-pill__dot`, Variante `b-pill--ok`). Seiten-Layouts: `start`, `area`, `hs`, `srv`, `soon`.
Zustände als Klasse: `is-done`, `is-now`, `is-new`, `is-flash`, `is-in`, `is-out`, `has-update`, `is-error`.

## Bausteine (Nummern wie auf dem Canvas)
| Nr. | Baustein | Klassen |
|---|---|---|
| K01–K07 | Knöpfe: Primär, Sekundär, Ghost, Gefahr, Dunkel, Sticker, Größen | `b-btn` + `--primary/--secondary/--ghost/--danger/--danger-solid/--dark/--sticker/--sm/--lg` |
| K08 | Zustände (hover, gedrückt, Fokus, gesperrt) | automatisch über `:hover`, `:active`, `:focus-visible`, `disabled` |
| K09 | Knopf lädt | `<span class="b-spin">` im Knopf + `aria-busy="true"`; mit Fortschritt `b-btn--progress` + `style="--progress:.42"` |
| K10 | Icon-Knöpfe | `b-icon` (`--plain`), immer `aria-label` |
| K11 | Runder Pfeil | `b-go` |
| K12 | Update-Hinweis-Punkt | `b-dot-badge` |
| K13 | Start/Stop-Schalter | `b-power--on/--off` |
| K14 | Knopfgruppe | `b-group` |
| K15–K19 | Textfeld, Passwort, Port-Zähler, Adresse mit Vor-/Nachsatz, Suche | `b-field`, `b-input`, `b-wrap`, `b-affix`, `b-in-icon`, `b-step`, `b-kbd`, `b-hint(--err)` |
| K20–K22 | Schalter, Checkbox, Auswahlpunkte | `b-switch`, `b-check`, `b-radio` (echte `<input>`) |
| K23–K24 | Umschalter (Erreichbarkeit, Funnel-Port) | `b-seg` (`--sm`, `--full`) |
| K25 | Auswahl (Branch) | `b-selectwrap` + `select.b-input` |
| K26 | Kopierfeld | `b-copy`; nach Klick `.is-done` für 1,6 s, Text „Kopiert“ |
| K27 | Formular „Server hinzufügen“ | `b-form` (+ `__head/__body/__foot`), im Dialog `b-backdrop` |
| K28–K33 | Zustands-Pillen | `b-pill--ok/info/neutral/warn/err`, `b-pill__dot(--live/--hollow/--square)`, `b-pill__spin` |
| K29 | Live-Punkt | `b-live--ok/--blue/--amber` |
| K31/K36 | Chips (Commit, Branch, Port) | `b-chip` |
| K34/K35 | Zähler, Kennzahlen | `b-count--blue/--soft/--amber`, `b-stats` + `b-stat` |
| K37 | Bogen-Loader | `b-loader-arch` (Markup in ui-kit.html) |
| K38 | Trittsteine-Loader | `b-stones` mit 5 `<i>` |
| K39 | Ring | `b-ring` (`--sm/--lg`) |
| K40/K41 | Ladebalken | `b-bar` + `b-bar__run` (ohne Ende) oder `b-bar__fill` mit `style="width:62%"` |
| K42 | Update-Schritte | `b-steps` + `b-step-i` (`.is-done`, `.is-now`) |
| K43 | Rollendes Update | `b-roll` |
| K44 | Platzhalter beim Laden | `b-skel`, `b-sh` |
| K45 | Start-Splash | `b-splash`, `b-splash__mark`, `b-splash__text` |
| K46 | Checkliste beim Server-Start | `b-checklist`, `b-checkrow` |
| K47/K48 | Toasts | `b-toast` (+ `__ic--ok/warn/err/info`, `--dark`, `__undo`), Stapel `b-toasts` unten rechts, `.is-in`/`.is-out`, `b-toast__timer` (`--toast-time`) |
| K49 | Banner | `b-banner--warn/--info` |
| K50/K51 | Dialoge | `b-backdrop` + `b-dialog` (+ `__btns`) |
| K52 | Tooltip | `b-tip` + `b-tip__bubble` (erscheint bei Hover/Fokus nach 0,35 s) |
| K53/K54 | Leer / Kommt noch | `b-empty`, `b-float`, `b-build` |
| K55 | Steuer-Dienst weg · Gespeichert | `b-offline`, `b-saved` |
| K56/K57 | Tempo & Kurven | `--dur-1…4`, `--ease-out/-io/-spring` in tokens.css |
| K58 | Zeile beim Drüberfahren | in `.area` und `.srv` eingebaut |
| K59 | Seitenwechsel | neue Seite `b-page-in`, zurück `b-page-in--back`, alte `b-page-out` |
| K60 | Logo wackelt | `b-wiggle` |
| K61 | Neue Log-Zeile | `b-log`, `b-log__line.is-new` |
| K62 | Zahl-Taste | Zeile kurz `.is-flash`, dann öffnen |
| K63 | Update da | Logo-SVG `b-logo has-update` mit `b-logo__dot` / `b-logo__ring` |

## Daten → Aussehen (aus /api/servers)
| Daten | Anzeige |
|---|---|
| `running=false` | Pille neutral „Aus“ (hohler Punkt) · Knopf „Starten“ primär |
| `running && !ready` | Pille info „Startet …“ (Spinner) · Stop gesperrt |
| `ready` | Pille ok „Läuft“ (pulsierender Punkt) · Knopf „Stop“ sekundär |
| `git.up_to_date` | Pille ok „Aktuell“ |
| `git.behind > 0` | Pille warn „N hinter“ + Chip „local → remote“ + Knopf „Update“ primär mit Hinweis-Punkt; Zähler „Update“ links |
| Update läuft | Pille info „Update läuft“ + Schritt-Text + Balken unten an der Zeile (25/50/75/100 %) |
| `git.error` | Pille err „Git nicht erreichbar“ |
| `expose=tailscale` | Chip mit `public_url` (Mitte gekürzt) · beim Aufbau Pille info „Tunnel baut auf“ |
| `expose=none` | Pille neutral „Nur lokal“ |
| Passwort | **nie anzeigen** (nur einmal im Formular K27 beim Anlegen) |

## Regeln
1. Farben, Schriften, Radien, Abstände, Tempo **nur über `var(--…)`** aus `tokens.css`. Keine eigenen Hex-Werte im App-Code.
2. Blauer Text auf hellem Grund immer `--accent-text` (#2152E6), nie `--accent`.
3. Keine Schriften oder Icons von CDNs – die App muss offline laufen.
4. Alles Klickbare ist `<a>` oder `<button>`, mit sichtbarem Fokus. Icon-Knöpfe immer mit `aria-label`.
5. Amber (`--amber`) nur im Logo und für „Update verfügbar“ / Hinweise.
6. Der Sticker-Knopf (K06) höchstens **einmal pro Seite** für die Haupt-Aktion.
7. Bewegung: Standard `--dur-2` + `--ease-out`; Seiten `--dur-4` + `--ease-io`; Schalter/Häkchen `--ease-spring`. „Bewegung reduzieren“ im System schaltet alles ab (steht schon in components.css).
8. Gefährliches (Stoppen, Löschen) immer mit Dialog K50/K51; Löschen erst nach Eintippen des Namens.

## Dateien
```
design/
  DESIGN.md              ← diese Datei
  FRAGEN.md              ← Fragen/Wünsche zwischen Bau- und Design-Claude
  tokens.css             ← Farben, Schriften, Abstände, Tempo (+ @font-face)
  components.css         ← alle Bausteine K01–K63 + Seiten-Layouts
  fonts/                 ← Sora, IBM Plex Sans, IBM Plex Mono (woff2) + Lizenzen
  logo/                  ← bridge-bildmarke.svg, bridge-wortmarke.svg, bridge-app-icon.svg
  screens/hosting.html   ← H01 erste Seite: alle Server
  screens/start.html     ← Startbildschirm eines Servers (09)
  screens/kommt-noch.html← Platzhalter für Bereiche ohne Daten (K54)
  screens/ui-kit.html    ← alle Bausteine mit Markup zum Kopieren
```

## Als Nächstes (Design)
- Echte Bereichs-Seiten: Übersicht, Vertraute Server, Backup, Einstellungen.
