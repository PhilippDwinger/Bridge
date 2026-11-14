# 13 – Vorlagen: Websites zum Einstellen (Phase 9)

Stand 14.11.2026 – gebaut (BridgeControll + Knoten). Paddy (13.11.): „Viele Vorlagen, die man einstellen kann, und dann hostet der eigene PC das. Ich will
Bridge auf vielen Geräten nutzen und Freunde auch, die gar nicht programmieren können. Und es soll Design-Plugins
geben.“ Entscheidung: ADR 0031.

## 1. Ziel
In BridgeControll **„Website aus Vorlage“**: eine Vorlage wählen (Gästebuch, Umfrage, Termine, Visitenkarte …), ein
paar Felder ausfüllen, ein Design wählen, „Veröffentlichen“ – ohne Ordner, ohne Code. Der eigene Owner-Knoten hostet
die Website (wie jede Website, docs/07); Bridge Login und gespeicherte Einträge funktionieren ohne Einrichtung.
„Bearbeiten“ ändert die Einstellungen später (neue Version, gleiche Adresse).

## 2. Eine Vorlage
- Liegt in BridgeControll (`apps/bridgecontroll/templates/<id>/`): `template.json` (Name, Beschreibung, `records`
  ja/nein, Felder) und `app.js`, optional weitere Dateien. Gemeinsam für alle: `index.html`, `base.css` (Aufbau, nur
  mit den Design-Variablen), `bridge.js` (Hilfen: Einstellungen laden, Text sicher einsetzen, Einträge-API, Login-Zeile)
  und `login.js` (der Login-Helfer aus `sdk/javascript`, docs/11 §17). Alles ist ins Programm eingebaut; zur Laufzeit
  wird keine Datei gelesen.
- **Felder** (`template.json` → `fields`, höchstens 24): `text` (eine Zeile, `max` ≤ 200 Zeichen), `area` (mehrere
  Zeilen, `max` ≤ 4.000 Zeichen, ≤ 100 Zeilen), `list` (`min`–`max` ≤ 50 Zeilen, je ≤ `line_max` Zeichen; `line`:
  `text`, `link` = „Titel https://…“ → `{title, url}`, `date` = „JJJJ-MM-TT [HH:MM] Titel“ → `{date, time, title}`,
  `parts` = „Teil 1 | Teil 2 | …“ → genau `parts` (2–4) Texte, der erste muss da sein, der letzte nimmt den Rest),
  `choice` (eine von `options`), `switch` (an/aus), `date` (`JJJJ-MM-TT`, 1970–2200, ein echter Tag), `time`
  (`HH:MM`), `link`
  (`https://…`, ≤ 300 Zeichen, ohne Leer- und Anführungszeichen, `<`, `>`, `\`). Jedes Feld hat `key`, `label`,
  optional `hint`, `default` (muss selbst gültig sein), `required`. BridgeControll prüft jede Eingabe gegen das Feld –
  unbekannte Einstellungen werden abgelehnt.
- Die Einstellungen landen als **`config.json`** in der Website; die Seite liest sie und setzt Texte nur mit
  `textContent` ein (nie als HTML). So kann eine Eingabe keine Seite kaputt oder gefährlich machen.
- Zusammengesetzt wird die Website in einem kurzlebigen Ordner `<Owner-Knoten>/templates/build-<zufall>/` (Dateien
  + `config.json` + `design.css` + bei `records` die Markierung `server.records`), dann wie „Website hochladen“
  veröffentlicht (gleiche Prüfungen, gleicher Weg ins Netz) und der Ordner gelöscht. BridgeControll merkt sich Vorlage,
  Design und die Eingaben in `<Owner-Knoten>/templates/<app-id>.json` (für „Bearbeiten“; Löschen der Website löscht
  auch diese Datei).
- **API von BridgeControll**: `GET /api/templates` → Vorlagen mit Feldern, Designs mit Vorschau-Farben.
  `POST /api/nodes/<id>/template-publish` `{"template","settings","design"?,"name"|"app","description"?,"address"?}`
  → wie `site-publish` (mit `app`: neue Version mit neuen Einstellungen). `POST /api/nodes/<id>/template-load`
  `{"app"}` → die gespeicherten Einstellungen. Im Dashboard tragen die eigenen App-Schlüssel `template` (oder `null`):
  Vorlagen-Websites haben „Bearbeiten“ statt „Neue Version“.

## 3. Designs (und später Design-Plugins)
- Jede Vorlage nutzt nur CSS-Variablen (`--bg`, `--fg`, `--muted`, `--accent`, `--on-accent`, `--card`, `--line`,
  `--radius`, `--font`, `--font-head`); ein **Design** ist eine CSS-Datei, die sie setzt (`design.css`). Eingebaut:
  „Hell“, „Dunkel“, „Bunt“ (nur Systemschriften – eine Website lädt nichts von außen).
- **Design-Plugins** (später, Paddy): ein Paket mit genau so einer `design.css` (und erlaubten Schriften/Bildern), lokal
  in BridgeControll installiert; bei einer Vorlage wählbar wie die eingebauten. Die Schnittstelle (Variablen, Klassen
  `.b-card`, `.b-btn`, `.b-list`) ist dafür jetzt schon fest.

## 4. Eingebauter Server-Baustein `records`
Gästebuch, Umfrage und Anmeldungen brauchen gespeicherte Einträge. Statt Server-Code je Vorlage (WebAssembly) gibt es
einen **eingebauten** Baustein im Knoten: App-Manifest `"server": "builtin:records"` (statt einer `.wasm`-Datei;
ältere Knoten lehnen solche Versionen ab und hosten sie nicht – fail closed). Er nutzt das Ereignis-Log der App
(docs/09 §13): Einträge werden bei allen Hosts der App gleich.
- `POST /app/<id>/api/add` `{"c": <sammlung>, "f": {feld: wert}}` → `{"id","t"}`. `api/list` `{"c", "limit" ≤ 100,
  "before"?, "mine"?}` → `{"records": [{"id","t","u","n","f"}…] (neueste zuerst), "total"}` (`mine: true`: nur die
  eigenen, braucht Login). `api/remove` `{"c","id"}` (nur eigene Einträge). `api/me` → `{"user","name"}` oder
  `{"user": null}`. `api/count` `{"c","by"}` → `{"counts": {wert: anzahl}, "total", "mine"}` (wie viele Einträge
  welchen Wert im Feld `by` haben, höchstens 100 Werte; `mine`: der eigene Wert); `api/counts` `{"cs": [≤ 32
  Sammlungen], "by"}` → dasselbe je Sammlung in einem Aufruf (Termine).
- **Sammlungen** `<art>-<name>` (`name`: `a-z 0-9 -`, 1–32): `pub-…` jeder darf schreiben (angemeldet: mit Namen),
  `user-…` nur Angemeldete, `vote-…` nur Angemeldete und **je Nutzer zählt nur der neueste** Eintrag (Umfragen,
  „Ich komme“).
- **Felder**: ein Objekt mit 1–16 Schlüsseln `[a-z][a-z0-9_]{0,31}`, Werte Text (≤ 1.000 Zeichen, keine
  Steuerzeichen außer Zeilenumbruch), ganze Zahl oder ja/nein; ein Eintrag ≤ 4 KiB. `u` ist die Nutzer-ID nur für
  diese App (docs/11 §9.2), `n` der Anzeigename, `t` die Zeit des Hosts.
- Grenzen wie beim Server-Code: höchstens 10.000 Einträge je Host und App, 50.000 je App; gleiche Aufruf-Begrenzung.
  Eine Seite liest höchstens die neuesten 5.000 Einträge einer App.

## 5. Die ersten Vorlagen
| Vorlage | Einstellungen | Server |
|---|---|---|
| **Visitenkarte** | Name, Untertitel, Text, Links (Zeilen „Titel https://…“) | – |
| **Gästebuch** | Titel, Begrüßung, nur mit Login ja/nein (Standard: ja) | `user-eintraege` / `pub-eintraege` |
| **Umfrage** | Frage, Erklärung, 2–8 Antworten, Ergebnis vor dem Abstimmen zeigen ja/nein | `vote-s<kennung>` (neue Frage oder neue Antworten → neue Kennung, die Umfrage beginnt neu) |
| **Termine** | Titel, Text, Termine (Zeilen „JJJJ-MM-TT [HH:MM] Titel“), „Ich komme“ ja/nein | `vote-t<datum><zeit>` je Termin („ja“/„nein“; ein neuer Titel behält die Zusagen) |
| **Anmeldung** | Titel, Datum, Uhrzeit, Ort, Text, Nachricht erlauben ja/nein | `vote-anmeldung` (`kommt` ja/nein, `personen` 1–10, `nachricht`; ändern und absagen möglich) |
| **Ideen sammeln** | Titel, Erklärung | `user-ideen`, ein Herz je Nutzer und Idee in `vote-i<id>` (die neuesten 30, die meisten Herzen oben) |
| **Countdown** | Worauf, Datum, Uhrzeit, Text, Text „so weit“ | – (zählt mit der Uhr des Besuchers) |
| **Rezept** | Name, Text, Menge, Dauer, Zutaten (Zeilen), Schritte (Zeilen) | – |
| **Wunschliste** | Titel, Text, Wünsche (Zeilen „Wunsch \| Link“) | `vote-w<kennung des wunsches>` („ja“ = ich schenke das, „nein“ = doch nicht) |
| **Pinnwand** | Titel, Text, nur mit Login ja/nein (Standard: ja) | `user-zettel` / `pub-zettel` (`text`, `farbe` 0–3; die neuesten 60) |
| **Fragen & Antworten** | Titel, Einleitung, Fragen (Zeilen „Frage \| Antwort“), Link „Noch Fragen?“ | – |
| **Speisekarte & Preise** | Titel, Text, Einträge (Zeilen „Name \| Preis \| Beschreibung“, ohne „\|“ = Überschrift), Hinweis | – |
| **Infoseite** | Name, Untertitel, Abschnitte (Zeilen „Überschrift \| Text“), Kontakt, Kontakt-Link | – |

Angemeldet wird man nur im Bridge-Rahmen (`/web/<name>/`, docs/11 §9.4) – also über die Adresse der Website. Wer die
Seite direkt öffnet (`/app/<id>/`, z. B. „Ansehen“ auf dem eigenen PC), sieht sie ohne Login und bekommt den Hinweis,
die Adresse zu nutzen.

## 6. Moderation und Grenzen
- Wer Einträge schreiben darf, bestimmen die Sammlungsarten. **Einträge anderer löschen** (Spam, Beleidigungen): in
  BridgeControll bei der Website **„Einträge“** – die neuesten Einträge aller Sammlungen, je „Löschen“.
- Weg dafür: `POST /v4/admin/app-entries` `{"app","before"?}` → `{"entries": [{"c","id","t","u","n","f"}], "total",
  "next"}` (höchstens 100) und `POST /v4/admin/app-entry-remove` `{"app","c","id"}` – beide als signierte
  Admin-Anfrage (Recht `bans` oder `seals`, wie Meldungen) an einen Host der App. Der Host hängt ein Ereignis
  `{"k":"mod","c","id"}` an das Log der App; jeder Host wendet es an (ein moderierter Eintrag zählt nirgends mehr; bei
  `vote-` zählt auch keine ältere Stimme dieses Nutzers, bis er neu abstimmt). Die App selbst (`api/…`) kann kein
  `mod` schreiben. Hosts einer App sind für ihr Ereignis-Log ohnehin vertrauenswürdig (docs/09 §13) – ein Host kann
  also moderieren, aber nichts, was er nicht schon könnte.
- BridgeControll: `POST /api/nodes/<id>/site-entries` `{"app","before"?}`, `site-entry-remove` `{"app","c","id"}`;
  App-Schlüssel im Dashboard tragen `records` (ja/nein).
- Zeiten kommen vom Host, der den Eintrag angenommen hat.

## 7. Abnahme
- Kern: `builtin:records` im Manifest (sonst nur `.wasm`-Dateien), Angriffe (unbekannter Baustein).
- Knoten (e2e): hinzufügen/lesen/entfernen, Sammlungsarten (ohne Login refused bei `user-`/`vote-`, neueste Stimme
  zählt), fremde Einträge nicht löschbar, Felder-Angriffe (zu groß, falsche Schlüssel, verschachtelt), zweiter Host
  bekommt die Einträge.
- BridgeControll: Vorlagen-Liste, Eingaben geprüft (Angriffe: unbekannte Einstellungen, falsche Arten, zu lang,
  Steuerzeichen, Links ohne https oder mit Ausbruch aus dem Attribut, unmögliche Daten), Veröffentlichen (Ordner +
  `config.json`, kein Build-Ordner bleibt), Bearbeiten (neue Version, Einträge bleiben), Löschen vergisst die
  Einstellungen, Moderation (Eintrag weg für Besucher), Rauchtest-Bilder 42–57 (Seiten laufen ohne Skriptfehler,
  ein Eintrag ohne Login, Einträge-Dialog).
- Kein Vorlagen-Code setzt etwas als HTML ein (Test sucht `innerHTML`, `outerHTML`, `insertAdjacentHTML`,
  `document.write`, `eval(`).
