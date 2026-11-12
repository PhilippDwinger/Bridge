# 08 – Namen, Web, Browser und Missbrauchsschutz (Phase 4)

*Stand 12.11.2026: gebaut, auch in BridgeControll (Browser, Namen, Meldungen: §12; Entscheidungen beim Bau: ADR 0018,
ADR 0017 Nachtrag 2; Befunde der Prüfung 9: ADR 0018 Nachtrag, ADR 0017 Nachtrag 3; Grenzen in §11). Paddy hat die
Details mit „mach einfach weiter“ an Claude übergeben – Freigabe durch Paddy steht aus.*

Baut auf 06 (Netz, Log, Zustand) und 07 (Apps, Blobs, Ausliefern) auf. Ziel (05, Phase 4): **`shop.meinnetz` im
Browser öffnet die Website eines anderen PCs; die Suche nach „shop“ liefert eine Liste; ein gefälschter
Namens-Eintrag wird abgewiesen.** Dazu – Paddys Vorgabe vom 10.11. – kämpft Bridge selbst gegen illegale Inhalte,
Phishing und nicht gekennzeichnete 18+-Inhalte, ohne Nachrichten zu lesen.

## 1. Grundsätze (ADR 0018)
- **Paddy liefert Software, er betreibt kein öffentliches Netz.** Wer ein Netz erstellt, ist dessen **Betreiber** und
  für sein Netz verantwortlich – auch für einen erreichbaren Meldeweg (`contact` im Manifest, §2). Bridge hat keinen
  zentralen Betreiber, keinen zentralen Server und keinen Generalschlüssel. Regeln für alle: `NUTZUNGSREGELN.md`.
- **Nachrichten bleiben Ende-zu-Ende verschlüsselt und werden nie durchsucht** (Z1). Bridge handelt nur dort, wo
  etwas **öffentlich** ist: Namen, Apps/Websites, Schlagworte, Beschreibungen.
- **Werkzeuge für Betreiber**, keine Automatik gegen Personen: Namensregeln mit Stufen und Kontingenten,
  Verwechslungs-Schutz, reservierte Wörter, Kennzeichnung (`label`), Meldungen (`report`), Not-Aus (`ban`, `revoke`).
  Eine Meldung allein löst nie etwas aus (§6).
- **Zero Trust auch im Browser**: Wer eine App über einen Namen öffnet, lädt sie über den **eigenen** Knoten, der
  alles selbst prüft (§8) – nie über einen fremden Knoten, dem man glauben müsste.

## 2. Manifest: neue optionale Felder
Alle Felder sind optional; fehlen sie, bleiben sie weg (ältere Manifeste behalten Bytes und Hash). Sind sie da, gilt
streng wie überall: genau diese Felder, feste Typen und Grenzen, sonst ist das Manifest ungültig.

| Feld | Form | Standard ohne Feld |
|---|---|---|
| `short` | Kurzname des Netzes für Adressen: `[a-z0-9-]`, 2–24 Zeichen, nicht mit `-` beginnend/endend, kein `--` | keiner – Adressen zeigen dann nur den Namen (§3) |
| `contact` | Meldeweg des Betreibers (E-Mail, Web-Adresse oder Bridge-ID als Text), 1–200 Zeichen, keine Steuerzeichen | keiner – das Netz gilt als **„ohne Meldeweg“** (Warnung `no_contact` bei jeder Auflösung, §7) |
| `names` | `{"min_level":0-3,"quota":[q0,q1,q2,q3],"reserved":["…"]}` – alle drei Felder Pflicht | `min_level` 1, `quota` [0, 3, 20, 100], `reserved` [] |
| `adult` | `"allowed"` oder `"forbidden"` | `"forbidden"` |
| `blocklists` | 0–8 verschiedene Identitäts-IDs (Herausgeber von Sperrlisten, §9) | [] |

- `names.min_level`: Stufe, die ein Inhaber zum Anmelden eines Namens braucht (02 §6: Stufe 1 „Geprüft“ darf Namen
  anmelden). `names.quota[s]`: so viele aktive Namen darf ein Inhaber der Stufe `s` haben (je 0–1.000).
  `names.reserved`: bis zu 64 zusätzliche reservierte Wörter (Namens-Syntax, §3), zur festen Liste dazu.
- `adult: "forbidden"` ist der Standard (fail closed, ADR 0018): Wer 18+-Inhalte erlaubt, entscheidet das als
  Betreiber bewusst und ist für Altersprüfungen nach seinem Recht verantwortlich (z. B. JMStV in Deutschland) – Bridge
  prüft kein Alter, es kennzeichnet nur.
- **Neue Netze**: `bridge-node net create` verlangt `--contact` und setzt `short` (`--short`, sonst aus dem Namen
  abgeleitet) und `adult` (`--adult`, Standard `forbidden`). Ältere Netze ohne `contact` bleiben gültig, werden aber
  überall als „ohne Meldeweg“ markiert; der Betreiber ergänzt das Feld mit einer neuen Manifest-Version.
- `GET /v4/names/info` zeigt diese Regeln (§7).

## 3. Namen (Aussage `name`, im Log)
Ein Name braucht eine Reihenfolge (wer zuerst kommt, bekommt ihn) – deshalb steht er im **Transparenz-Log** wie
Siegel und Sperren und wird beim Abspielen deterministisch geprüft (06 §6).

```json
{"name":"shop","kind":"app","target":"<app-id>","owner":"<mitglied-id>","owner_card":<karte des inhabers>,
 "card":<karte des app-schlüssels>,"description":"Mein Laden","tags":["laden","kleidung"],"category":"general",
 "hosts":["<knoten-id>"]}
```
- **Syntax des Namens**: `[a-z0-9-]`, 2–40 Zeichen, nicht mit `-` beginnend oder endend, kein `--`, und **keine
  gültige ID** (32 Zeichen Base32) – so ist eine Eingabe immer eindeutig Name oder ID. Nur ASCII: keine
  Homoglyphen aus anderen Schriften.
- `kind`: `app` (Ziel = App-ID), `node` (Ziel = Knoten-ID, z. B. ein Empfänger), `member` (Ziel = Mitglied, z. B. zum
  Anschreiben).
- `description` 0–200 Zeichen (keine Steuerzeichen), `tags` 0–8 verschiedene Schlagworte (Syntax wie Namen, 2–24
  Zeichen), `category` `general` oder `adult` (Selbstauskunft, §5).
- `hosts` (nur bei `app`, optional, 1–8 Knoten-IDs): **Hinweis**, wo die App zu finden ist. Nie vertraut – der
  Leser prüft die App-Version selbst (§8); er spart nur die Suche.
- **Wer unterschreibt** (so kennt der Zustand die Inhaberschaft ohne App-Manifest im Log):
  - `app`: genau zwei Unterzeichner (`sigs`) – der **App-Schlüssel** (`target`) und der **Inhaber** (`owner`, ≠
    `target`); `card` = Karte des App-Schlüssels (Rolle `app`, ID = `target`), `owner_card` = Karte des Inhabers (Rolle
    `client` oder `node`). Wer den App-Schlüssel hat, ist der Owner der App (07 §2) – der Name kann also nur von ihm
    kommen. Beim Auflösen prüft der Knoten zusätzlich, dass das aktuelle App-Manifest denselben Owner nennt (§7).
  - `node`: genau ein Unterzeichner, `owner` = `target` = der Knoten, `owner_card` Rolle `node`, kein `card`.
  - `member`: genau ein Unterzeichner, `owner` = `target` = das Mitglied, `owner_card` Rolle `client`, kein `card`.
  - Die Karten reisen im Body mit (wie im App-Manifest): Mitglieder der Stufe 0/1 haben keine Karte im Log.
- **Regeln beim Abspielen** (Prüfzeit t, 06 §6; sonst wird der Eintrag übersprungen bzw. beim Log-Führer abgelehnt):
  1. Strenger Body, Syntax, `exp − iat` ≤ 1 Jahr, Unterzeichner wie oben, Signaturen mit den Karten im Body.
  2. Inhaber (und Ziel) darf etwas bekommen (06 §6: nicht die Netz-ID, nicht kaskadiert, kein Identitäts-Widerruf für
     ältere Aussagen, nicht gesperrt).
  3. Inhaber hat zur Prüfzeit eine **Stufe ≥ `names.min_level`** (Mitglied oder gesiegelt).
  4. `category: "adult"` in einem Netz mit `adult: "forbidden"` → abgelehnt.
  5. **Reservierte Wörter** (§4) im Namen **oder in einem Schlagwort** nur mit Stufe ≥ 3.
  6. **Wer zuerst kommt**: Gilt der Name schon (nicht abgelaufen) für einen **anderen** Inhaber → abgelehnt. Derselbe
     Inhaber **verlängert** oder ändert ihn (Ziel, Beschreibung …) mit einer neueren Aussage (größeres `iat`); ist der
     alte Eintrag abgelaufen, darf jeder den Namen nehmen. Jede Aussage muss neuer sein als die geltende **und** als
     jede frühere Aussage dieses Namens, die nicht mehr gilt (Prüfung 9: ersetzte und widerrufene Namens-Aussagen merkt
     der Zustand als einen „Boden“ `(iat, hash)` je Name, bis jede ältere Aussage abgelaufen ist – nicht in der Tabelle
     der Widerrufe, die Verlängerungen sonst füllen würden; höchstens 200.000 Böden, ist die Tabelle voll, gelten
     Namens-Aussagen bis zum neuesten verworfenen Boden als zu alt – fail closed).
  7. **Ändern höchstens einmal am Tag** (Prüfung 9): Derselbe Inhaber ändert oder verlängert einen geltenden Namen erst
     einen Tag (Abspielzeit) nach der letzten Aussage – außer in den letzten 30 Tagen vor dem Ablauf, dann jederzeit.
  8. **Verwechslungs-Schutz** (§4): Hat ein anderer gültiger Name dasselbe Skelett → abgelehnt (`sh0p` neben `shop`).
  9. **Kontingent**: aktive Namen des Inhabers < `names.quota[stufe]` (Verlängern zählt nicht neu); höchstens 100.000
     Namen im Netz. Dazu **Namens-Einträge je Inhaber und Tag** (Prüfung 9): höchstens `names.quota[stufe] + 2` (neue
     Namen, Verlängerungen und Änderungen zusammen, Tag nach Abspielzeit).
  10. **Eigener Topf** (Prüfung 9): Namen – und Widerrufe von Namen durch ihren Inhaber oder App-Schlüssel, die kein Admin
     sind – zählen in einem eigenen Topf von `log_entries_per_day` je Tag (gleich groß wie der der Admins und Empfänger,
     wie bei Wächtern, 06 §11.2). Namen können das Log für Beitritte, Siegel und Kennzeichnungen nie aufbrauchen; Admins
     widerrufen Namen aus ihrem Topf (mit 10 % Reserve).
- **Ende eines Namens**: Ablauf (`exp`), `revoke` mit `statement` = Hash der Namens-Aussage – durch den Inhaber
  (oder den App-Schlüssel, beide sind Unterzeichner; die Karte des App-Schlüssels kommt aus dem Namen, seit Prüfung 9),
  durch einen Admin mit Recht `seals` oder den Hauptschlüssel –,
  `revoke` mit `identity` des Inhabers oder Ziels (entfernt alle seine Namen), `cascade` (alles, was er unterschrieben
  hat). Danach ist der Name frei.
- **Adresse**: `<name>.<short>` (z. B. `shop.meinnetz`). Die Adresse gilt nur in den Netzen, die der Nutzer kennt;
  Netze unterscheidet ihre **Netz-ID** – zwei Netze mit gleichem `short` zeigt BridgeControll mit Netz-Namen und
  ID-Anfang zur Auswahl. Ohne `short` ist die Adresse nur der Name (im gewählten Netz).

## 4. Skelett und reservierte Wörter (deterministisch)
- **Skelett** eines Namens (`bridge_net::names::skeleton`): Bindestriche fallen weg, dann wird Zeichen für Zeichen
  ersetzt: `0→o`, `1→l`, `i→l`, `2→z`, `3→e`, `4→a`, `5→s`, `6→b`, `7→t`, `8→b`, `9→g`, und – zerlegt statt
  zusammengefasst, damit die Reihenfolge egal ist – `m→rn`, `w→vv`, `d→cl`. So haben `shop`, `sh0p`, `s-hop`
  dasselbe Skelett, ebenso `paypal`/`paypa1`/`paypai`, `modem`/`rnodern`, `wallet`/`vvallet`, `bank`/`8ank`,
  `cloud`/`doud`.
- **Reserviert** ist ein Name, dessen Skelett oder das Skelett eines seiner **Schlagworte** das Skelett eines
  reservierten Wortes **enthält** (Schlagworte seit Prüfung 9). Feste Liste: `bank`, `login`, `paypal`, `admin`,
  `support`, `official`, `secure`, `wallet`, `verify`, `update`, `account`, `bridge`, `password`, `passwort`, `konto` –
  dazu `names.reserved` aus dem Manifest. Reservierte Namen meldet nur ein Inhaber mit Stufe ≥ 3 an (ein Owner oder ein
  von Admins im Mehr-Augen-Verfahren versiegeltes Mitglied). Ändert eine neue Manifest-Version die reservierten Wörter,
  gilt die neue Liste für alle Namen (beim Abspielen neu bestimmt).
- **Beschreibungen** dürfen reservierte Wörter enthalten (sonst wäre „Wir bieten Support“ verboten), aber ein Wort der
  Beschreibung, das eines enthält, **zählt für die Suche nicht** bei Inhabern unter Stufe 3 (Rang 4, §7) – ein
  `PayPal Login hier` eines neuen Mitglieds wird über „paypal“ nicht gefunden (Prüfung 9).
- Bewusster Preis: Teilwort-Treffer erwischen auch harmlose Namen (`badminton` enthält `admin`, `sandbank` enthält
  `bank`). Wer so einen Namen will, wählt einen anderen oder fragt einen Admin (Stufe 3). Lieber zu streng als ein
  `paypal-login` von einem neuen Mitglied.
- Grenzen des Skeletts: Es erkennt nur die Liste oben (kein vollständiges Unicode-Verwechslungs-Verzeichnis; Namen sind
  ohnehin nur ASCII) – `rn`/`m` u. Ä. ja, `u`/`v` oder `h`/`n` nicht.

## 5. Kennzeichnung (Aussage `label`, im Log)
```json
{"target":"<name oder id>","category":"adult|general","reason":"…"}
```
- `target` ist ein Name (Syntax §3) oder eine ID (App, Knoten, Mitglied) – eindeutig, weil Namen keine IDs sein
  dürfen. `reason` 0–200 Zeichen.
- Ausstellen: **ein** Admin mit Recht **`seals`** oder der Hauptschlüssel (eine Kennzeichnung ist eine Aussage über
  Vertrauenswürdigkeit wie ein Siegel). Eine neuere Kennzeichnung desselben Ziels ersetzt die ältere; `revoke` wie bei
  Siegeln (`seals`, Unterzeichner, Hauptschlüssel). Höchstens 100.000 im Netz.
- **Wirkung** (wirksame Kategorie eines Namens, seit Prüfung 9): **18+ von irgendeiner Seite gewinnt** – `adult`, wenn
  die Selbstauskunft, die Kennzeichnung des Namens oder die Kennzeichnung seines Ziels `adult` sagt, sonst `general`.
  Eine Kennzeichnung `general` macht also nichts harmloser, was eine andere Seite als 18+ nennt; sie hebt nur eine
  ältere `adult`-Kennzeichnung desselben Ziels auf (neuere ersetzt ältere). Wer 18+ fälschlich angibt, ändert seine
  Selbstauskunft mit einer neuen Namens-Aussage.
- **Eine Kennzeichnung eines Namens gilt für dessen Inhaber** (Prüfung 9): Beim Abspielen merkt der Zustand, wem der
  Name gerade gehört; geht er an einen anderen Inhaber (abgelaufen oder widerrufen und neu angemeldet), gilt sie für den
  neuen nicht. Eine Kennzeichnung eines Namens, den gerade niemand hält, gilt für jeden späteren Inhaber.
- `adult` in einem Netz mit `adult: "forbidden"`:
  - **Namen** lösen nicht mehr auf und erscheinen in keiner Suche.
  - **Apps**: Ist die **App-ID** als `adult` gekennzeichnet, hören alle Hosts auf, sie auszuliefern (wie bei einer
    Sperre, 07 §5 „Aufhören“), und kein Leser lädt sie (§8). Ein Name allein als `adult` gekennzeichnet versteckt nur den
    Namen. Danach veröffentlicht der Owner eine neue Version (der Rang der alten ist gemerkt, 07 §3).
- In Netzen mit `adult: "allowed"` bleiben `adult`-Namen auflösbar, aber die **sichere Suche** (§7) zeigt sie nie.

## 6. Meldungen (`report`, nicht im Log)
Meldungen enthalten, **wer** etwas meldet – das gehört nicht in ein öffentliches Log (Datenschutz). Sie bleiben bei den
Knoten und gehen an den Log-Führer (meist der Owner-Knoten), damit Admins alle an einer Stelle sehen.
- **Abgeben**: `POST /v4/report` – Sitzung (`Authorization: Bearer`) **und** signierte Anfrage `rq` des angemeldeten
  Mitglieds (`op:"report"`, `iss` = Sitzung, `aud` = dieser Empfänger),
  `body:{"target":"<name oder id>","reason":"illegal|phishing|adult_unlabeled|spam|other","sealed":<umschlag>|null}`.
  **Der Text ist versiegelt** (Prüfung 9, Z1): `sealed` ist ein Umschlag (04 §4) des Mitglieds an einen **Log-Führer**
  des Netzes (in der Regel den ersten, seine Karte aus dem Log), Art `msg`, Inhalt der Text (0–500 Zeichen,
  Zeilenumbruch erlaubt), höchstens 2.016 Byte Geheimtext; `null` ohne Text. Ein Klartext-Feld `text` wird abgelehnt.
  So liest der Empfänger, der die Meldung annimmt und weiterreicht, den Text nie; Ziel und Grund bleiben lesbar (er
  braucht sie für seine Grenzen). Der Empfänger prüft: Umschlag dieses Netzes, `from` = Mitglied, `to` ∈ Log-Führer der
  geltenden Regeln, gültig, Signatur mit der Karte des Mitglieds. Antwort `{"ok":true,"id":"<id>","duplicate":bool,
  "forwarded":bool}`. Prüfung billig zuerst: Sitzung → Größe/Form → `rq` frisch und für diesen Knoten → `iss` =
  Sitzung → Signatur → Nonce einmalig (`REPLAY`) → Body streng → Umschlag.
- **Grenzen**: je Mitglied höchstens **10 Meldungen in 24 Stunden** (je Knoten gezählt; darüber `429 RATE_LIMITED`);
  eine offene Meldung desselben Mitglieds zum selben Ziel aus den letzten 24 Stunden → `duplicate: true`, nichts Neues;
  höchstens **10.000 Meldungen** je Knoten – ist die Tabelle voll, geht die älteste erledigte, sonst (Prüfung 9) die
  älteste offene Meldung der **niedrigsten Stufe unter der des neuen Melders** (Stufe beim Eingang gemerkt; Stufe 0
  zuerst), sonst `429 QUOTA_EXCEEDED`. Neue Mitglieder können so die Meldungen anderer nicht verdrängen. Offene
  Meldungen von Mitgliedern der Stufe 0 werden nach 30 Tagen gelöscht, erledigte nach 90 Tagen.
- **ID** einer Meldung = Base64url(SHA-256 der kanonischen Bytes der signierten Anfrage) – dieselbe beim Empfänger und
  beim Log-Führer.
- **Weitergabe** (Knoten → Knoten): Ist der Empfänger nicht selbst der aktive Log-Führer, reicht er jede neue Meldung
  weiter: `POST /v4/node/report` mit `rq` des Empfängers (`op:"report"`, `body:{"report":<die signierte Anfrage des
  Mitglieds>,"card":<karte des mitglieds>}`). Der Log-Führer prüft: Aufrufer ist Empfänger, `rq` frisch, für ihn,
  einmalig, Signatur; die innere Anfrage hat `op:"report"`, `aud` = der Aufrufer, `iss` = ID der Karte (Rolle `client`
  oder `node`), gültige Signatur, `iat` höchstens 7 Tage alt, das Mitglied ist Mitglied, der Umschlag wie beim Empfänger
  (ohne seine Zeit – es zählt das Alter der Meldung). So kann kein Empfänger
  Meldungen im Namen eines Mitglieds erfinden. Gleiche Grenzen wie oben. Der Empfänger versucht es je Takt (Standard
  30 s) mit bis zu 16 Meldungen, bis der Log-Führer sie annimmt oder sie 7 Tage alt sind.
- **Lesen und erledigen** (Admins): `POST /v4/admin/reports` – `rq` eines Admins mit Recht `bans` **oder** `seals`
  (oder des Hauptschlüssels), `op:"reports"`, `body:{"status":"open|done|all","max":1-100,"before":<ms>?}` →
  `{"reports":[{"id","reporter","target","reason","text","sealed_to","level","received","status","via","handled_by",
  "handled_at"}],"next":<ms>|null}` (neueste zuerst; `via` = der Empfänger, bei dem sie abgegeben wurde). Der Knoten
  öffnet einen an ihn versiegelten Text selbst (`text`); ist er an einen anderen Log-Führer versiegelt, ist `text`
  `null` und `sealed_to` nennt ihn. `level` = Stufe des Melders beim Eingang. `POST /v4/admin/report` –
  `rq` `op:"report-status"`, `body:{"id","status":"done|open"}` → `{"ok":true}`. Nonce einmalig. Andere Knoten als der
  Log-Führer zeigen nur, was bei ihnen abgegeben wurde.
- **Keine Automatik**: Eine Meldung ändert nichts im Netz. Ein Admin entscheidet und handelt mit den bekannten
  Werkzeugen: `label`, `revoke` (Name, Siegel), `ban` (App-ID, Inhaber, Knoten).

## 7. Auflösen und Suchen (jeder Knoten eines Netzes, aus seinem eigenen Zustand)
Lese-Endpunkte ohne Anmeldung, mit einer **eigenen Grenze je Adresse** (Standard 5/s, kurz bis 20; `Limits::
names_per_address`) über der allgemeinen. Ein Knoten ohne Netz kennt sie nicht (`404`), einer, der sein Log noch lädt,
antwortet `503 UNAVAILABLE`.

| Endpunkt | Eingabe | Antwort |
|---|---|---|
| `GET /v4/names/info` | – | `{"net","name","short","contact","adult","names":{"min_level","quota","reserved"},"blocklists":[…]}` |
| `POST /v4/names/resolve` | `{"name":"shop"}` oder `{"name":"shop.meinnetz"}` | siehe unten; sonst `404 NOT_FOUND` |
| `POST /v4/names/search` | `{"q":"shop","safe":true,"max":20}` | `{"results":[<wie resolve, ohne app>],"more":bool}` |
| `POST /v4/names/list` | `{"owner":"<id>"}` | `{"names":[<wie resolve, ohne app>]}` (gültige Namen dieses Inhabers) |
| `POST /v4/names/submit` | eine `name`-Aussage (Inhaber = Sitzung) oder ein `revoke` eines eigenen Namens (`iss` = Sitzung) | `{"ok":true,"hash","index"}` |
| `POST /v4/names/blocklist` | `{"publisher":"<id>"}` | `{"statement":<blocklist>}` (die Liste, die der Knoten hält; sonst `404`) |
| `POST /v4/names/blocklist/update` | eine `blocklist`-Aussage (ohne Sitzung: die Signatur des Herausgebers ist der Beweis) | `{"taken":bool,"version"}` |

- **Auflösen** liefert nur, was gerade gilt: Name aktiv, Inhaber nicht gesperrt und mit Stufe ≥ `names.min_level`,
  Ziel nicht gesperrt, reservierter Name nur bei Inhaber-Stufe ≥ 3, wirksam `adult` nur bei `adult: "allowed"`. Alles
  andere: `404 NOT_FOUND` (kein Unterschied zwischen „gibt es nicht“ und „gesperrt“, 04 §9). Ein Suffix `.<short>`, das
  nicht das `short` dieses Netzes ist, ist `404` (anderes Netz).
- **Antwort** (alle Felder immer da, `null` wenn leer):
  ```json
  {"name":"shop","address":"shop.meinnetz","net":"<id>","kind":"app","target":"<id>","owner":"<id>",
   "description":"…","tags":["…"],"category":"general","declared":"general","expires":0,"statement":"<hash>",
   "card":<karte des ziels bei node/member, sonst null>,"card_verified":true|false|null,
   "safety":{"owner_level":2,"contact":true,"reserved":false,"labels":{"name":null,"target":null},
             "adult_policy":"forbidden","warnings":["…"]},
   "app":{"name","description","version","entry","owner_matches":true,"hosts":[{"id","urls":[…]}]} | null,
   "open":"/app/<app-id>/" | null}
  ```
  `warnings` (Codes, die Oberfläche übersetzt): `owner_level_low` (Inhaber unter Stufe 2), `no_contact` (Netz ohne
  Meldeweg), `adult` (wirksam 18+), `label_override` (Kennzeichnung weicht von der Selbstauskunft ab), `app_unknown`
  (App-Version hier nicht bekannt), `owner_mismatch` (das App-Manifest nennt einen anderen Owner als der Name – dann
  `open: null`), `card_unverified` (Prüfung 9: Knoten-Name eines Knotens ohne Siegel – `card` ist dann nur die eigene
  Karte des Knotens aus dem Namen, ihre Adressen hat niemand geprüft).
- **`card_verified`** (Prüfung 9): `true`, wenn `card` aus einem Siegel kommt (Knoten mit Siegel), `false` für die
  eigene Karte aus dem Namen (Knoten ohne Siegel, Mitglieder), `null` bei App-Namen.
- **`app`**: aus dem, was der Knoten über die App weiß (selbst gehostet oder im Leser-Speicher, §8). Nur für Aufrufer,
  die den Leser benutzen dürfen (§8), holt der Knoten die Version bei Bedarf selbst – so kann niemand aus dem Internet
  einen Knoten als Verstärker für Abfragen an andere Knoten benutzen. `open` ist der Pfad am **eigenen** Knoten.
- **Suche**: `q` 1–64 Zeichen (Kleinbuchstaben, ein `.<short>` dieses Netzes am Ende wird abgeschnitten), `max` 1–50
  (Standard 20), `safe` Standard `true`. Rang: 0 Name genau gleich, 1 Name beginnt mit `q` oder gleiches Skelett,
  2 Schlagwort gleich, 3 Name enthält `q` oder Schlagwort beginnt mit `q`, 4 ein Wort der Beschreibung beginnt mit `q`;
  bei Gleichstand höhere Inhaber-Stufe zuerst, dann der Name. Es zählen nur Namen, die auch auflösen würden. Rang 4
  zählt nicht für eine Beschreibung mit reserviertem Wort, wenn der Inhaber unter Stufe 3 ist (§4).
  **Sichere Suche** (`safe: true`) zeigt keine wirksam `adult`-Namen und keine Namen von Inhabern unter Stufe 2.
- **Begrenzte Arbeit** (Prüfung 9): Vorher prüfte jede Suche jeden Treffer vollständig (Regeln und Namen kopiert –
  380 ms bei 100.000 Namen, auf einem Arbeits-Thread unter der Sperre des Kerns, ohne Anmeldung auslösbar). Jetzt: ein
  Durchgang billiger Vergleiche über die Namen (ohne Speicher je Name; reservierte Wörter und die Wörter der
  Beschreibung beim Eintragen vorberechnet), dann die Stellung der Kandidaten Rang für Rang, im Rang nach Name –
  höchstens **2.000** Prüfungen (`MAX_SEARCH_CHECKS`), keine schlechteren Ränge mehr, sobald bessere mehr als `max`
  Treffer gaben; eine abgeschnittene Suche sagt `more: true`. Die Suche läuft auf einer Momentaufnahme des Zustands in
  einem eigenen (blockierenden) Thread – die Sperre des Kerns ist nur für das Kopieren des `Arc` gehalten, alle
  anderen Anfragen laufen weiter –, und höchstens **2 Suchen gleichzeitig** je Knoten, egal von wem (darüber sofort
  `429 RATE_LIMITED`, zusätzlich zur Grenze je Adresse). Ein Eintrag ins Log während einer Suche ändert eine Kopie des
  Zustands (gezählt in `state_copies`).
- **Eintragen über einen Empfänger** (`/v4/names/submit`, Sitzung nötig): Der Empfänger prüft die Aussage wie der
  Log-Führer (`validate_candidate`), reicht sie ihm weiter (`submit` als Empfänger) und wartet höchstens `join_wait`,
  bis sie bei ihm gilt. Die Kommandozeile (§10) gibt Aussagen direkt mit dem Admin-Schlüssel ab.

## 8. Leser (Browser über den eigenen Knoten)
Ein Knoten liefert `GET /app/<app-id>/…` auch für Apps, die er **nicht** hostet – als **Leser** für den Browser
seines Besitzers:
1. **Nur lokal** (`NodeConfig::reader`, Kommandozeile `--reader off|local|lan|tailnet`, Standard `local`): Die Anfrage
   kommt direkt von `127.0.0.1`/`::1` (nicht über einen vertrauten Proxy, keine Kopfzeile `X-Forwarded-For`,
   `Forwarded`, `X-Real-IP`), und `Host` ist `localhost`, `127.0.0.1` oder `[::1]` (mit Port) – das hält auch
   DNS-Rebinding ab und Anfragen, die über Tailscale Funnel hereinkommen. `lan` erlaubt zusätzlich das **Heimnetz**
   (10/8, 172.16/12, 192.168/16, IPv6-ULA fc00::/7 **ohne** Tailscales fd7a:115c:a1e0::/48, Link-Local), `tailnet`
   stattdessen das **eigene Tailnet** (100.64.0.0/10 und fd7a:115c:a1e0::/48 – dieselben Bereiche wie
   `--peer-addresses tailnet`, 06 §2), beide mit `Host` = eine IP-Adresse (Prüfung 9: vorher galt Tailscales IPv6 als
   Heimnetz, sein IPv4 nicht); `off` schaltet den Leser ab. Für alle anderen Aufrufer ist eine nicht gehostete App wie
   bisher `404` – **nie ein offener Proxy**.
   **Zugang nur für diesen PC** (Prüfung 9, `NodeConfig::reader_listen`, `--reader-listen 127.0.0.1:<port>`): ein
   zweiter Listener des Knotens, nur an eine Loopback-Adresse gebunden (eine andere lehnt der Start ab), der **keinem
   Proxy** vertraut und nur den Leser (`GET /app/…`, auch gehostete Apps) und die lesenden Namens-Endpunkte
   (`/v4/names/info|resolve|search|list`) bedient – alles andere `404`. Die Regeln oben gelten dort genauso (Loopback,
   lokaler `Host`, keine Weiterleitungs-Kopfzeile, Leser nicht `off`). So bedient ein Knoten hinter Tailscale Funnel
   (`--trust-proxy 127.0.0.1`), dessen Haupt-Port den eigenen Browser nicht von Anfragen aus dem Internet
   unterscheiden kann, den Browser seines Besitzers trotzdem. Gleiche Grenzen je Adresse wie der Haupt-Port.
2. **Version finden**: aus dem Leser-Speicher (höchstens 30 s alt), sonst bei den Hosts der letzten bekannten Version,
   den `hosts`-Hinweisen gültiger Namen der App und bis zu 16 Knoten mit `web`-Siegel aus dem Log (in einer je App
   festen, verteilten Reihenfolge), je `POST /v4/app/manifest`. **Geprüft wie ein Host** (07 §3): beide Signaturen,
   Owner Mitglied mit `apps.min_level`, App und Owner nicht gesperrt, App-ID nicht als `adult` gekennzeichnet in einem
   `forbidden`-Netz, mindestens ein gültiger Host. Die höchste gültige Version gewinnt. Ohne Erfolg: `404`, gemerkt für
   10 s.
3. **Dateien**: Teil für Teil von den gültigen Hosts der Version (`/v4/blob/hashes`, `/v4/blob/get`), die Hash-Liste
   gegen die Blob-ID geprüft, **jeder Teil gegen seinen Hash** – ein falscher Teil wird nie ausgeliefert; ein Host, der
   einen liefert, wird für diese Datei übersprungen, der Teil kommt vom nächsten. Ausgeliefert wird mit denselben Köpfen
   wie beim Host (Sandbox-CSP, `nosniff`, `Content-Type` aus dem Manifest, `ETag`), große Dateien als Strom.
4. **Speicher**: Teile und Hash-Listen in einem eigenen Speicher im RAM (LRU, Standard 64 MiB, höchstens 4.096 Teile;
   `ReaderConfig::cache_bytes`), getrennt von den Kontingenten des Hosts, nie festgehalten, nach Neustart leer;
   höchstens 256 App-Versionen.
5. Jede Anfrage prüft die Version erneut gegen den aktuellen Zustand (Sperre, Kennzeichnung, Ablauf) – ein Not-Aus
   wirkt beim Leser so schnell wie beim Host.

## 9. Sperrlisten (`blocklists`, gebaut 12.11.2026)
- Das Manifest-Feld `blocklists` (0–8 Herausgeber-IDs, §2) sagt, wessen Listen das Netz folgt; der Betreiber setzt es
  (`bridge-node net blocklists --set <id,…>|none`, Recht `rules`). Wer Herausgeber ist, entscheidet der Betreiber – was
  auf der Liste steht, der Herausgeber (z. B. eine Stelle, die Phishing-Seiten sammelt).
- **Aussage `blocklist`** (nicht im Log, wie `app`): Body `{"publisher","card","version","entries":[…]}`, signiert nur
  vom Herausgeber, dessen Karte im Body steckt (er braucht kein Siegel und keine Mitgliedschaft), an ein Netz gebunden
  (`net`), höchstens 1 Jahr gültig, höchstens 512 KiB. Einträge: `id:<id>` (App, Knoten, Mitglied – auch Inhaber eines
  Namens) oder `name:<skelett>` (das Verwechslungs-Skelett nach §4: `name:paypal` trifft auch `paypa1`); streng
  sortiert, ohne Doppelte, höchstens 10.000. Eine höhere `version` ersetzt die niedrigere; gleich oder niedriger wird
  ignoriert (kein Zurückrollen).
- **Wirkung**: Ein Knoten behandelt einen gelisteten Namen, ein gelistetes Ziel oder einen gelisteten Inhaber wie
  gesperrt – Auflösen `404`, Suche und `names/list` ohne ihn, Hosts liefern eine gelistete App (oder eine App eines
  gelisteten Inhabers) nicht mehr aus und hören auf, der Leser auch. Abgelaufene Listen und Listen von Herausgebern, die
  das Manifest nicht mehr nennt, zählen sofort nicht mehr.
- **Verteilen**: Der Herausgeber gibt die Liste an einen Knoten (`POST /v4/names/blocklist/update`,
  `bridge-node blocklist publish`); jeder Knoten fragt je Runde (`NetTiming::blocklists`, Standard 5 Minuten) bis zu 3
  andere Knoten nach jeder genannten Liste (`POST /v4/names/blocklist`) und nimmt nur eine geprüfte, neuere. Gespeichert
  im Speicher des Knotens (Schema 11, höchstens 8 je Netz), nach einem Neustart wieder geprüft geladen.
- *Beim Bau festgelegt*: Die Prüfung (bis 10.000 Einträge) läuft außerhalb jeder Sperre; ersetzt wird die ganze
  Sammlung als `Arc` (Lesen ohne Warten). Schlüssel des Herausgebers: `bridge-node blocklist key --key <datei>`.
  Eintragsdatei: je Zeile ein Name (sein Skelett wird gelistet) oder eine ID, `#` = Kommentar.

## 10. Kommandozeile (Deutsch)
- `bridge-node net create … --contact <meldeweg> [--short <kurzname>] [--adult allowed|forbidden]`.
- `bridge-node name register --data <ordner> --name shop (--app <id> | --kind node|member) [--description <text>]
  [--tags a,b] [--category general|adult] [--days 365] [--node <adresse>]` – im Ordner des Owner-Knotens: Inhaber ist
  `owner-key.json` (bei `--kind node` der Knoten selbst), bei `--app` unterschreibt der App-Schlüssel aus
  `apps/<id>.json` mit; die `hosts`-Hinweise kommen aus der aktuellen App-Version. Prüft vorher alle Regeln (§3) am
  abgespielten Log und nennt den Grund einer Ablehnung; abgegeben wird mit dem Admin-Schlüssel (`submit`).
- `bridge-node name list --data <ordner> [--owner <id>]` – alle (bzw. die eines Inhabers, höchstens 1.000) mit
  Adresse, Art, Ziel, Kategorie oder Grund, warum er gerade nicht auflöst, Ablauf, Stufe des Inhabers und Hash.
- `bridge-node name revoke --data <ordner> --name shop [--reason <text>]` – als Inhaber (Owner-Schlüssel bzw. Knoten),
  sonst als Admin mit `seals`.
- `bridge-node net label --data <ordner> --target <name|id> --category adult|general [--reason <text>] [--days 365]`.
- `bridge-node net reports --data <ordner> [--status open|done|all] [--done <id>] [--open <id>]` (die neuesten
  100).
- `bridge-node … --reader off|local|lan|tailnet [--reader-listen 127.0.0.1:<port>]` (Leser, §8; `--reader-listen 7500`
  heißt 127.0.0.1:7500).

*Beim Bau festgelegt*:
- Die Kommandozeile nimmt nur Schalter mit Wert, daher `--kind node|member` und `--category adult` statt
  Schaltern ohne Wert. `net create` ohne `--short` leitet den Kurznamen aus dem Netz-Namen ab (Kleinbuchstaben, Ziffern,
  ä→ae …, alles andere `-`, höchstens 24 Zeichen; sonst `netz`).
- `admin::create_network` und `create_network_with_words` (BridgeControll) bleiben wie sie sind – ihre Netze bekommen
  `short` aus dem Namen und `adult: "forbidden"`, aber **keinen** `contact` (Warnung `no_contact`), bis BridgeControll
  das Feld abfragt; `admin::create_network_with_options` nimmt alle Optionen (`NetOptions`).
- Meldungen gehen je Takt der Weiterleitung (`NetTiming::relay_retry`) und sofort nach dem Abgeben an den
  Log-Führer.
- Der Leser hält nur Teile und Hash-Listen im Speicher; die App-Version (≤ 256) prüft er bei jeder Anfrage gegen den
  Zustand. Er liefert eine nicht gültige Version immer als `404` (wie ein Host).
- Transport (`bridge-transport`): `Request` trägt jetzt `host` (Kopfzeile `Host`, höchstens 255 Byte) und `forwarded`
  (von einem vertrauten Proxy oder mit einer Weiterleitungs-Kopfzeile) – damit entscheidet der Knoten über den Leser.

## 11. Grenzen und offene Punkte von Phase 4
- **Sperrlisten** (§9): Ein Netz folgt höchstens 8 Herausgebern; eine Liste mit mehr als 10.000 Einträgen muss geteilt
  werden (mehrere Herausgeber-Schlüssel). BridgeControll zeigt die Listen noch nicht (Kommandozeile).
- **Leser in großen Netzen**: Er fragt höchstens 16 `web`-Knoten plus Hinweise – hostet keiner davon die App und gibt
  es keinen Namen mit `hosts`-Hinweis, findet er sie nicht. Abhilfe später: Dienst `names` als Verzeichnis.
- **Suche** (Prüfung 9): ein Durchgang billiger Vergleiche über alle Namen (höchstens 100.000) und höchstens 2.000
  Stellungs-Prüfungen je Suche, neben der Sperre, höchstens 2 gleichzeitig (§7). Bewusst **kein Volltext-Index**: Jeder
  Knoten hält den Zustand im Speicher und kopiert ihn bei Regelwechseln – ein Index über Schlagworte und Wörter der
  Beschreibungen würde ihn um ein Vielfaches vergrößern; die Namen sind ohnehin sortiert (Präfix) und das Skelett hat
  seine Tabelle. Preis: Hat ein Rang mehr als 2.000 Kandidaten, werden die ersten 2.000 nach Name geprüft – Namen
  höherer Stufe weiter hinten im Alphabet können dann fehlen (`more: true`; genauer suchen hilft).
- **Namen und das Log** (Prüfung 9): Namen haben einen eigenen Topf von `log_entries_per_day`; viele Inhaber zusammen
  können ihn für den Tag füllen – dann nimmt das Netz bis zum nächsten Tag keine Namen mehr an (Beitritte, Siegel,
  Kennzeichnungen gehen weiter).
- **Skelett** nur mit der festen Ersetzungsliste (§4); Teilwort-Treffer bei reservierten Wörtern sind gewollt streng.
- **Meldungen** zählen je Knoten (ein Mitglied kann bei mehreren Empfängern je 10 abgeben); sie bleiben im Speicher der
  Knoten, nicht im Log – geht der Log-Führer verloren, sind dort gesammelte Meldungen weg (die Empfänger behalten ihre,
  aber ohne lesbaren Text). Der Text ist an **einen** Log-Führer versiegelt (ein Umschlag hat einen Empfänger): Übernimmt
  ein anderer Log-Führer, sieht er Ziel und Grund, den Text nicht. Die Antwort an den Admin trägt den geöffneten Text
  über die Verbindung zum Owner-Knoten (bei BridgeControll Loopback; von außen per `https`).
- **Kein Alters-Nachweis**: `adult` ist eine Kennzeichnung, keine Altersprüfung (Sache des Betreibers, §2).
- **„Freigabe nach Namensregel“** (04 §3) ist durch Stufen, Kontingente und reservierte Wörter ersetzt; eine
  Freigabe-Warteschlange für Admins gibt es nicht.
- Der Dienst `names` (Siegel-Dienst) hat noch keine eigene Aufgabe: jeder Knoten löst aus seinem eigenen Log auf.
- **Leser und Tailscale Funnel** (gelöst mit Prüfung 9): Ein Knoten mit öffentlicher Adresse vertraut dem Proxy auf
  `127.0.0.1` (Funnel); auf seinem Haupt-Port bleibt der Leser für den eigenen Browser zu (fail closed). Der eigene
  Browser nimmt seinen **Zugang nur für diesen PC** (`--reader-listen`, §8); BridgeControll gibt jedem Knoten mit
  öffentlicher Adresse dafür einen eigenen Port (§12). Apps, die über den Leser laufen, erreichen dort nur den Leser und
  die Namens-Suche, nicht die übrige Bridge-API (die erreichen sie über die normale Adresse ihres Knotens).
- **Grenzen je Adresse auf einem PC**: BridgeControll, seine Status-Runden, die anderen Knoten des PCs und der Browser
  (alle Dateien einer App über den Leser) erreichen einen Knoten von `127.0.0.1` und teilen sich dessen Grenzen
  (allgemein 20/s, Lesen 10/s, Namen 5/s). BridgeControll wiederholt Admin-Aktionen bei `RATE_LIMITED` (bis zu dreimal);
  eine App mit sehr vielen Dateien lädt im Browser spürbar langsamer. Abhilfe später: eigene Grenze für den Leser des
  eigenen Besitzers.
- **Melden von Mitglieds-Knoten**: Der Mitglieds-Schlüssel eines PCs, der einem Einladungs- oder geschlossenen Netz mit
  einem Knoten beigetreten ist, ist kein Mitglied (der Knoten selbst ist es) – Melden geht dort nur über den Meldeweg
  des Betreibers (§12). Abhilfe später: eine Melde-Anfrage, die der Knoten selbst signiert (`/v4/report` für
  Knoten-Mitglieder) oder eine zweite Nutzung der Einladung beim Beitritt.

## 12. BridgeControll: Bridge-Browser, Namen, Meldungen (gebaut 12.11.2026)
Die Oberfläche für §2–§8 (ADR 0017 Nachtrag 2). Alles läuft über die Knoten **dieses** PCs; Texte auf Deutsch.

**Bridge-Browser** (Startseite „Bridge-Browser“, im Dashboard je Netz; Route `#/browser[/<knoten>[/<adresse>]]`):
- **Adresse** `shop.meinnetz`: der Kurzname wählt das Netz aus dem Manifest, das BridgeControll aus dem Log des
  eigenen Knotens abgespielt hat (dasselbe wie `GET /v4/names/info`). Haben mehrere Netze dieses PCs denselben
  Kurznamen, fragt ein Dialog mit Netz-Name und **ID-Fingerabdruck** (erste 12 und letzte 4 Zeichen der Netz-ID). Ohne
  Kurznamen gilt das gewählte Netz. Je Netz nimmt der Browser einen Knoten, dessen Leser diesem PC dienen kann: Leser
  nicht `off`, Knoten läuft und hält sein Log – sonst sagt er, warum nicht. Ein Knoten **mit öffentlicher Adresse**
  (Tailscale Funnel) dient über seinen **Leser-Port** (Prüfung 9): BridgeControll gibt ihm einen eigenen Port ab 7601
  (`reader_port` in `bridgecontroll.json`, ältere Dateien bekommen ihn beim Start, gespeichert mit der nächsten
  Änderung) und startet ihn mit `--reader-listen 127.0.0.1:<leser-port>`; ohne öffentliche Adresse ist es der
  normale Port.
- **Suche** (beim Tippen, `POST /v4/names/search`, höchstens 20): Name, Beschreibung, Schlagworte, Stufe des Inhabers,
  Kategorie. **Sicherer Modus** (Standard an) = sichere Suche des Knotens (keine 18+, keine Inhaber unter Stufe 2).
- **Auflösen** (`POST /v4/names/resolve` am Leser des eigenen Knotens): Die Antwort wird geprüft wie fremde Daten
  (Felder, Typen, Grenzen, Netz-ID) und als „Schloss“ gezeigt: Netz mit Fingerabdruck, Stufe des Inhabers, Meldeweg,
  Kennzeichnung, Warnungen auf Deutsch (`owner_level_low`, `no_contact`, `adult`, `label_override`, `app_unknown`,
  `owner_mismatch`, `card_unverified`; unbekannte Codes als allgemeine Warnung). Status „Geprüft“ (keine Warnung, Inhaber ab Stufe 2), „Vorsicht“ oder „Nicht
  geöffnet“.
- **Öffnen** nur, wenn `open` genau `/app/<ziel>/` eines App-Namens ist, dessen App-Manifest denselben Owner nennt:
  `<iframe sandbox="allow-scripts allow-forms allow-popups" referrerpolicy="no-referrer">` (nie `allow-same-origin`;
  die Sandbox steht vor der Adresse) mit `http://127.0.0.1:<leser-port>/app/<id>/` – dem Leser des eigenen Knotens,
  der jede Datei prüft und mit Sandbox-CSP ausliefert. Dazu „In neuem Tab öffnen“ (`noopener noreferrer`).
- **Schranken**: 18+ öffnet nur in Netzen mit `adult: "allowed"`, mit ausgeschaltetem sicherem Modus und nach dem
  Häkchen „Ich bin volljährig“ (Bridge prüft kein Alter, §2). Im sicheren Modus braucht ein Inhaber unter Stufe 2 ein
  „Trotzdem öffnen“. Namen für Knoten oder Mitglieder öffnen nichts.
- **CSP** der Seite: `frame-src` genau die Leser dieses PCs (`http://127.0.0.1:<port>` je Knoten mit Leser – der
  Leser-Port bei öffentlicher Adresse), sonst und für jede andere Antwort `frame-src 'none'`; alles andere bleibt
  (`default-src 'self'`, `frame-ancestors 'none'` …). Eine Seite, die vor dem Knoten geladen wurde, lädt einmal neu –
  seit Prüfung 9 **nur**, wenn die blockierte Herkunft wirklich ein Leser dieses PCs ist (`frames` von
  `GET /api/browser`) und nicht schon in der CSP der Seite steht, höchstens einmal je Laden der Seite und nie zweimal für
  dieselbe Herkunft (vorher lud eine App, die ihren Rahmen auf beliebige Ports von 127.0.0.1 lenkte, die Seite in einer
  Schleife neu).
- **Melden** (an jeder geöffneten Seite): Grund (Phishing/Betrug, illegal, 18+ ohne Kennzeichnung, Spam, Sonstiges) und
  Text (≤ 500 Zeichen) → `POST /v4/report` an einem Empfänger des Netzes (zuerst ein Knoten dieses PCs), signiert vom
  **Mitglieds-Schlüssel dieses PCs** in diesem Netz (`owner-key.json` im Ordner des Knotens, wie bei `app publish`);
  den Text versiegelt BridgeControll an den ersten Log-Führer des Netzes (§6) – ohne dessen Karte im Log geht keine
  Meldung mit Text hinaus (nie im Klartext). Der Dialog sagt das.
  Der Dialog sagt, dass die Meldung an die Admins des Netzes geht (nicht an Bridge), dass sie sehen, wer meldet, und
  dass nichts automatisch passiert. Der Owner-Knoten nimmt seinen Schlüssel selbst auf (Admin-Schlüssel); ein
  Mitglieds-Knoten in einem offenen Netz tritt beim ersten Melden bei; in Einladungs- und geschlossenen Netzen nennt
  die Antwort stattdessen den Meldeweg des Betreibers (§11).

**Assistent „Neues BridgeNet“**, Schritt 1: **Meldeweg** (Pflicht, 1–200 Zeichen – mit Erklärung, warum),
**Kurzname** (aus dem Netz-Namen vorgeschlagen, `admin::derive_short`), **Inhalte ab 18** („Nicht erlaubt“ Standard /
„Erlaubt (gekennzeichnet)“ mit Hinweis auf die Altersprüfung). Geprüft, bevor Wörter erzeugt werden; erstellt mit
`admin::create_network_with_options`.

**Owner-Dashboard**:
- **Namen**: alle Namen des Netzes (höchstens 200) mit Adresse, Art, Kategorie, ob er gilt (sonst der Grund),
  Inhaber-Stufe, Restlaufzeit; **Name anmelden** für eine App aus dem Owner-Ordner (`apps/<id>.json`), den Owner-Knoten
  oder den Betreiber selbst – über `bridge_node_cli::names::register` (alle Regeln vorher geprüft, Ablehnung mit Grund).
  App- und Betreiber-Namen gehören dem Betreiber-Schlüssel (`owner-key.json`); hat er weniger als Stufe 2, siegelt
  BridgeControll ihn vorher mit Stufe 2 ohne Dienste (sonst zeigt die sichere Suche seine Namen nicht). **Widerrufen**
  über `names::revoke`.
- **Meldungen** (`POST /v4/admin/reports`, neueste 100, Filter offen/erledigt/alle, alle 15 s und nach jeder Aktion
  neu): Grund, Ziel, Zeit, Text (als Text, Zeilenumbrüche erhalten), von wem, über welchen Empfänger; **Erledigt** /
  **Wieder öffnen**; **Schnell-Aktionen** nach Bestätigung: *Als 18+ kennzeichnen* (der Name und – bei einem App-Namen –
  die App-ID, 365 Tage), *App sperren* (365 Tage), *Namen widerrufen*; danach ist die Meldung erledigt. *App sperren*
  gibt es seit Prüfung 9 nur für eine **bekannte App**: das Ziel eines App-Namens im Log oder ein App-Schlüssel im
  Owner-Ordner – nie für das Netz, einen Log-Führer, Zeugen, Wächter, Empfänger oder Admin (auch der Server von
  BridgeControll lehnt es ab); die Zeile und die Bestätigung nennen, was die gemeldete ID ist („eine App“, „ein
  Empfänger (Gateway) des Netzes“ …). Andere Identitäten sperrt der Admin bewusst unter „Mitglieder“. Ein an einen
  anderen Log-Führer versiegelter Text erscheint als „Text verschlüsselt für den Log-Führer …“.
- **„Meldeweg fehlt“** (Netze ohne `contact`): Banner mit „Meldeweg eintragen“ – neue Manifest-Version mit `contact`,
  signiert vom Admin-Schlüssel (Recht `rules`). Unter „Regeln für Namen“: Kurzname, 18+-Regel, Meldeweg („ändern“).
- **Einstellungen je Knoten**: „Leser für den Bridge-Browser“ – Aus / Nur dieser PC (Standard) / Heimnetz (LAN) /
  Tailnet (`--reader`, in `bridgecontroll.json` als `reader`; ältere Dateien ohne das Feld: `local`).

**API** (Sitzung, Origin, JSON wie alles in BridgeControll): `GET /api/browser`, `POST /api/browser/resolve`
`{"address","node"?,"safe"?}`, `POST /api/browser/search` `{"node","q","safe"?}`, `POST /api/nodes/<id>/report`,
`GET /api/nodes/<id>/reports?status=…`, `POST /api/nodes/<id>/name-register|name-revoke|report-status|report-action|
contact`, `POST /api/wizard/short`.
