# 04 – Protokoll v4 (Entwurf)

Ein Protokoll für alles: Clients ↔ Knoten und Knoten ↔ Knoten. Alles, was reist, ist eine **Aussage**
(signiert, öffentlich lesbar) oder ein **Umschlag** (signiert und verschlüsselt).

## 1. Grundregeln
- **Kodierung**: JSON, für Signaturen **kanonisch** nach RFC 8785 (JCS). Binärdaten als Base64url ohne `=`.
- **Zeit**: Millisekunden seit 1970 (UTC), Feld `iat` (ausgestellt) und `exp` bzw. `ttl`. Toleranz ±5 Minuten.
- **Version**: Jedes Objekt hat `"v": 4`. Unbekannte Felder werden ignoriert, sind aber mit-signiert.
- **Domänen-Trennung**: Jede Signatur läuft über `"bridge4/<art>\n" + JCS(objekt ohne sig)`, `<art>` = Feld `t`
  (`key`, `env`, `rq`, `pow`, bei Aussagen ihre Art wie `seal`) – eine Signatur für das eine kann nie für etwas
  anderes gelten. Die Arten `env`, `key`, `rq`, `pow`, `part` sind für Aussagen gesperrt.
- **Grenzen vor dem Parsen**: Anfrage max. 1 MiB, Umschlag max. 256 KiB (Größeres als Strom, §6), JSON-Tiefe max. 32
  (Umschlag max. 8, damit er verpackt in Antworten immer lesbar bleibt), Schlüsselkarte max. 2 KiB,
  Strings/IDs mit festen Mustern.
- **Strenges JSON** (Z3): doppelte Schlüssel, Kommazahlen und ganze Zahlen außerhalb ±(2^53−1) werden abgelehnt
  (`BAD_FORMAT`) – so lesen alle Sprachen dasselbe Objekt gleich, und die kanonische Form ist eindeutig.
  Binärfelder müssen kanonisches Base64url sein (genau eine Schreibweise pro Wert).

## 2. Identität
**ID** = Base32 (Kleinbuchstaben, ohne Padding) der ersten 20 Bytes von SHA-256(Ed25519-Public-Key) → 32 Zeichen,
z. B. `k3x7q2...`.

**Schlüsselkarte** (selbst-signiert):
```json
{"v":4,"t":"key","id":"<id>","sign":"<ed25519-pub>","box":"<x25519-pub>",
 "role":"client|node|net|admin","name":"optional","iat":1794200000000,"sig":"<ed25519>"}
```
Prüfung: `id == ID(sign)`, Signatur gültig, `role` erlaubt.

## 3. Aussagen (signierte Erklärungen)
```json
{"v":4,"t":"<art>","net":"<netz-id>","iss":"<id>","iat":0,"exp":0,"body":{},"sig":"<ed25519>"}
```
Mehr-Augen: statt `iss`/`sig` ein Feld `sigs: [{"iss":"<id>","sig":"<...>"}]` – streng aufsteigend nach `iss`
(Byte-Reihenfolge der ID, also jeder Unterzeichner höchstens einmal), jeder Eintrag genau `{iss, sig}`. Signiert
wird das Objekt ohne `sig`/`sigs`. So hat jede signierte Aussage genau eine Byte-Form; ihr Hash (docs/06 §3) lässt
die Signaturen weg (ADR 0010).

| Art (`t`) | Inhalt (`body`) | Wer darf ausstellen |
|---|---|---|
| `manifest` | Name, Beschreibung, Netz-Art, Regeln (Beitritt, Stufen, Kontingente, Namensregeln, Mehr-Augen), Start-Empfänger | Hauptschlüssel (Grundregeln) / Admins mit Recht |
| `delegation` | Admin-ID, Rechte-Liste | Hauptschlüssel |
| `member` | Mitglieds-ID, Stufe | Empfänger mit Recht „aufnehmen“ (Stufe 0) / Admin |
| `seal` | Knoten-/Dienst-ID, Stufe, Dienst-Arten | Admin (Stufe 2), Mehr-Augen (Stufe 3), Wächter (Stufe 1 automatisch) |
| `revoke` | ID der widerrufenen Aussage oder Identität, Grund | wer ausstellen durfte, oder Owner |
| `ban` | Identität, Dauer, Grund | Admin |
| `name` | Name → Ziel-ID, Dienst-Art, Beschreibung, Schlagworte | Inhaber des Ziels (+ Freigabe nach Namensregel) |
| `log` | Log-Eintrag: Nummer, Hash des Vorgängers, Aussage | Stufe-3-Wächter |

Jede Aussage, die Rechte gibt oder nimmt, gilt nur, wenn sie im **Transparenz-Log** steht.

## 4. Umschlag
```json
{"v":4,"t":"env","id":"<16 Byte>","net":"<netz-id>","from":"<id>","to":"<id>",
 "iat":0,"ttl":600,"kind":"msg|req|res|evt|ack","epk":"<x25519 wegwerf>","n":"<12 Byte Zufall>",
 "ct":"<...>","sig":"<ed25519>"}
```
**Verschlüsseln** (Absender):
1. Wegwerf-Schlüsselpaar `e` (X25519) erzeugen; `epk = e.pub`.
2. `shared = X25519(e.priv, empfänger.box)`
3. `key = HKDF-SHA256(ikm=shared, salt=epk‖empfänger.box, info="bridge4/env/v1"‖id, 32 Byte)`
4. `n` = 12 Byte Zufall; `ct = ChaCha20-Poly1305(key, nonce=n, klartext, aad=JCS(kopf))` – Kopf = alle Felder außer
   `ct`, `sig`. Invariante **N1** (02 §4): Wegwerf-Schlüssel nur intern erzeugt + zufällige Nonce → das Paar
   (Schlüssel, Nonce) wiederholt sich nie.
5. `sig = Ed25519(absender.sign, "bridge4/env\n" ‖ JCS(alles außer sig))`

**Prüfen** (jeder Knoten auf dem Weg, billig zuerst): Größe → Format → `iat`/`ttl` → Absender bekannt/erlaubt
(guard) → Signatur. **Öffnen** (nur der Empfänger): Signatur → Entschlüsseln → Replay-Prüfung (`id` schon gesehen?).

**Klartext** (innen, ebenfalls strenges JSON):
```json
{"v":4,"type":"direct|task|response|progress|event|instruction|stream","ctype":"text/plain",
 "body":"<Text>" | "data":"<Base64url>", "reply":"<umschlag-id>", "card":{"…eigene Schlüsselkarte beim Erstkontakt…"},
 "stream":{"key":"<32 Byte>","prefix":"<8 Byte>","size":0,"parts":1,"hash":"<SHA-256>"}}
```
- Genau eines von `body` (Text) oder `data` (Bytes); `stream` nur bei `type: "stream"` (§6).
- `ctype` max. 64 Zeichen. Knoten sehen also nur: Netz, von, an, Zeit, Art, Größe – nie den Inhalt (Z1).

## 5. Gruppen (später, Phase 3+)
Ein Inhalt an viele (Topics, Events): Inhalt einmal mit Zufallsschlüssel verschlüsseln, den Schlüssel pro Empfänger
einpacken (max. 1.000 pro Umschlag). Für große Gruppen später Gruppen-Schlüssel mit Wechsel (MLS-artig).

## 6. Große Daten (Strom)
Über 180 KiB Klartext: ein **Kopf-Umschlag** (normaler Umschlag, Klartext `type: "stream"`) + **Teile** à 64 KiB.
- Der Kopf trägt verschlüsselt: Inhalts-Schlüssel (32 Byte Zufall, pro Strom neu, nur intern erzeugt – N1),
  Präfix (8 Byte Zufall), `size`, `parts`, `hash` (SHA-256 des ganzen Klartexts). Knoten sehen nichts davon.
- Teil:
  ```json
  {"v":4,"t":"part","sid":"<id des Kopf-Umschlags>","i":0,"last":false,"ct":"<...>"}
  ```
  `ct = ChaCha20-Poly1305(key, nonce = präfix ‖ i (4 Byte, big endian), teil, aad = "bridge4/part/v1" ‖ sid ‖ i ‖ last)`.
- Teilnummer und „letztes Teil“-Kennzeichen stehen in den AAD → Teile können weder vertauscht noch abgeschnitten noch
  einem anderen Strom untergeschoben werden. Der Empfänger prüft zusätzlich Reihenfolge, Anzahl, Größe und `hash`.
- `parts = max(1, ⌈size / 64 KiB⌉)`, höchstens 65.536 Teile (4 GiB). Jedes Teil außer dem letzten ist genau 64 KiB.
- Teile sind nicht einzeln signiert: Die Abgabe beim Knoten ist eine signierte Anfrage (§7), die Echtheit Ende-zu-Ende
  sichert die AEAD (nur Absender und Empfänger kennen den Schlüssel). Knoten speichern nur verschlüsselte Teile und
  nur zu Köpfen desselben Absenders, im Rahmen der Kontingente. (Endpunkte für Teile: Phase 3.)

## 7. Transport
Das Protokoll (Aussagen, Umschläge) ist **unabhängig vom Transport**. Eine App weiß nicht, ob eine Nachricht über
das Internet oder das LAN kam – das Abteil `transport` kapselt das. Weil Inhalte schon Ende-zu-Ende verschlüsselt und
signiert sind, dient die Transport-Verschlüsselung nur dem Schutz der Metadaten.

| Transport | Wann | Wie |
|---|---|---|
| **Internet** | Standard | HTTPS (TLS), z. B. über Tailscale Funnel oder eigene Domain; Long-Poll bis 25 s |
| **LAN** | Geräte im selben Netz, auch **ohne Internet** | Finden per mDNS/DNS-SD (`_bridge4._tcp`); Verbindung TLS mit selbst-signiertem Zertifikat, dessen Fingerabdruck in der signierten Schlüsselkarte des Knotens steht (Pinning statt Zertifizierungsstelle) |
| **Später** | je nach Bedarf | QUIC, WebRTC (Browser ↔ Browser), Bluetooth |

- Der Client fragt immer selbst (pull-only, wie Bridge 3). Knoten ↔ Knoten: Anfragen in beide Richtungen; jede ist
  eine signierte Aussage/ein Umschlag.
- Ein Knoten bietet mehrere Transporte gleichzeitig an; seine Schlüsselkarte listet sie (signiert). Clients wählen
  den besten erreichbaren (LAN vor Internet). Genau (Pin-Quelle, Suche, Reihenfolge, Grenzen): 06 §2 „LAN im Knoten
  und im SDK“.

**Endpunkte (Entwurf)**
| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/v4/info` | Schlüsselkarte des Knotens, Netze, Fähigkeiten, Grenzen (signiert) |
| POST | `/v4/auth/challenge` | Anmelde-Rätsel (Zufall, Ablauf, ggf. Proof-of-Work-Schwierigkeit) |
| POST | `/v4/auth/login` | Schlüsselkarte + signiertes Rätsel (+ PoW-Lösung) → Sitzung (60 min) |
| POST | `/v4/net/join` | Beitritt: PoW + ggf. Einladungscode → `member`-Aussage |
| GET/POST | `/v4/net/{netz}/manifest` · `/head` · `/log` … | Netz prüfen, Log nachladen (genau: 06 §9) |
| POST | `/v4/send` | Umschlag abgeben |
| POST | `/v4/poll` | Umschläge abholen (`wait`, `max`) |
| POST | `/v4/ack` | Abgeholtes bestätigen (wird dann gelöscht) |
| POST | `/v4/node/relay` · `/v4/node/homes` | Knoten → Knoten: Umschlag weiterreichen, `home`-Einträge (06 §8) |
| POST | `/v4/node/probe` | Wächter-Proben |

Sitzungen sind nur für Billiges (Abholen). Alles, was etwas verändert, ist zusätzlich signiert (Z2).

**Signierte Anfrage** (`rq`, Domäne `bridge4/rq`):
```json
{"v":4,"t":"rq","aud":"<knoten-id>","iss":"<id>","iat":0,"n":"<16 Byte Zufall>","op":"login|ack|…","body":{},
 "sig":"<ed25519>"}
```
Gültig nur für den Knoten `aud`, nur ±5 min um `iat`. Max. 64 KiB. Wiederholung (Replay) wird je Operation
verhindert: `login` hängt an der einmaligen Challenge, `ack` ist idempotent (doppelt bestätigen ändert nichts).
Künftige Operationen, die beides nicht sind, merken sich (`iss`, `n`) im Zeitfenster – höchstens 256 pro Identität.

**Phase 2 – genaue Endpunkte** (Antworten JSON; Sitzung im Kopf `Authorization: Bearer <Base64url 32 Byte>`)
| Endpunkt | Eingabe | Antwort | Prüfung (billig zuerst) |
|---|---|---|---|
| `GET /v4/info` | – | Aussage `info` des Knotens (`body`: Version, Grenzen) + seine Schlüsselkarte | – |
| `POST /v4/auth/challenge` | `{}` (im Netz für den Beitritt: `{"for":"join"}`, 06 §7) | `{"challenge","exp","pow"}` (`pow` = Rätsel §8 oder `null`) | Limit pro Adresse |
| `POST /v4/auth/login` | `rq` mit `op:"login"`, `body:{"challenge","card","pow":"<8 Byte>"?,"home":<aussage>?}` (`home` im Netz, 06 §8) | `{"session","exp"}` | Größe → Format → Rätsel offen + einmalig → PoW → Karte (`card.id == iss`, Rolle nicht `net`) → Signatur → im Netz: Knoten ist Empfänger, Mitglied, nicht gesperrt, `home` gültig → Platz für die Identität |
| `POST /v4/send` | Umschlag | `{"ok":true}` | Sitzung → Größe → Format → Zeit → `from` = Sitzung → Limit → Empfänger bekannt → Kontingent → Signatur → Replay → speichern |
| `POST /v4/poll` | `{"wait":0–25,"max":1–100}` | `{"envelopes":[…],"cards":{"<id>":<karte>}}` (Umschläge zusammen max. 1 MiB, mindestens einer) | Sitzung → Limit |
| `POST /v4/ack` | `rq` mit `op:"ack"`, `body:{"acks":[{"from":"<id>","id":"<16 Byte>"},…]}` (max. 100) | `{"removed":n}` | Sitzung → `iss` = Sitzung → Signatur |
| `POST /v4/card` | `{"id":"<id>"}` | `{"card":…}` | Sitzung → Limit |

- Sitzungen leben nur im RAM (60 min, max. 8 pro Identität): Nach einem Neustart meldet sich der Client neu an.
- Das Postfach liegt in SQLite: Nicht bestätigte Umschläge überleben Neustarts und kommen bei jedem `poll` wieder,
  bis sie bestätigt sind oder ablaufen (mindestens einmal; der Empfänger erkennt Doppelte an der `id`).
- Replay: Der Knoten merkt sich (`from`, `id`) jedes angenommenen Umschlags bis zum Ablauf – auch über Neustarts.
- Karten sind selbst-beglaubigend (`id` = Hash des Schlüssels): Eine Karte vom Knoten kann nicht gefälscht sein.
- Der Client merkt sich empfangene (`from`, `id`) bis zum Ablauf – auf Wunsch in einer Datei, damit auch ein
  böser Knoten nach einem Neustart des Clients nichts Altes unterschieben kann. Scheitert das Bestätigen, bekommt
  die App die Nachrichten trotzdem; die Bestätigung wird beim nächsten Abholen wiederholt.
- Standard-Grenzen (einstellbar): pro Adresse 20 Anfragen/s (Stoß 40), Rätsel 2/s (Stoß 10), 32 offene
  Verbindungen (nicht für vertraute Proxys); pro Identität 10 Sendungen/s (Stoß 30); Postfach 1.000 Umschläge /
  32 MiB, davon max. 200 vom selben Absender; max. 20.000 gemerkte Umschlag-IDs pro Absender (bis zum Ablauf);
  2 gleichzeitige Long-Polls pro Identität; 100.000 Identitäten pro Knoten (ist die Tabelle voll, wird die am
  längsten ruhende ohne wartende Post vergessen – frühestens nach einem Tag; sie schickt ihre Karte bei der nächsten
  Anmeldung neu). Zähler-Tabellen sind begrenzt (100.000 Einträge); ist eine voll, wird abgelehnt (Z8).
- Transport: Kopfzeilen müssen in 10 s da sein, der Inhalt in weiteren 10 s, jede Anfrage endet nach 35 s.
  Die Adress-Prüfung läuft, bevor der Inhalt gelesen wird. `X-Forwarded-For` zählt nur von vertrauten Proxys und
  nur der letzte Eintrag (der, den der Proxy selbst angehängt hat).

## 8. Proof-of-Work (nur optional / unter Last)
Rätsel vom Knoten:
```json
{"v":4,"t":"pow","node":"<id>","nonce":"<16 Byte>","bits":18,"exp":0,"sig":"<knoten>"}
```
Lösung: Zahl `c` (8 Byte), sodass `SHA-256(JCS(rätsel) ‖ c)` mindestens `bits` führende Null-Bits hat. Jedes Rätsel
gilt einmal und kurz (2 min). `bits` steigt mit Last, sinkt mit Stufe; höchstens 28. Das Rätsel hängt an der
Anmelde-Challenge: Der Knoten merkt es sich, der Client schickt nur `c` zurück.

## 9. Fehler
```json
{"error":"RATE_LIMITED","message":"lesbarer Text","retry_after":30}
```
Feste Codes (Auszug): `BAD_FORMAT`, `TOO_LARGE`, `BAD_SIGNATURE`, `EXPIRED`, `NOT_YET_VALID`, `REPLAY`,
`CANNOT_OPEN` (nur beim Empfänger), `NO_SESSION`, `UNKNOWN_IDENTITY`, `NOT_MEMBER`, `FORBIDDEN`, `RATE_LIMITED`,
`QUOTA_EXCEEDED`, `POW_REQUIRED`, `BANNED`, `NOT_FOUND`, `UNAVAILABLE`.

| HTTP | Codes |
|---|---|
| 400 | `BAD_FORMAT` |
| 401 | `BAD_SIGNATURE`, `EXPIRED`, `NOT_YET_VALID`, `NO_SESSION` |
| 403 | `FORBIDDEN`, `NOT_MEMBER`, `BANNED`, `POW_REQUIRED` |
| 404 | `NOT_FOUND`, `UNKNOWN_IDENTITY` |
| 409 | `REPLAY` |
| 413 | `TOO_LARGE` |
| 429 | `RATE_LIMITED`, `QUOTA_EXCEEDED` (mit `retry_after`) |
| 503 | `UNAVAILABLE` |
Fehler verraten nicht mehr als nötig (z. B. kein Unterschied „gibt es nicht“ / „darfst du nicht sehen“).

## 10. Offen in diesem Entwurf
- Format der Schlüsseldateien (Wiederherstellungs-Wörter: BIP-39, englische Standard-Liste – entschieden).
- ~~Heim-Empfänger eines Clients finden~~ – gelöst in Phase 3: `home`-Aussage beim Login, Austausch zwischen
  Empfängern (06 §8).
- Gruppen-Verschlüsselung im Detail.
