# 04 – Protokoll v4 (Entwurf)

Ein Protokoll für alles: Clients ↔ Knoten und Knoten ↔ Knoten. Alles, was reist, ist eine **Aussage**
(signiert, öffentlich lesbar) oder ein **Umschlag** (signiert und verschlüsselt).

## 1. Grundregeln
- **Kodierung**: JSON, für Signaturen **kanonisch** nach RFC 8785 (JCS). Binärdaten als Base64url ohne `=`.
- **Zeit**: Millisekunden seit 1970 (UTC), Feld `iat` (ausgestellt) und `exp` bzw. `ttl`. Toleranz ±5 Minuten.
- **Version**: Jedes Objekt hat `"v": 4`. Unbekannte Felder werden ignoriert, sind aber mit-signiert.
- **Domänen-Trennung**: Jede Signatur läuft über `"bridge4/<art>\n" + JCS(objekt ohne sig)` – eine Signatur für das
  eine kann nie für etwas anderes gelten.
- **Grenzen vor dem Parsen**: Anfrage max. 1 MiB, Umschlag max. 256 KiB (Größeres als Strom, §6), JSON-Tiefe max. 32,
  Strings/IDs mit festen Mustern.

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
Mehr-Augen: statt `iss`/`sig` ein Feld `sigs: [{"iss":"<id>","sig":"<...>"}]`.

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

**Klartext** (innen):
```json
{"type":"direct|task|response|progress|event|instruction","ctype":"text/json/…","body":"…",
 "reply":"<umschlag-id>","card":{"…eigene Schlüsselkarte beim Erstkontakt…"}}
```
Knoten sehen also nur: Netz, von, an, Zeit, Art, Größe – nie den Inhalt (Z1).

## 5. Gruppen (später, Phase 3+)
Ein Inhalt an viele (Topics, Events): Inhalt einmal mit Zufallsschlüssel verschlüsseln, den Schlüssel pro Empfänger
einpacken (max. 1.000 pro Umschlag). Für große Gruppen später Gruppen-Schlüssel mit Wechsel (MLS-artig).

## 6. Große Daten (Strom)
Über 256 KiB: Kopf-Umschlag mit `size`, `chunks`, `hash` (SHA-256 des Klartexts) + Teile à 64 KiB. Nonce je Teil =
zufälliges 8-Byte-Präfix (im Kopf) + 4-Byte-Teilnummer; Teilnummer und „letztes Teil“-Kennzeichen stehen in den AAD –
Teile können weder vertauscht noch abgeschnitten werden. Knoten speichern nur verschlüsselte Teile.

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
  den besten erreichbaren (LAN vor Internet).

**Endpunkte (Entwurf)**
| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/v4/info` | Schlüsselkarte des Knotens, Netze, Fähigkeiten, Grenzen (signiert) |
| POST | `/v4/auth/challenge` | Anmelde-Rätsel (Zufall, Ablauf, ggf. Proof-of-Work-Schwierigkeit) |
| POST | `/v4/auth/login` | Schlüsselkarte + signiertes Rätsel (+ PoW-Lösung) → Sitzung (60 min) |
| POST | `/v4/net/join` | Beitritt: PoW + ggf. Einladungscode → `member`-Aussage |
| GET | `/v4/net/{netz}/manifest` · `/log?from=n` · `/head` | Netz prüfen, Log nachladen |
| POST | `/v4/send` | Umschlag abgeben |
| POST | `/v4/poll` | Umschläge abholen (`wait`, `max`) |
| POST | `/v4/ack` | Abgeholtes bestätigen (wird dann gelöscht) |
| POST | `/v4/node/relay` | Knoten → Knoten: Umschlag weiterreichen |
| POST | `/v4/node/probe` | Wächter-Proben |

Sitzungen sind nur für Billiges (Abholen). Alles, was etwas verändert, ist zusätzlich signiert (Z2).

## 8. Proof-of-Work (nur optional / unter Last)
Rätsel vom Knoten:
```json
{"v":4,"t":"pow","node":"<id>","nonce":"<16 Byte>","bits":18,"exp":0,"sig":"<knoten>"}
```
Lösung: Zahl `c` (8 Byte), sodass `SHA-256(JCS(rätsel) ‖ c)` mindestens `bits` führende Null-Bits hat. Jedes Rätsel
gilt einmal und kurz. `bits` steigt mit Last, sinkt mit Stufe.

## 9. Fehler
```json
{"error":"RATE_LIMITED","message":"lesbarer Text","retry_after":30}
```
Feste Codes (Auszug): `BAD_FORMAT`, `TOO_LARGE`, `BAD_SIGNATURE`, `EXPIRED`, `REPLAY`, `UNKNOWN_IDENTITY`,
`NOT_MEMBER`, `FORBIDDEN`, `RATE_LIMITED`, `QUOTA_EXCEEDED`, `POW_REQUIRED`, `BANNED`, `NOT_FOUND`, `UNAVAILABLE`.
Fehler verraten nicht mehr als nötig (z. B. kein Unterschied „gibt es nicht“ / „darfst du nicht sehen“).

## 10. Offen in diesem Entwurf
- Format der Schlüsseldateien (Wiederherstellungs-Wörter: BIP-39, englische Standard-Liste – entschieden).
- Heim-Empfänger eines Clients finden (Verzeichnis-Eintrag „wohnt bei“) – Teil von Phase 3.
- Gruppen-Verschlüsselung im Detail.
