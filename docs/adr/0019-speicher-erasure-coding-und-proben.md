# ADR 0019 – Speicher: Erasure Coding beim Client, Proben über den Wächter

- **Status**: angenommen (12.11.2026, von Claude entschieden – Paddy war weg, „entscheide selber“; Freigabe steht aus)
- **Kontext**: Phase 5 (docs/05): Dateien sollen den Ausfall von 4 von 10 Speicher-Knoten überleben; ein Knoten, der
  lügt, soll durch die Proben fallen und seine Stufe verlieren (docs/09).
- **Entscheidung**:
  1. **Verschlüsseln und Kodieren beim Client**: Datei → `encrypt_file` → Reed-Solomon (eigene Umsetzung in
     `bridge-core::erasure`, GF(2^8) mit Cauchy-Matrix – keine Kryptographie, kein fremdes Crate) → `n` Blobs auf `n`
     Knoten. Standard 6 + 4.
  2. **Stücke sind gewöhnliche Blobs** (07 §1): kein neues Upload-Protokoll, keine neue Speicher-Art im Knoten;
     Kontingente und Anheften gelten wie für Apps. Die Speicher-Karte bleibt beim Besitzer.
  3. **Proben = zufälliger Teil + Hash-Liste**: Ein Teil (64 KiB) beweist, dass der Knoten ihn hat; die Hash-Liste ist
     durch die Blob-ID gesichert. Kein neues Kryptoverfahren.
  4. **Stufe verlieren über den Wächter** (ADR 0016): `WATCH_SERVICES` = `web`, `storage`, `compute`. Der Wächter legt
     einen Proben-Blob ab (`/v4/storage/probe`) und prüft ihn bei jeder Probe; nach `fail_limit` Fehlschlägen
     widerruft er sein Siegel. Kein neuer Automatismus mit Admin-Rechten.
  5. **Verteilung**: verschiedene Knoten und verschiedene Hosts der ersten Adresse; sonst Abbruch (fail closed).
- **Folgen**: Ein Netz mit mindestens `n` Speicher-Knoten auf verschiedenen PCs kann Dateien sicher ablegen. Die
  Regel `WATCH_SERVICES` ist Teil des Zustands: alle Knoten eines Netzes brauchen diese Version (sonst lehnen ältere
  Knoten Wächter-Siegel mit `storage`/`compute` ab).
- **Grenzen**: siehe docs/09 §9.
