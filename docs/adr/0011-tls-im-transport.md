# ADR 0011 – Transport-Verschlüsselung (TLS) liegt im Abteil `transport`

- **Status**: angenommen (09.11.2026, Phase 3, LAN)
- **Kontext**: Regel Z10/CLAUDE.md: „Krypto nur in `bridge-core`“. Für das LAN braucht der Transport TLS mit
  selbst-signierten Zertifikaten und Pinning (ADR 0004). TLS ist ein ganzer Protokoll-Stapel (rustls, ring, rcgen),
  kein einzelner Baustein, und schützt nur Metadaten auf dem Weg – Inhalte sind schon Ende-zu-Ende verschlüsselt und
  signiert (core).
- **Entscheidung**:
  - `bridge-transport` darf rustls (nur mit dem ring-Anbieter, nie aws-lc), tokio-rustls und rcgen nutzen – nur für
    TLS-Verbindungen.
  - Alles, was Bridge-Objekte schützt oder prüft (Signaturen, Umschläge, Schlüssel, Hashes von Bridge-Daten), bleibt
    in `bridge-core::crypto`.
  - Fingerabdrücke berechnet der Transport mit `bridge_core::crypto::sha256`. Vertraut wird nur dem Zertifikat, dessen
    Fingerabdruck in der signierten Schlüsselkarte steht.
- **Folgen**: zwei Orte mit Krypto-Bibliotheken, klar getrennt nach Zweck. Die CI prüft, dass kein aws-lc
  hineinkommt (`cargo tree -i aws-lc-rs` muss leer sein).
