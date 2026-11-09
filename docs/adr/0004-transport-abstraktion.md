# ADR 0004 – Transport-Abstraktion: Internet, LAN, später mehr

- **Status**: angenommen (09.11.2026; Hinweis aus der ChatGPT-Prüfung, passt zu Paddys LAN-Idee)
- **Kontext**: Geräte im selben WLAN sollen auch ohne Internet zusammenarbeiten. Das Protokoll war nur für HTTPS
  beschrieben.
- **Entscheidung**:
  - Eigenes Abteil `transport`. Das Protokoll (Aussagen, Umschläge) ist unabhängig vom Transportweg.
  - Internet: HTTPS.
  - LAN: mDNS/DNS-SD zum Finden, TLS mit Zertifikats-Pinning über die signierte Schlüsselkarte.
  - Später QUIC, WebRTC und Bluetooth.
  - Clients nehmen den besten erreichbaren Weg; LAN geht vor Internet.
- **Folgen**: Apps merken nichts vom Weg. LAN kommt in Phase 3, Internet in Phase 2.
