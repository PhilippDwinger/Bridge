# ADR 0006 – Transparenz-Log als Merkle-Log mit Zeugen

- **Status**: angenommen (09.11.2026; Hinweis aus der ChatGPT-Prüfung: Split-View)
- **Kontext**: Eine Hash-Kette allein verhindert nicht, dass ein böser Log-Führer verschiedenen Teilnehmern
  verschiedene Versionen zeigt.
- **Entscheidung**:
  - Ein Merkle-Baum-Log wie bei Certificate Transparency, mit signierten Log-Köpfen.
  - Inclusion- und Consistency-Proofs.
  - k-von-n-Mitsignatur durch unabhängige Zeugen (Stufe 3, verschiedene Besitzer).
  - Gossip der Köpfe zwischen Clients und Knoten.
  - Zwei unvereinbare signierte Köpfe gelten als Beweis: automatischer Widerruf des Log-Führers.
  - Siegel und Sperren gelten nur mit Inclusion-Proof gegen einen ausreichend bezeugten Kopf.
- **Folgen**: Kleine Netze brauchen mindestens einen Zeugen (Owner-Knoten). Der Wächter-Dienst bekommt die Zeugen-Rolle.
