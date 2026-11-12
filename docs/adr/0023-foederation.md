# ADR 0023 – Föderation: Netze verbinden sich beidseitig über benannte Empfänger

- **Status**: angenommen (13.11.2026, von Claude entschieden – Paddy war weg; Freigabe steht aus).
- **Kontext**: Netze sind getrennte Vertrauensräume (eigenes Log, eigene Rechte). Mitglieder verschiedener Netze sollen
  sich trotzdem schreiben können, ohne dass ein Netz dem anderen mehr glauben muss als nötig.
- **Entscheidung**:
  - Aussage `federation` im Log, **nur vom Hauptschlüssel**; sie nennt das andere Netz und 1–8 seiner Empfänger mit
    Karten. Wirksam nur **beidseitig** (beide Logs) – wie das manuelle, beidseitige Server-Vertrauen in Bridge 3.
  - Umschläge bekommen das Feld `dnet` (Ziel-Netz, signiert). Zustellung über `/v4/fed/relay` an einen gelisteten
    Empfänger des Ziel-Netzes, der nur für Mitglieder mit Heim bei sich annimmt (kein zweiter Sprung).
  - Clients nehmen fremde Netze nur mit beigelegter, selbst geprüfter `federation`-Aussage ihres Hauptschlüssels an.
  - Kartensuche über `/v4/fed/card`. Nur Nachrichten (`scope: messages`); Namen/Apps bleiben im Netz.
- **Warum nicht das Log des anderen Netzes nachspielen**: zu teuer und unnötig – B vertraut den von B selbst benannten
  Empfängern von A, dass sie die Mitgliedschaft in A geprüft haben; Ende-zu-Ende-Verschlüsselung und Signatur des
  Absenders bleiben unberührt.
- **Folgen**: Neue Log-Art (`Kind::Federation`), neues Umschlag-Feld, zwei Endpunkte. Gateways des Partners ändern sich
  → der Owner erneuert die Aussage (ersetzt die alte).
