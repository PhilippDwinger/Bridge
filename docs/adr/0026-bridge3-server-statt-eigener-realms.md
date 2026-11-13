# ADR 0026 – Bridge-3-Server im Netz statt eigener Realms

- **Status**: angenommen (13.11.2026, Paddy: „Ansich soll Bridge 4 keine eigene Realms haben … Bridge 4 ist einfach
  riesiger und kann viele Bridge 3 enthalten“).
- **Kontext**: Bridge 3 kann Dinge, die Bridge 4 fehlen: Realms, Topics/Events, Commands mit Host-Wahl, Friends,
  BridgeExpress, geplante Nachrichten. Spiele und Mods (Roblox, Minecraft) nutzen sie über die Bridge-3-Extensions.
- **Entscheidung**: Bridge 4 baut diese Dinge **nicht** nach. Ein BridgeNet kann einen oder mehrere **echte
  Bridge-3-Server** enthalten (Code aus `bridge-3`, Python des PCs), die BridgeControll v2 startet und überwacht; das
  Tor macht sie unter `/bridge4/<netz>/bridge3/<id>/` erreichbar, das Netz macht sie auffindbar (Name).
- **Alternativen**: Bridge-3-Protokoll in Rust nachbauen – doppelter Code, jede Bridge-3-Korrektur zweimal, kleine
  Unterschiede würden Extensions brechen.
- **Folgen**: Alle Bridge-3-Extensions laufen unverändert (nur neue Adresse). Ein Bridge-3-Server hat weiter die
  Sicherheit von Bridge 3 (Passwort, RAM); er ist ein eigener Prozess ohne Zugriff auf Schlüssel von Bridge 4.
  Python wird auf dem PC gebraucht, der den Server betreibt.
