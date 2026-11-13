# ADR 0025 – Öffentlich über ein Tor auf einem Tailscale-Port

- **Status**: angenommen (13.11.2026, mit Paddy besprochen).
- **Kontext**: Bridge 4 soll öffentlich werden (Websites, Apps, Knoten aus dem Internet). Tailscale Funnel ist
  kostenlos, bietet aber nur die Ports 443, 8443 und 10000. Mehrere Netze (und Bridge-3-Server) müssen sich einen Port
  teilen – über den Pfad, wie BridgeControll 3 es mit `/<server-id>` macht. Ob Tailscale den Pfad beim Weiterleiten
  abschneidet, ist nicht sicher.
- **Entscheidung**: Ein eigener Prozess, **das Tor** (`bridgecontroll gate`, Abteil `crates/bridge-gate`), lauscht
  auf `127.0.0.1` und bekommt von Tailscale **einen** Pfad: `/bridge4`. Es verteilt `/<netz>/…` an die Knoten dieses PCs
  (Ziele nur aus einer Routen-Datei von BridgeControll), setzt die Weiterleitungs-Köpfe selbst, begrenzt Verbindungen
  und kennt einen Not-Aus für Websites. Es kommt mit und ohne abgeschnittenes `/bridge4` zurecht. Netze, die 18+
  erlauben, werden nie öffentlich. Websites erscheinen öffentlich in einer **Hülle** des Knotens (Netz, Name, Meldeweg)
  und bleiben in ihrer undurchsichtigen Sandbox-Herkunft (docs/07 §5).
- **Alternativen**: (a) ein Tailscale-Eintrag pro Netz direkt auf den Knoten – hängt am Abschneide-Verhalten von
  Tailscale, jede Änderung braucht Tailscale (langsam, kann scheitern), keine eigenen Grenzen; (b) das Tor im Prozess
  der Oberfläche – das Internet wäre im selben Prozess wie Sitzungen und Admin-Schlüssel (gegen Z1/Abteile).
- **Folgen**: Ein neues Netz braucht keine Tailscale-Änderung; Not-Aus wirkt sofort. Das Tor funktioniert genauso
  hinter anderen Tunneln oder einer eigenen Domain (später, optional). Alle öffentlichen Websites teilen eine Herkunft –
  deshalb bleiben Apps sandboxed ohne eigene Cookies; Konten kommen über Bridge Login (docs/11 §9).
