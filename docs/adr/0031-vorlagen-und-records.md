# ADR 0031 – Vorlagen zum Einstellen, eingebauter Server-Baustein `records`

- **Status**: angenommen (14.11.2026; Paddy, 13.11.: „ganz wichtig, dass es da viele gibt … Freunde, die gar nicht
  programmieren können … Design-Plugins später“).
- **Kontext**: Websites sind Bridge-Apps aus einem Ordner (docs/07); Server-Code gibt es als WebAssembly (docs/09 §13).
  Für Menschen ohne Programmier-Kenntnisse braucht es fertige Websites mit Einstellungen. Viele davon brauchen
  gespeicherte Einträge (Gästebuch, Umfrage). Server-Code je Vorlage in WebAssembly zu schreiben und auszuliefern wäre
  viel Code an einer heiklen Stelle (Eingaben Fremder) und ohne Rust-Ziel `wasm32` nicht baubar.
- **Entscheidung**:
  - Vorlagen liegen in BridgeControll; die Einstellungen gehen als `config.json` in die Website, die Seite setzt sie
    nur als Text ein. Designs sind CSS-Dateien mit festen Variablen – die Schnittstelle für spätere Design-Plugins.
  - Ein **eingebauter Server-Baustein** `builtin:records` im Knoten (Rust, getestet): Sammlungen mit drei Arten
    (`pub-`, `user-`, `vote-`) auf dem vorhandenen Ereignis-Log der App. Das App-Manifest nennt ihn statt einer
    `.wasm`-Datei.
- **Alternativen**: Server-Code je Vorlage als WebAssembly (aufwendig, fehleranfällig); Einträge auf dem PC des Owners
  statt im Netz (nicht bei den anderen Hosts, weg mit dem PC); Vorlagen mit HTML-Platzhaltern füllen (Gefahr von
  eingeschleustem HTML).
- **Folgen**: Neue Vorlagen brauchen nur HTML/CSS/JS und eine `template.json`. Ältere Knoten hosten Vorlagen mit
  `records` nicht (sie kennen den Baustein nicht) – bis sie aktualisiert sind. Weitere Bausteine (z. B. Chat) können
  dazukommen. Einzelheiten: docs/13.
