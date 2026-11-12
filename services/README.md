# services – Dienste (Kern-Plugins)

Ein Crate pro Dienst-Art, jedes nutzt nur `bridge-plugin-api` und `bridge-core` (die Logik ohne Netz und Schlüssel);
das Programm `bridge-node` verbindet sie mit dem Netz.

- `ai/` (Crate `bridge-ai`, Phase 6, docs/10 §4, ADR 0024): KI-Dienst mit einem Modell auf diesem PC (Ollama oder
  OpenAI-kompatibel, nur Loopback). Start: `bridge-node ai …`.

Die übrigen Dienste der Phasen 3–5 (Empfänger, Wächter, Namen, Web, Speicher, Rechnen) leben im Knoten
(`crates/bridge-node`); fremde Plugins sind WebAssembly (ADR 0005, ADR 0020).
