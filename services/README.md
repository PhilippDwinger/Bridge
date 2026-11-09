# services – Dienste (Kern-Plugins)

Ein Crate pro Dienst-Art, jedes nutzt nur `bridge-plugin-api` und `bridge-core`. Kommt ab Phase 3:
`gateway` (Empfänger), `watch` (Wächter/Zeuge), `names` (DNS + Suche), `web`, `mailbox`, `storage`, `compute`, `ai`,
`bridge` (zu anderen Netzen). Fremde Plugins sind WebAssembly-Komponenten (ADR 0005).
