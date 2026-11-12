# vendor – eingebettete Krypto (noble)

`noble.js` ist ein Bündel aus den geprüften noble-Bibliotheken von Paul Miller (MIT, `LICENSE-noble`):
`@noble/curves@2.4.0` (Ed25519, X25519), `@noble/hashes@2.4.0` (SHA-256/512, HKDF), `@noble/ciphers@2.4.0`
(ChaCha20-Poly1305) – nur die genutzten Teile, mit esbuild 0.25.12 zusammengefasst, nicht verkleinert.

- Neu bauen: `sh build.sh` (gleiche Versionen → gleiche Datei; SHA-256 steht in `SUMS`, der Test prüft sie).
- Eingebettet statt npm, damit Bridge-Apps im Browser das SDK ohne Paketmanager laden können (docs/10 §2.1).
