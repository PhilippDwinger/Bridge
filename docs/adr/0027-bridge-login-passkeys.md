# ADR 0027 – Bridge Login: Passkeys, Konten auf den Speicher-Knoten

- **Status**: angenommen (13.11.2026; Paddy: „extra Bridge Login Feature mit Accounts … nur freigeschaltet, wenn das
  BridgeNet einen Knoten zum Speichern mit Verifizierung hat“, kostenlos, ohne fremde Dienste).
- **Kontext**: Öffentliche Websites/Apps sollen Konten haben können. Alle Apps teilen eine Browser-Herkunft (Tor) und
  laufen sandboxed ohne Cookies – Login darf nicht in der App passieren. Passwörter wären stehlbar, E-Mail bräuchte
  einen fremden Dienst.
- **Entscheidung**: Passkeys (WebAuthn, ES256 + EdDSA, ohne Attestation – der Nutzer bestimmt seinen Schlüssel).
  Konten liegen als **selbst-beglaubigte Einträge** auf den Speicher-Knoten (`storage`, Stufe ≥ 2) und werden zwischen
  ihnen abgeglichen; jeder Knoten prüft jeden Eintrag selbst. Wiederherstellung über einen 120-Bit-Code (nur sein Hash
  liegt beim Netz). Der Login läuft in der Hülle (Bridges eigene Seite mit eigenem Skript); Apps bekommen per
  `postMessage` ein kurzlebiges, vom Knoten signiertes **App-Zeichen** mit einer Nutzer-ID nur für diese App; der Host
  prüft es für den Server-Code. Neues Krypto-Baustein-Paket: `p256` (RustCrypto) nur zum **Prüfen** von ES256 in
  `bridge-core::crypto` (Invariante: Krypto nur dort; Signieren nur im Test-Feature `test-vectors`).
- **Umfang v1** (gebaut 13.11.2026): ein Passkey je Konto, Einträge `create` und `recover`; Login an einem Knoten, der
  selbst Speicher-Knoten mit öffentlicher `https`-Adresse ist (BridgeControll: „Login hier einschalten“); Sitzung nur
  im Speicher der Hülle (kein Browser-Speicher, `Cross-Origin-Opener-Policy: same-origin`). Später: angemeldet
  bleiben, gemeinsame Domain für mehrere Eingänge.
- **Nachtrag 14.11.2026 – mehrere Geräte** (Phase 8, Schritt 3, docs/11 §14): 1–8 Passkeys je Konto, jedes Gerät mit
  eigenem Passkey (keine Passkey-Fenster für fremde Geräte). Neue Einträge `add`/`remove`, unterschrieben von einem
  Passkey, den das Konto schon hat – jeder Speicher-Knoten prüft das selbst. Gekoppelt wird mit einem Kopplungs-Code
  (8 Zeichen, 5 min, einmal; auch als QR-Code) und einer Prüfzahl, die beide Geräte zeigen. Verworfen: den Passkey
  selbst teilen (geht nur innerhalb eines Anbieters wie Google/Apple), Hybrid-Anmeldung per Bluetooth (das sind die
  Fenster, die Paddy stören), ein zweiter Wiederherstellungs-Code je Gerät (wäre ein Passwort).
- **Alternativen**: Passwörter mit Argon2 (stehlbar, Phishing); Login per E-Mail (fremder Dienst, kostet); OAuth bei
  großen Anbietern (fremd, Tracking); Konten im Transparenz-Log (öffentlich, bläht das Log auf).
- **Folgen**: Kein Geheimnis auf dem Server; ein Speicher-Knoten kann kein Konto übernehmen (nur verweigern). Ein
  Passkey gilt für den Host eines Eingangs (weitere PCs später). Ohne Speicher-Knoten mit Siegel gibt es kein Login.
  Restrisiken (gemeinsamer Ursprung hinter dem Tor, Code an einem bösen Knoten einlösen) in docs/11 §9.5.
