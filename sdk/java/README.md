# net.bridge4 – Java-SDK (Bridge 4, Phase 6)

Nur das JDK (≥ 17): Ed25519, XDH, ChaCha20-Poly1305, HmacSHA256 (HKDF nach RFC 5869), `java.net.http`. Eigener strenger
JSON-Leser. Gleiche Formate und Prüfungen wie der Rust-Kern (docs/10 §2); besteht alle Testvektoren aus `sdk/vectors`.

```java
Identity ich = Identity.generate();                    // speichern: ich.toKeyFile() (nur für dich lesbar)
Client client = Client.join(ich, "bridge4://join?net=…");
KeyCard karte = client.cardOf("<id>");
client.send(karte, "Hallo!");
for (Client.Received m : client.receive(20).messages) System.out.println(m.from + ": " + m.content.text);
Client.Received antwort = client.request(kiKarte, Json.map("prompt", "Hallo"), 60, null);   // KI-Dienst
```

Tests: `./run_tests.sh` (Vektoren; Live-Test mit `cargo build -p bridge-tests --bin sdk-fixture`). Für Minecraft-Mods
(Java 21) direkt als Quellen einbinden.
