# Bridge4 – Luau-SDK (Roblox-Server, Lune) – Bridge 4, Phase 6

Reines Luau, keine Abhängigkeiten. Gleiche Formate und Prüfungen wie der Rust-Kern (docs/10 §2.5); besteht die
RFC-Testvektoren (SHA-256/512, HKDF, ChaCha20-Poly1305, X25519, Ed25519) und alle Bridge-Vektoren aus `sdk/vectors`.

**Restrisiko R1**: Roblox hat keine Krypto-Bausteine. `src/Crypto.luau` ist ein Port von TweetNaCl (gemeinfrei, von
Cure53 geprüft) plus RFC-Code – nur über Testvektoren geprüft, ohne Timing-Garantie. Zufall: Roblox hat keine
kryptografische Zufallsquelle; `Bridge4.roblox()` mischt GUIDs von HttpService mit der Uhr. **Schlüssel daher nicht in
Roblox erzeugen**, sondern mit `bridge-node`/BridgeControll (Schlüsseldatei) und den Text im `ServerStorage` oder einem
DataStore ablegen – nie im `ReplicatedStorage`.

```lua
local Bridge4 = require(game.ServerScriptService.Bridge4.Bridge4)   -- Rojo: Ordner src als Modul-Ordner
Bridge4.roblox()                                                    -- Lune: Bridge4.lune()
local ich = Bridge4.identityFromKeyFile(SCHLUESSEL_TEXT)
local client = Bridge4.Client.join(ich, "bridge4://join?net=…")     -- später: Bridge4.Client.new(ich, url, knoten):connect()
local karte = client:cardOf("<id>")
client:send(karte, "Hallo aus Roblox!")
for _, m in client:receive(20).messages do print(m.from, m.content.text) end
local antwort = client:request(kiKarte, Bridge4.Json.object({ prompt = "Hallo" }), 60)   -- KI-Dienst
```

Nur auf dem Server (HttpService aktivieren; höchstens 500 Anfragen pro Minute – `receive` mit `wait` bis 20 s).
Richtwert (Lune): Signieren/Prüfen je ≈ 50 ms, eine Nachricht senden oder öffnen ≈ 0,1–0,2 s.

Tests: `tests/run_tests.sh` (Lune 0.8.9; Live-Test mit `cargo build -p bridge-tests --bin sdk-fixture`).
