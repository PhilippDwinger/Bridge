# bridge4 – JavaScript-SDK (Bridge 4, Phase 6)

ES-Modul ohne Build-Schritt und ohne npm-Abhängigkeiten: Node ≥ 20 und moderne Browser (Bridge-Apps). Krypto nur aus
den eingebetteten, geprüften noble-Bibliotheken (`vendor/`, mit Prüfsumme). Gleiche Formate und Prüfungen wie der
Rust-Kern (docs/10 §2); besteht alle Testvektoren aus `sdk/vectors`.

```js
import { Client, Identity } from './bridge4.js';

const ich = Identity.generate();                  // speichern: ich.toKeyFile() (nur für dich lesbar ablegen)
const client = await Client.join(ich, 'bridge4://join?net=…');
const karte = await client.cardOf('<id>');
await client.send(karte, 'Hallo!');
for (const m of (await client.receive(20)).messages) console.log(m.from, m.content.text, m.agentOf);

const antwort = await client.request(kiKarte, { prompt: 'Wie spät ist es?' }, 60);   // KI-Dienst (docs/10 §4)
const ausweis = client.issueAgent(agentKarte, { to: [karte.id], note: 'Mein Bot' });   // Agent (docs/10 §3)
await client.send(karteInB, 'Hallo Netz B', '<netz B>');                               // verbundenes Netz (§6)
```

Tests: `npm test` (= `node --test`; der Live-Test braucht `cargo build -p bridge-tests --bin sdk-fixture`).
Doppelte werden im Speicher erkannt (100.000); dauerhaft speichern ist Sache der App.
