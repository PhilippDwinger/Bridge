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

## Bridge Login in einer App (docs/11 §17)
Eine App läuft in Bridges Hülle (`/web/<name>/`) und fragt sie, wer angemeldet ist. `src/login.js` hat keine
Abhängigkeiten – einfach neben die `index.html` der App kopieren:

```js
import { bridgeLogin } from './login.js';
const login = bridgeLogin({ onChange: (user) => render(user) }); // user: {id, name, token, exp} oder null
const user = await login.ready;               // null: niemand angemeldet (oder nicht in Bridge)
anmelden.onclick = () => login.ask();         // öffnet das Anmelde-Fenster der Hülle
const notes = await login.api('api/notes', { text: 'Hallo' }); // POST an den Server-Code, mit X-Bridge-Login
```
Nur Nachrichten der Hülle (`window.parent`) zählen, jede wird geprüft; `id` ist die Nutzer-ID nur für diese App.
