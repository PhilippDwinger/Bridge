# bridge4 – Python-SDK (Bridge 4, Phase 6)

Nur `cryptography` als Abhängigkeit (`pip install cryptography`). Gleiche Formate und Prüfungen wie der Rust-Kern
(docs/10 §2); besteht alle Testvektoren aus `sdk/vectors`.

```python
from bridge4 import Client, Identity

ich = Identity.load_or_create("ich.json")          # Schlüsseldatei (nur für dich lesbar)
client = Client.join(ich, "bridge4://join?net=…")  # beim ersten Mal; später: Client(ich, url, knoten_id).connect()
karte = client.card_of("<id des anderen>")
client.send(karte, "Hallo!")
for nachricht in client.receive(wait=20).messages:
    print(nachricht.sender, nachricht.content.text, nachricht.agent_of)

antwort = client.request(ki_karte, {"prompt": "Wie spät ist es?"}, wait=60)   # KI-Dienst (docs/10 §4)
ausweis = client.issue_agent(agent_karte, to=[karte.id], note="Mein Bot")       # Agent (docs/10 §3)
client.send(karte_in_b, "Hallo Netz B", net="<netz B>")                         # verbundenes Netz (docs/10 §6)
```

Tests: `python -m unittest discover -s tests` (Vektoren; der Live-Test braucht
`cargo build -p bridge-tests --bin sdk-fixture`).
