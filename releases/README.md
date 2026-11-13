# releases/

`bridgecontroll.json` – die von Paddy unterschriebene Update-Ankündigung für BridgeControll (docs/12 §3, ADR 0029).
Nur `bridge-node release sign` schreibt sie (auf Paddys PC, mit seinem Veröffentlichungs-Schlüssel); ohne gültige
Unterschrift nimmt kein BridgeControll ein Update. Prüfen: `bridge-node release verify --file releases/bridgecontroll.json`.
