# Bridge 4 – Doku

| Datei | Inhalt |
|---|---|
| [00_GRUNDSAETZE](00_GRUNDSAETZE.md) | Zero Trust, Struktur, Qualität, Checkliste für jede Funktion |
| [01_BEGRIFFE](01_BEGRIFFE.md) | Netz, Knoten, Dienst, Empfänger, Siegel, Stufe … |
| [02_SICHERHEITSMODELL](02_SICHERHEITSMODELL.md) | Angreifer, Krypto-Suite, Schlüssel, Stufen, Angriffe + Abwehr, Log, Limits, Restrisiken |
| [03_ARCHITEKTUR](03_ARCHITEKTUR.md) | Abteile, Schichten, Repo-Struktur, Laufzeit, Abläufe, Persistenz, Technik |
| [04_PROTOKOLL_V4](04_PROTOKOLL_V4.md) | Formate: Schlüsselkarte, Aussagen, Umschlag, Strom, Endpunkte, PoW, Fehler |
| [05_FAHRPLAN](05_FAHRPLAN.md) | Phasen mit Abnahme, offene Fragen |
| [06_BRIDGENET](06_BRIDGENET.md) | Phase 3: Hauptschlüssel, Netz-Aussagen, Transparenz-Log, Netz-Zustand, Beitritt, Weiterleitung |
| [07_APPS_UND_DATEIEN](07_APPS_UND_DATEIEN.md) | Phase 4a: Dateien nach Inhalt, Bridge-Apps mit mehreren Hosts, Ausliefern, spätere Daten-Werkzeuge |
| [08_NAMEN_WEB_BROWSER](08_NAMEN_WEB_BROWSER.md) | Phase 4: Namen im Log, Verwechslungs-Schutz, Kennzeichnung, Meldungen, Auflösen und Suchen, Leser im eigenen Knoten |
| [09_SPEICHER_UND_RECHNEN](09_SPEICHER_UND_RECHNEN.md) | Phase 5: Speicher (Erasure Coding, Proben, Reparatur), Rechnen (WebAssembly), Plugins, Apps Stufe 2 |
| [10_SDKS_KI_FOEDERATION](10_SDKS_KI_FOEDERATION.md) | Phase 6: SDKs (Python, JavaScript, Java, Luau), Agenten-Ausweise, KI-Dienst, Suche, Föderation |
| [11_OEFFENTLICH_BRIDGE3_LOGIN](11_OEFFENTLICH_BRIDGE3_LOGIN.md) | Phase 7: öffentlich über das Tor (ein Tailscale-Port), Bridge-3-Server im Netz, Bridge Login |
| `adr/` | Entscheidungen: 0001 Zero Trust + Abteile · 0002 Lizenz · 0003 Rust/Tauri · 0004 Transport (Internet/LAN) · 0005 Plugin-Isolation · 0006 Merkle-Log mit Zeugen · 0007 PoW optional · 0008 Nonce-Invariante · 0009 Netz-Zustand aus dem Log · 0010 Aussage-Identität + Log-Regel-Wechsel · 0011 TLS im Transport · 0012 Not-Wiederherstellung · 0013 Übergangs-Köpfe beim Aufholen · 0014 Not-Form nur mit dem ersten Log-Führer · 0015 Apps und Dateien · 0016 Wächter und automatische Stufe 1 · 0017 BridgeControll v2 · 0018 Missbrauch und Haftung · 0019 Speicher · 0020 wasmi · 0021 SDKs · 0022 Agenten-Ausweise · 0023 Föderation · 0024 KI-Dienst lokal · 0025 Öffentlich über ein Tor · 0026 Bridge-3-Server statt eigener Realms · 0027 Bridge Login (Passkeys) |

Nutzungsregeln (Entwurf): [../NUTZUNGSREGELN.md](../NUTZUNGSREGELN.md)
