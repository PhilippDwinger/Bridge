# 02 – Sicherheitsmodell

## 1. Schutzziele
| Ziel | Heißt |
|---|---|
| **Vertraulichkeit** | Inhalte liest nur, für wen sie bestimmt sind. Knoten auf dem Weg nicht. |
| **Echtheit** | Man weiß sicher, von wem etwas kommt (Signatur), und es wurde nicht verändert. |
| **Verfügbarkeit** | Ein Netz funktioniert weiter, wenn einzelne Knoten ausfallen oder böse sind. |
| **Fairness** | Niemand kann das Netz mit Masse (Spam, Rechenlast) für andere unbrauchbar machen. |
| **Kontrolle** | Der Owner bestimmt die Regeln seines Netzes – und auch er kann nichts heimlich tun. |

## 2. Wer greift an? (Angreifer-Modell)
- **A1 Fremder im Internet**: kann Knoten/Empfänger anfragen, fluten, Pakete wiederholen.
- **A2 Böses Mitglied**: hat einen Ausweis (Stufe 0+), will spammen, Kontingente umgehen, andere ausspionieren.
- **A3 Böser Knoten**: bietet einen Dienst an und lügt, liest mit, behält Daten, liefert falsche Ergebnisse.
- **A4 Viele Fake-Identitäten (Sybil)**: erzeugt tausende Clients/Knoten, um Mehrheiten oder Kontingente zu bekommen.
- **A5 Gehackter Admin-/Owner-PC**: Schlüssel wird geklaut.
- **A6 Leitung**: liest/ändert Verkehr zwischen Client und Knoten (falls TLS fehlt oder gebrochen ist).

Nicht abgedeckt (bewusst): Angriffe auf das Betriebssystem eines PCs selbst, Seitenkanäle auf fremder Hardware,
staatliche Angreifer mit Kontrolle über große Teile des Internets. Metadaten (wer redet wann mit wem) sind in Stufe 1
für Empfänger sichtbar (siehe Restrisiken).

## 3. Vertrauensgrenzen
Jede Grenze wird mit **Z3 (prüfen)** überquert:
1. Client ↔ Empfänger (Internet)
2. Knoten ↔ Knoten (Internet, auch innerhalb desselben Netzes)
3. Knoten ↔ Plugin (fremder Code auf demselben PC → WASM-Sandbox mit Fähigkeiten-Liste, siehe 03 §4)
4. Owner/Admin-Schlüssel ↔ alles andere
5. KI-Agent ↔ alles andere (KIs sind Clients mit begrenzten Rechten, nie „Systemteil“)

## 4. Kryptografie (Suite „B4-1“)
Eine einzige Suite, keine Aushandlung (kein Downgrade). Spätere Suiten kommen nur über eine neue Protokoll-Version.

| Zweck | Verfahren |
|---|---|
| Signaturen | Ed25519 (RFC 8032) |
| Schlüsselaustausch | X25519 (RFC 7748), **pro Umschlag ein Wegwerf-Schlüssel** |
| Schlüsselableitung | HKDF-SHA256 (RFC 5869) |
| Verschlüsselung | ChaCha20-Poly1305 (RFC 8439) |
| Hash | SHA-256 |
| Passwort → Schlüssel | Argon2id (Schlüsseldateien, Wiederherstellung) |
| Zufall | Zufallsquelle des Betriebssystems |

Bibliotheken: Knoten (Rust) RustCrypto/dalek (`ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`,
`argon2`); SDKs: Python `cryptography`, Java JDK (eingebaut), JavaScript geprüfte `noble`-Bibliotheken (eingebettet,
MIT), Luau reine Luau-Umsetzung (**Risiko R1**, früh prototypen).

**Invariante N1 – (Schlüssel, Nonce) wiederholt sich nie.** Die Sicherheit von ChaCha20-Poly1305 hängt daran. Wir
verlassen uns nicht auf eine einzige Annahme, sondern sichern doppelt:
1. Jeder Umschlag bekommt einen **frischen Wegwerf-Schlüssel** (X25519) – die Schnittstelle in `core` erzeugt ihn
   selbst und nimmt nie einen von außen an; der abgeleitete Schlüssel enthält zusätzlich die Umschlag-ID.
2. Die Nonce ist **zusätzlich zufällig** (96 Bit) und steht im Umschlag. Selbst wenn ein Wegwerf-Schlüssel durch einen
   Fehler doch zweimal entstünde (kaputter Zufall, wiederhergestellter VM-Schnappschuss), wiederholt sich das Paar
   (Schlüssel, Nonce) praktisch nicht.
3. Bei Strömen (große Daten) gilt Nonce = zufälliges 64-Bit-Präfix + 32-Bit-Zähler; der Zähler darf nicht überlaufen
   (Strom endet vorher).
4. **Tests**: Millionen Umschläge → keine doppelten Wegwerf-Schlüssel/Nonces; gleicher Klartext zweimal → anderer
   Geheimtext; Neustart-Test (Zufallsquelle nach Neustart unabhängig); die API kann keinen eigenen Schlüssel/keine
   eigene Nonce entgegennehmen (Kompilier-Test).

**Warum ChaCha20-Poly1305 und nicht AES-GCM:** schnell und sicher auch ohne Hardware-Unterstützung (wichtig für reine
Software wie Luau), keine Timing-Lücken in Software.

## 5. Identitäten und Schlüssel
- Jede Identität erzeugt **selbst** ihr Schlüsselpaar – es gibt keine zentrale Registrierung.
- **ID** = Base32 der ersten 20 Bytes von SHA-256(Ed25519-Public-Key) → 32 Zeichen. Wer den Schlüssel hat, besitzt die
  ID; niemand kann eine fremde ID übernehmen.
- Eine **Schlüsselkarte** (Key Bundle) verbindet Signier- und Verschlüsselungsschlüssel und ist selbst-signiert.
- **Netz-ID** = ID des Hauptschlüssels des Owners. Wer eine Netz-ID kennt, kann jede Aussage des Netzes bis zum
  Hauptschlüssel zurück prüfen – ein böser Empfänger kann kein fremdes Netz vortäuschen.
- **Schlüssel auf der Platte** sind mit einem Passwort (Argon2id) verschlüsselt; Programme ohne Mensch (Knoten,
  Bots) nutzen den Schlüsselspeicher des Betriebssystems, wo möglich.

### Owner- und Admin-Schlüssel
- **Hauptschlüssel** des Netzes: wird beim Erstellen erzeugt, als **24 Wiederherstellungs-Wörter** angezeigt (auf
  Papier aufschreiben) und danach **nicht dauerhaft gespeichert**. Er wird nur gebraucht, um Admins einzusetzen oder
  abzusetzen und um das Manifest grundlegend zu ändern.
- **Admin-Schlüssel**: Alltag. Vom Hauptschlüssel per **Delegation** eingesetzt: Rechte-Liste + Ablaufdatum (Standard
  90 Tage, verlängerbar). Ein geklauter Admin-Schlüssel ist widerrufbar, ohne das Netz neu aufzubauen.
- **Mehr-Augen**: Das Manifest legt fest, welche Aktionen k von n Admin-Signaturen brauchen (Standard für kleine
  Netze 1 von 1; empfohlen ab mittlerer Größe 2 von 3 für: Admins ändern, Stufe 3 vergeben, Regeln ändern).

## 6. Vertrauensstufen
Gelten für **Mitglieder** (Clients) und **Knoten** getrennt. Das Manifest legt pro Stufe Rechte und Kontingente fest.

| Stufe | Name | Wie erreicht | Typische Rechte |
|---|---|---|---|
| 0 | Neu | Beitritt (Proof-of-Work, ggf. Einladung) | lesen, wenige Nachrichten, kleine Kontingente |
| 1 | Geprüft | automatisch: Zeit im Netz + keine Verstöße (Mitglied) / bestandene Proben + Online-Zeit (Knoten) | normale Kontingente, Namen anmelden, Dienste anbieten (nur als Zusatz-Kopie) |
| 2 | Versiegelt | Siegel von Admin/Owner | volle Dienste, Daten als Haupt-Kopie, eigene Namen ohne Prüfung |
| 3 | Vertraut | Siegel mit Mehr-Augen (Regel im Manifest) | Infrastruktur: Empfänger, DNS, Wächter |

- Siegel laufen ab (Standard 30 Tage). Wächter verlängern Stufe 1 automatisch, solange Proben bestehen; Stufe 2/3
  verlängert ein Admin (oder automatisch, wenn das Manifest es erlaubt und die Proben passen).
- **Wächter** (Dienst `watch`, Siegel Stufe ≥ 2 von Admins; 06 §11, ADR 0016) vergeben **nur Stufe 1**: an Mitglieder
  nach `member_age_s` (Standard 7 Tage) Mitgliedschaft ohne Sperre, an Knoten (die selbst Mitglied sind) nach
  `node_observe_s` (Standard 24 h) mit ≥ `success_pct` (90 %) bestandenen Proben, als einzigen Dienst höchstens `web`.
  Der Netz-Zustand prüft das (Stufe, Dienste, Mitgliedschaft, Alter, Budget je Wächter und Tag), die Regeln stehen im
  Manifest (`watch`).
- Abstieg: Verstoß, durchgefallene Proben oder Widerruf → sofort niedrigere Stufe (Wächter: nach `fail_limit`
  Fehlschlägen in Folge widerrufen sie ihr Siegel; auch bei Sperre oder Ende der Mitgliedschaft).
- **Bürgen** (optional pro Netz): Wer einlädt, bürgt. Fliegt der Eingeladene wegen Missbrauch, verliert der Bürge Ruf.

## 7. Angriffe und Abwehr
| # | Angriff | Abwehr |
|---|---|---|
| 1 | **Massen-Erstellung** (10 Mio. Objekte) | Kontingente pro Identität und Stufe (Z5); Rate-Limits pro Identität, IP und Netz; Stufe 0 darf fast nichts erstellen; Sperre löscht alles der Identität; Proof-of-Work nur als Bremse **unter Last**. |
| 2 | **Massen-Identitäten** (Sybil) | Einladungen und Bürgen (Hauptschutz, Standard in den Vorlagen); Stufe 0 darf fast nichts; Rechte wachsen erst mit Zeit und Prüfungen; Ruf hängt am Bürgen. Offene Netze: Proof-of-Work beim Beitritt nur, wenn der Owner es einschaltet oder Last herrscht. |
| 3 | **Speicher-Knoten liest Daten** | Daten werden beim Client verschlüsselt, bevor sie den PC verlassen (Z1). Der Knoten sieht nur Bytes. |
| 4 | **Speicher-Knoten behält/verliert Daten** | Aufteilen + Erasure Coding (z. B. 10 Teile, 6 reichen) auf Knoten **verschiedener Besitzer**; regelmäßige Speicher-Proben durch Wächter; wer durchfällt, verliert Stufe/Ruf, Teile werden neu verteilt; Stufe-1-Knoten bekommen nur Zusatz-Kopien. |
| 5 | **Rechen-Knoten liefert Falsches** | Ergebnisse stichprobenartig auf einem zweiten Knoten nachrechnen; Abweichung → Stufe verloren; vertrauliche Jobs nur an Stufe 2+. Fremder Code läuft in einer Sandbox (WebAssembly) mit Zeit-/Speicher-Limit. |
| 6 | **Böser Empfänger** | Sieht nur verschlüsselte Umschläge + Metadaten; kann nichts fälschen (Signaturen); Clients kennen mehrere Empfänger und wechseln bei Auffälligkeit; Wächter testen Empfänger mit Probe-Nachrichten. |
| 7 | **Gefälschte Namen/DNS** | Jeder Namens-Eintrag ist signiert und muss zur Regel des Netzes passen; der Client prüft selbst. |
| 8 | **Wiederholte Pakete (Replay)** | Jeder Umschlag hat ID + Zeitstempel + Lebensdauer; Empfänger merken gesehene IDs bis zum Ablauf. |
| 9 | **Fluten (DoS)** | Billige Prüfungen zuerst (Größe, Rate, Format), teure zuletzt (Signatur, Datenbank); Proof-of-Work-Rätsel unter Last; mehrere Empfänger; feste Obergrenzen für offene Verbindungen/Long-Polls. |
| 10 | **Geklauter Admin-Schlüssel** | Befristete Delegation; Widerruf durch Owner/Mehr-Augen; alles sichtbar im Transparenz-Log. |
| 11 | **Owner handelt heimlich** | Jede Siegel-/Regel-Änderung steht im Transparenz-Log; Knoten folgen nur Aussagen, die im Log stehen. |
| 12 | **Böses Plugin** | Fremde Plugins laufen als WebAssembly in einer Sandbox (wasmtime) und bekommen nur die Fähigkeiten, die ihr Manifest nennt; kein Zugriff auf Schlüssel des Knotens; signierte Pakete; Not-Aus über das Netz-Log (siehe 03 §4). |
| 13 | **KI-Agent tut zu viel** | KI = Client mit eigenem, eng begrenztem Ausweis (Rechte + Budget + Ablauf); kritische Aktionen schlägt sie nur vor, ein Mensch bestätigt. |
| 14 | **Uhren-Tricks** | Zeitfenster mit Toleranz (±5 min); Ablaufzeiten großzügig genug; Knoten mit falscher Uhr fallen bei Proben auf. |
| 15 | **Riesige/verschachtelte Eingaben** | Feste Größen- und Tiefen-Grenzen vor dem Parsen (wie heute `jsoncheck`), Streaming für Großes. |

## 8. Transparenz-Log (nach dem Vorbild Certificate Transparency)
Eine einfache Hash-Kette reicht nicht: Ein böser Log-Führer könnte verschiedenen Teilnehmern **verschiedene
Log-Versionen** zeigen (Split-View). Deshalb:
- **Merkle-Baum-Log**: Einträge = signierte Aussagen (Manifest, Delegation, Siegel, Widerruf, Sperre,
  Namensregel-Änderung, Plugin-Widerruf). Der **Log-Kopf** (Größe + Wurzel-Hash + Zeit) wird vom Log-Führer signiert.
- **Nachweise**: *Inclusion Proof* (Eintrag X steht im Log mit Kopf K) und *Consistency Proof* (Kopf K2 ist eine
  Erweiterung von K1 – nichts wurde umgeschrieben). Jeder Knoten/Client prüft beim Aktualisieren die Konsistenz zu
  seinem zuletzt gesehenen Kopf.
- **Zeugen (Witnesses)**: mehrere unabhängige Stufe-3-Knoten **verschiedener Besitzer** prüfen jeden neuen Kopf
  (Konsistenz) und **mit-signieren** ihn. Ein Kopf gilt erst als vertrauenswürdig mit **k von n Zeugen-Unterschriften**
  (Manifest, Standard: 2 von 3; kleine Netze: Owner-Knoten zählt als Zeuge).
- **Gossip gegen Split-View**: Clients und Knoten tauschen beim Kontakt die zuletzt gesehenen Köpfe aus. Zwei
  gültig signierte, aber unvereinbare Köpfe sind ein **Beweis** für Betrug: automatischer Widerruf des Log-Führers,
  Alarm an Owner und Admins, Umschalten auf einen anderen Log-Führer.
- **Regel**: Knoten und Clients akzeptieren Siegel, Sperren und Widerrufe nur mit Inclusion Proof gegen einen
  ausreichend bezeugten Kopf (Z9). Widerrufe wirken spätestens nach dem nächsten Kopf (Ziel: unter 60 s).
- Log-Kopien liegen bei allen Zeugen; jeder kann das ganze Log nachrechnen.
- **Wechsel der Zeugen oder Log-Führer** (per Manifest) gelten für einen Knoten erst, wenn der Kopf, der mit dem Wechsel
  endet, noch von der **alten** Besetzung bezeugt ist (ADR 0010, 0013): signiert von einem alten Log-Führer **und**
  mit-signiert von der alten Zeugen-Mehrheit (`witness_threshold`). Einzige Ausnahme ist die Not-Wiederherstellung
  (ADR 0012, 0014): ein Manifest allein vom Hauptschlüssel, dessen Übergangs-Kopf der **erste** alte Log-Führer
  (`logs[0]`) signiert und der Hauptschlüssel mit-signiert – ein zweiter oder dritter Log-Führer zählt dafür nie.
  Eine Gabelung eines Knotens, der schon folgt, braucht also entweder einen alten Log-Führer und die alte
  Zeugen-Mehrheit, oder die 24 Wörter und den Schlüssel des ersten alten Log-Führers. Mit dem Hauptschlüssel oder den
  Admins allein – auch nicht über einen vorher selbst eingetragenen zweiten Log-Führer (Prüfung 6) – kann niemand eine
  neue Besetzung erfinden und Knoten auf eine Gabelung führen; wer sich mit den Wörtern zum ersten Log-Führer macht,
  tut das sichtbar im echten Log, bezeugt von den alten Zeugen. Ganz neue Knoten (erster Kontakt) haben als Anker nur
  die Netz-ID (06 §10).

## 9. Kontingente und Limits (Grundgerüst)
- **Token-Bucket** je (Identität, Aktion), je (IP, Aktion) und je (Netz, Aktion).
- **Kontingente** je Stufe im Manifest (Beispiel Stufe 0: 100 Objekte/Tag, 20 MB, 1 Name; Stufe 1: 10.000 Objekte,
  1 GB, 10 Namen …) – Werte wählt der Owner per Vorlage, ohne Programmieren.
- **Erster Schutz: Einladungen, Bürgen, Stufen und Kontingente** – nicht Rechenarbeit.
- **Proof-of-Work nur optional**: (a) automatisch, wenn ein Knoten unter Last steht (Bremse gegen Fluten), (b) beim
  Beitritt offener Netze, wenn der Owner es einschaltet. Rätsel: Zufall + Ablauf + Schwierigkeit; normal < 1 s. Mitglieder
  ab Stufe 1 bekommen keine Rätsel. Es ist **kein** Sybil-Schutz für sich allein.
- **Alles hat eine Obergrenze**: Anzahl Mitglieder, Namen, Siegel, offene Polls, Postfach-Größe, Log-Größe pro Tag.

## 10. Restrisiken (bewusst offen, mit Plan)
| # | Risiko | Plan |
|---|---|---|
| R1 | Krypto in Luau (Roblox) langsam/aufwendig | Früh prototypen; notfalls „leichter Client“ mit Hilfe eines vertrauten Knotens (klar gekennzeichnet). |
| R2 | Metadaten für Empfänger sichtbar | Später „versteckter Absender“ und Onion-Routing als Option. |
| R3 | Owner verliert Wiederherstellungs-Wörter | Netz läuft mit Admins weiter, aber keine neuen Admins; optional Mehr-Personen-Wiederherstellung (Shamir) später. |
| R4 | Proof-of-Work benachteiligt schwache Geräte | Nur optional/unter Last; Stufe ≥ 1 und eingeladene Mitglieder sind ausgenommen. |
| R5 | Fremde Plugins | Anfangs nur eigene Plugins; Signatur-Pflicht; später Prüfprozess. |
