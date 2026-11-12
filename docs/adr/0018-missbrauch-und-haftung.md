# ADR 0018 – Missbrauch und Haftung: Namen, Kennzeichnung, Meldungen, Leser

- **Status**: angenommen beim Bau (12.11.2026; Paddy hat mit „mach einfach weiter“ an Claude übergeben – Freigabe
  durch Paddy steht aus)
- **Kontext**: In BridgeNet kann jeder ein Netz, Namen und Apps/Websites erstellen – auch illegale, Phishing- oder
  18+-Seiten. Paddy (10.11.): Er will dafür nicht verklagt werden können, und Bridge soll selbst aktiv dagegen
  ankämpfen. Gleichzeitig gilt Z1: Inhalte sind Ende-zu-Ende verschlüsselt, Knoten sehen sie nie. Phase 4 (05) bringt
  Namen (`shop.meinnetz`), Suche und den Browser.
- **Entscheidung**:
  1. **Rollen**: Paddy liefert Software und betreibt kein öffentliches Netz. Wer ein Netz erstellt, ist **Betreiber**
     und verantwortlich für sein Netz, mit erreichbarem Meldeweg (`contact` im Manifest – Pflicht bei `net create`,
     ältere Netze ohne ihn werden überall als „ohne Meldeweg“ markiert). Regeln in Klartext: `NUTZUNGSREGELN.md`
     (Entwurf, vor einem öffentlichen Start anwaltlich prüfen lassen). Bridge hat keinen zentralen Betreiber.
  2. **Nichts Verschlüsseltes wird durchsucht.** Bridge handelt nur an öffentlichen Dingen: Namen, Schlagworte,
     Beschreibungen, Apps. Keine Inhalts-Scanner, keine Hintertür, kein Generalschlüssel – das wäre ein Bruch von Z1 und
     selbst ein Haftungs- und Sicherheitsrisiko.
  3. **Namen stehen im Log** (Aussage `name`): Eindeutigkeit braucht eine Reihenfolge („wer zuerst kommt“), und das Log
     ist die eine Reihenfolge, die jeder Knoten gleich abspielt. Regeln deterministisch im Netz-Zustand: Stufe
     (Standard 1), Kontingent je Stufe, höchstens 1 Jahr, Verlängern nur durch denselben Inhaber.
  4. **Inhaberschaft einer App ohne App-Manifest im Log**: Ein App-Name ist von **App-Schlüssel und Inhaber**
     gemeinsam unterschrieben (`sigs`), beide Karten im Body. Wer den App-Schlüssel hat, ist der Owner (07 §2); beim
     Auflösen muss das aktuelle App-Manifest denselben Owner nennen, sonst kein `open`. Verworfen: App-Manifeste ins Log
     (bis 960 KiB je Version – das Log bleibt der Verwaltung) und „der Log-Führer prüft das App-Manifest“ (nicht
     deterministisch beim Abspielen).
  5. **Verwechslungs-Schutz deterministisch**: ein festes Skelett (Ziffern und Buchstaben-Paare, `m→rn`, `w→vv`,
     `d→cl` zerlegt statt zusammengefasst – ordnungs-unabhängig); gleiches Skelett wie ein gültiger Name → abgelehnt.
     **Reservierte Wörter** (Bank, Login, PayPal, Admin …, als Teilwort im Skelett) nur ab Stufe 3. Nur ASCII-Namen (keine
     Homoglyphen aus anderen Schriften). Bewusst streng (Teilwort-Treffer wie `badminton`).
  6. **Kennzeichnung** (`label`, im Log) durch Admins mit **`seals`**: eine Aussage über Vertrauenswürdigkeit wie ein
     Siegel, in beide Richtungen (falsche Selbstauskunft korrigieren). Vorrang: Name vor Ziel vor Selbstauskunft.
  7. **18+**: Manifest-Feld `adult`, Standard **`forbidden`** (fail closed). In solchen Netzen werden `adult`-Namen
     abgelehnt, als `adult` gekennzeichnete Namen lösen nicht mehr auf, und eine als `adult` gekennzeichnete **App-ID**
     wird nirgends mehr ausgeliefert (Hosts hören auf wie bei einer Sperre). Wer `allowed` wählt, verantwortet als
     Betreiber Altersprüfungen nach seinem Recht; die sichere Suche zeigt `adult` nie.
  8. **Meldungen nicht im Log** (wer meldet, ist privat), beim Empfänger gespeichert und – vom Mitglied signiert – an den
     Log-Führer weitergereicht, damit Admins alle an einer Stelle sehen und kein Empfänger Meldungen erfinden kann.
     Begrenzt je Mitglied und Knoten. **Keine Automatik**: Meldungen sind Hinweise, entscheiden tut ein Mensch – sonst
     würde Massen-Melden zur Waffe gegen Unschuldige.
  9. **Leser im eigenen Knoten** (Zero Trust für den Browser): Der Browser lädt eine App über den Knoten seines
     Besitzers, der Manifest und jeden Teil selbst prüft – nie über einen fremden Knoten. Nur lokal (Loopback, lokaler
     `Host`, keine Proxy-Köpfe; einstellbar `off|local|lan`), damit kein Knoten zum offenen Proxy wird. Eigener,
     begrenzter Speicher im RAM, getrennt von Host-Kontingenten.
  10. **Not-Aus**: `ban` (App-ID, Inhaber, Knoten) und `revoke` wirken beim Auflösen, Suchen, Hosten und Lesen sofort,
     weil jede Anfrage den aktuellen Zustand fragt.
  11. **Sperrlisten** (`blocklists`): nur das Manifest-Feld jetzt, das Holen später (08 §9) – klein halten.
- **Folgen**:
  - Betreiber haben ohne Programmieren die Werkzeuge, um Missbrauch in ihrem Netz zu bekämpfen; was in einem Netz
    passiert, ist sichtbar (Log) und nachvollziehbar (Z9).
  - Neue Mitglieder (Stufe 0) können standardmäßig keine Namen anmelden; Stufe 1 kommt automatisch vom Wächter (06 §11).
  - Harmlose Namen mit reservierten Teilwörtern brauchen Stufe 3.
  - Der Leser fragt in großen Netzen nur eine begrenzte Zahl von Hosts (08 §11).
  - Rechtlich ist das eine technische Grundlage, keine Rechtsberatung: Nutzungsregeln und Betreiber-Pflichten müssen vor
    einem öffentlichen Start anwaltlich geprüft werden.
- **Nachtrag (Prüfung 9, 12.11.2026)** – Befunde der Prüfung von Phase 4, von Claude entschieden (Freigabe durch Paddy
  steht aus; Einzelheiten docs/08 §3–§8, §11):
  1. **Suche ohne Anmeldung war ein DoS** (380 ms je Suche bei 100.000 Namen, auf einem Arbeits-Thread unter der Sperre
     des Kerns; je Treffer wurden Regeln und Name kopiert und reservierte Wörter neu berechnet): Die Suche läuft auf
     einer Momentaufnahme (`Arc`) in einem blockierenden Thread, höchstens 2 gleichzeitig je Knoten (zusätzlich zur
     Grenze je Adresse), mit begrenzter Arbeit: ein billiger Durchgang ohne Speicher je Name (Merkmale beim Eintragen
     vorberechnet, beim Manifest-Wechsel neu), dann höchstens 2.000 Stellungs-Prüfungen in Rang-Reihenfolge.
     **Verworfen**: ein Volltext-Index (Schlagworte, Wörter der Beschreibung) – er würde den Zustand, den jeder Knoten im
     Speicher hält und bei Regelwechseln kopiert, um ein Vielfaches vergrößern; Präfix (sortierte Namen) und Skelett
     (eigene Tabelle) sind ohnehin schnell. Preis: Bei mehr als 2.000 Kandidaten in einem Rang zählen die ersten nach
     Name (`more: true`).
  2. **Namen konnten das Log eines Tages aufbrauchen** (ein Mitglied der Stufe 1 verlängerte endlos; mit
     `log_entries_per_day` 50 gingen danach keine Beitritte und Kennzeichnungen mehr) und füllten mit jeder ersetzten
     Aussage die Tabelle der Widerrufe (1.000.000 – danach hätte niemand mehr etwas widerrufen können): (a) Namen haben
     einen **eigenen Topf** von `log_entries_per_day` (wie Wächter), (b) **je Inhaber und Tag** höchstens Kontingent
     seiner Stufe + 2 Namens-Einträge, deterministisch nach Abspielzeit, (c) Ändern/Verlängern desselben Namens
     **höchstens einmal am Tag**, außer in den letzten 30 Tagen vor dem Ablauf, (d) ersetzte und widerrufene
     Namens-Aussagen kommen nicht in die Tabelle der Widerrufe, sondern hinterlassen **einen Boden je Name**
     (`iat`, Hash der neuesten), der jede ältere Aussage abweist, bis sie abgelaufen sein muss (höchstens 200.000; voll:
     alle Namens-Aussagen bis zum neuesten verworfenen Boden gelten als zu alt – fail closed).
  3. **Kennzeichnungen von Namen hängen am Inhaber, 18+ gewinnt** (vorher überlebte eine Kennzeichnung den Wechsel des
     Inhabers, und ein `general` des Namens schlug ein `adult` des Ziels): Beim Abspielen merkt der Zustand den
     Inhaber, dem der Name bei der Kennzeichnung gehörte; für einen späteren anderen Inhaber gilt sie nicht (eine
     Kennzeichnung eines freien Namens gilt für jeden). Die wirksame Kategorie ist `adult`, wenn Selbstauskunft,
     Kennzeichnung des Namens oder des Ziels `adult` sagt – Punkt 6 oben („in beide Richtungen“, „Name vor Ziel vor
     Selbstauskunft“) gilt damit nur noch für die Richtung zu 18+; `general` hebt nur eine ältere eigene Kennzeichnung
     auf. **Verworfen**: die Kennzeichnung an den Hash der Namens-Aussage zu binden (wie vorgeschlagen) – jede
     Verlängerung ist eine neue Aussage, ein Inhaber hätte eine 18+-Kennzeichnung mit einer Verlängerung abgestreift.
  4. **App-Schlüssel widerruft seinen Namen** (docs/08 §3 sagte es, die Karte fehlte): Die Karte des App-Schlüssels
     kommt aus dem geltenden App-Namen, wie die des Inhabers.
  5. **Reservierte Wörter in Schlagworten** brauchen Stufe 3 wie im Namen. **Beschreibungen**: nicht ablehnen (zu viele
     harmlose Sätze enthalten „Support“, „Konto“, „Update“), sondern ein Wort mit reserviertem Wort zählt in der Suche
     nicht für Inhaber unter Stufe 3 – in beiden Such-Arten, weil Phishing keine Frage des sicheren Modus ist.
  6. **Meldungen**: Der Text ist an den Log-Führer **versiegelt** (Umschlag des Mitglieds, 04 §4; Klartext abgelehnt) – der
     Empfänger auf dem Weg sieht nur Ziel und Grund (Z1). Der Log-Führer öffnet ihn für die Admins. Eine volle Tabelle
     macht Platz mit offenen Meldungen der niedrigsten Stufe unter der des neuen Melders; offene Meldungen der Stufe 0
     gehen nach 30 Tagen (Schema 10 des Stores: Stufe beim Eingang). Grenze: ein Umschlag hat einen Empfänger – nach
     einem Wechsel des Log-Führers ist der Text dort nicht lesbar.
  7. **Leser**: `lan` = Heimnetz (RFC 1918 + ULA ohne Tailscales fd7a:115c:a1e0::/48 + Link-Local), neue Stufe
     `tailnet` = Tailscales Bereiche (wie `--peer-addresses tailnet`). Ein **Zugang nur für diesen PC**
     (`--reader-listen`, Loopback, ohne Proxy-Vertrauen, nur Leser und lesende Namens-Endpunkte) löst „Leser hinter
     Tailscale Funnel zu“ (vorher Grenze in docs/08 §11).
  8. **Knoten-Namen ohne Siegel**: Die Antwort nennt `card_verified: false` und warnt `card_unverified` – die Adressen
     sind nur die Angabe des Knotens.
