# 01 – Begriffe

| Begriff | Bedeutung |
|---|---|
| **BridgeNet / Netz** | Ein eigenes Netz eines Owners. Hat eine Netz-ID, ein Manifest (Regeln) und Mitglieder. |
| **Owner** | Wem das Netz gehört. Besitzt den **Hauptschlüssel** (offline, als Wiederherstellungs-Wörter). |
| **Admin** | Vom Owner beauftragte Identität mit Teilrechten (Delegation, befristet, widerrufbar). |
| **Identität** | Schlüsselpaar (Ed25519 + X25519) einer Person, eines Programms, eines Knotens oder eines Netzes. Die **ID** ist der Fingerabdruck des Signier-Schlüssels. |
| **Client** | Programm, das ein Netz nutzt (Spiel, Bot, Website, App). Hat eine eigene Identität. |
| **Knoten** | Laufender Bridge-Prozess auf einem PC/Server. Bietet einen oder mehrere **Dienste** an. |
| **Dienst** | Was ein Knoten anbietet: Empfänger, DNS, Speicher, Rechnen, Web, KI … (als Plugin). |
| **Empfänger** | Dienst, über den Clients ins Netz kommen (Zugang, Postfach, Weiterleitung). Braucht Siegel-Stufe 3. |
| **Wächter** | Dienst, der andere Knoten prüft (Proben, Erreichbarkeit) und das Transparenz-Log mitführt. |
| **Mitglied** | Identität mit gültigem **Mitgliedsausweis** eines Netzes. Hat eine Vertrauensstufe. |
| **Stufe** | Vertrauensstufe 0–3 einer Identität (Mitglied oder Knoten) im Netz; bestimmt Rechte und Kontingente. |
| **Siegel** | Signierte Bestätigung (Owner/Admin/automatisch), dass ein Knoten/Dienst eine Stufe hat. Läuft ab, widerrufbar. |
| **Aussage** | Jede signierte Erklärung (Manifest, Siegel, Delegation, Widerruf, Namens-Eintrag, Sperre). |
| **Transparenz-Log** | Nur-anhängbare, verkettete Liste aller sicherheitsrelevanten Aussagen eines Netzes. |
| **Umschlag** | Die verschlüsselte, signierte Einheit, in der alles reist (Nachricht, Anfrage, Antwort). |
| **Name** | Kurzer Name im Netz (`shop.meinnetz`), zeigt auf eine lange Adresse. Signierter Eintrag. |
| **Adresse** | `bridge://<netz-id>/<ziel>` – Ziel ist eine ID oder ein Name. |
| **Kontingent** | Wie viel eine Identität erstellen/speichern/rechnen darf (pro Stufe im Manifest festgelegt). |
| **Probe** | Prüfung eines Dienstes durch Wächter (z. B. Speicher-Probe: „beweise, dass du Stück X noch hast“). |
| **Plugin** | Paket, das eine Dienst-Art umsetzt, mit Manifest (Rechte, Ressourcen, Einstellungs-Formular). |
