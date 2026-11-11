# ADR 0016 – Wächter und automatische Stufe 1

- **Status**: angenommen beim Bau (11.11.2026; Paddy war mit dem UI-Entwurf beschäftigt und hat die Details an Claude
  übergeben – Freigabe durch Paddy steht aus)
- **Kontext**: 02 §6 verspricht Stufe 1 „Geprüft“ **automatisch**: für Mitglieder nach Zeit im Netz ohne Verstöße,
  für Knoten nach bestandenen Proben und Online-Zeit; Wächter verlängern, solange Proben bestehen, und stufen bei
  Fehlschlägen ab. Apps brauchen Hosts mit `web`-Siegel ab Stufe 1 (07). Bisher konnten nur Admins Stufe 1 vergeben.
  Der Dienst `watch` stand schon in der Liste der Dienste, tat aber nichts.
- **Entscheidung**:
  1. **Ein Wächter ist ein Knoten mit Siegel Stufe ≥ 2 und Dienst `watch`** (aus dem Log, wie jede Rolle). Stufe 2
     reicht, weil der Wächter nur einen kleinen Teil dessen tut, was ein Admin mit `seals` ohnehin darf – und dieser
     Admin hat ihn eingesetzt.
  2. **Der Netz-Zustand prüft, was ein Wächter unterschreibt** – nicht der Wächter selbst und nicht der Log-Führer
     allein: nur `level` 1, genau ein Unterzeichner, Inhaber ≠ Wächter und Mitglied (Stufe 1 baut auf Stufe 0 auf; der
     Beitritt nach dem Modus des Netzes bleibt das Tor, auch für Knoten – sonst bekäme in einem `closed`-Netz jeder
     fremde Knoten, der dem öffentlichen Log folgt, nach 24 Stunden `web`), Lebensdauer ≤ `seal_s`, Budget je Wächter
     und Tag. Zwei Arten, an der Karte erkennbar: **Mitglied** (keine Karte, keine Dienste, Mindestalter der
     Mitgliedschaft und Abstand zur letzten Sperre – beides deterministisch aus dem Log) und **Knoten** (Knoten-Karte mit
     Adressen, Dienste ⊆ {`web`}; die Proben sind Sache des Wächters).
  3. **Feste Dienst-Liste {`web`}**: Websites und Apps prüft der Client selbst (Hash-Listen, zwei Signaturen), ein
     schlechter Host kann nur ausfallen – genau das messen die Proben. `storage`, `compute`, `names` brauchen eigene
     Proben und kommen erst mit ihnen; Infrastruktur (`gateway`, `log`, `witness`, `watch`) bleibt bei Admins.
  4. **Ein Stufe-1-Siegel je Inhaber, wer zuerst kommt**: Ein Wächter ersetzt nur sein eigenes (Verlängerung) oder ein
     verwaistes (Aussteller kein Wächter mehr), nie das eines Admins oder eines anderen aktiven Wächters. So gibt es
     bei mehreren Wächtern keine Doppelten und kein Hin und Her; was zuerst im Log steht, gilt.
  5. **Keine Kaskade beim Ende eines Wächters**: Seine Siegel laufen aus (≤ 30 Tage), andere Wächter übernehmen sie
     beim Verlängern, Admins widerrufen einzeln, der Hauptschlüssel per `cascade`. Verworfen: „Siegel gelten nur,
     solange ihr Wächter Wächter ist“ – ein vergessenes Verlängern des Wächter-Siegels ließe alle Stufe-1-Siegel des
     Netzes auf einmal fallen.
  6. **Abstieg durch Widerruf, nicht nur durch Ablauf**: nach `fail_limit` Fehlschlägen in Folge (Standard 3, also
     ~15 min) widerruft der Wächter sein Siegel. Widerrufe zählen nicht zum Budget (Abstieg muss immer gehen).
  7. **Regeln im Manifest** (`watch`, optional, streng, Standardwerte ohne Feld): alle sichtbar und nur per
     Manifest-Änderung (`rules`) änderbar. Zeiten in Sekunden – so können Tests sie kurz setzen, ohne die Uhr zu
     verstellen.
  8. **Proben**: `/v4/info` (richtige ID, signiert, richtige Uhr) und `/v4/net/{netz}/head` (konsistent mit dem
     eigenen Log, nicht weit hinten), zusammen ≤ 5 s, über denselben Weg wie jede Knoten-Anfrage (LAN gepinnt, dann
     `urls`). Knoten melden sich mit einer signierten Anfrage und ihrer Karte an (begrenzte Tabelle, Ablauf); die
     Proben-Geschichte wird gespeichert (Schema 7) und überlebt Neustarts.
- **Folgen**: Ein böser Wächter kann höchstens `seals_per_day` Mitgliedern/Knoten Stufe 1 bzw. `web` geben, je
  höchstens `seal_s` lang – sichtbar im Log und widerrufbar. Proben-Ergebnisse sind nicht im Log nachprüfbar (bewusst:
  sie sind Beobachtungen, keine Aussagen). Mitglieder ohne Verstöße und erreichbare Knoten steigen ohne Admin auf.
- **Nachtrag (Prüfung 8, 12.11.2026)** – Befunde der Sicherheitsprüfung, von Claude entschieden (Freigabe durch Paddy
  steht aus):
  1. **Eigene Tabelle und eigener Topf**: Wächter-Siegel füllten die gemeinsamen 10.000 Siegel-Plätze – danach konnte
     kein Admin mehr siegeln. Jetzt haben sie eine eigene Tabelle (höchstens `limits.members`), die Plätze von Admins
     und Hauptschlüssel bleiben unberührt; Einträge von Wächtern zählen in einem eigenen, gleich großen Topf von
     `log_entries_per_day`; `seals_per_day` ist höchstens ein Viertel davon (06 §11.2 Punkt 8, §11.3).
  2. **Adress-Schutz**: Angemeldete Adressen und Adressen aus Karten, die nur ein Wächter gesiegelt hat, ruft ein
     Knoten nur auf öffentlichen IPs an – aufgelöst und festgelegt je Aufruf, Ausnahme gepinntes LAN. Regel
     `--peer-addresses public|tailnet|any`: `public` ist der Standard von `bridge-node`; `tailnet` erlaubt dazu genau
     die Tailscale-Bereiche 100.64.0.0/10 und fd7a:115c:a1e0::/48 (Entscheidung mit Paddy, der alles über Tailscale
     Funnel betreibt: MagicDNS löst Funnel-Namen im Tailnet zu 100.x auf); `any` prüft nichts (LAN-Netze, Tests). Adressen haben überall die strenge Form `http(s)://host[:port][/pfad]`
     (06 §2). Verworfen: der Schutz für alle Knoten-Adressen – Adressen in Admin-Siegeln sind bewusst gewählt, und
     LAN-/Tailnet-Netze folgten ihrem Log sonst nicht mehr.
  3. **Volle Anmelde-Tabelle**: verdrängt wird die älteste Anmeldung, die nicht besteht; neue Anmeldungen höchstens 16
     je Adresse und Stunde. Keine Stufe und kein Rätsel für die Anmeldung – das Tor bleibt die Mitgliedschaft (06
     §11.5).
  4. **Beobachtungszeit**: neue `urls`/`tls` beginnen die Beobachtung neu; ohne volle Zeit nur eine reine
     Verlängerung mit derselben Karte (06 §11.5, §11.6).
  5. **Ausweichen durch Nicht-Anmelden**: Ein Knoten-Siegel, dessen Anmeldung abgelaufen ist, widerruft der Wächter
     („Anmeldung abgelaufen“, erst 2 Anmelde-Takte nach seinem Start). Verworfen: mit der Karte aus dem Siegel weiter
     proben – ein Siegel ohne Anmeldung hätte keine Verlängerung und keinen Platz in der Tabelle (06 §11.6).
  6. **Alter der Mitgliedschaft** ab der Prüfzeit ihres Eintrags (Log-Uhr), nicht ab ihrem `iat` (06 §11.2 Punkt 4).
- **Ort im Code**: Regeln im Netz-Zustand (`bridge-net`, `NetState::check_watch_seal`), Proben und Entscheidungen im
  Knoten (`bridge-node`, Modul `network::watcher`, wie der Empfänger) – ein eigenes Plugin unter `services/watch` erst,
  wenn es das Plugin-Gerüst gibt (03).
- Genaues: docs/06 §11.
