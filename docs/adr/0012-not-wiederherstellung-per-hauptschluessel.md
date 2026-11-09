# ADR 0012 – Not-Wiederherstellung: der Hauptschlüssel bestätigt einen Übergangs-Kopf

- **Status**: angenommen (09.11.2026, nach Prüfung 4; Paddy schläft, „entscheide selber“)
- **Kontext**: Ein Kopf gilt erst mit `witness_threshold` Zeugen-Signaturen der Log-Regeln für seine Größe
  (ADR 0010). Sind diese Regeln nicht mehr erfüllbar – Zeugen-Schlüssel verloren, Mehrheit weg, eine ID vertippt –,
  wird kein Kopf mehr bezeugt. Auch ein reparierendes Manifest hilft nicht: Sein eigener Übergangs-Kopf wird noch
  gegen die kaputten Regeln geprüft. Das Netz stünde für immer still (Prüfung 4, Befund 3). Die Vorbeugung beim
  Log-Führer (Manifest-Wechsel nur mit gesiegelten Zeugen und Log-Führer, docs/06 §4) verhindert Tippfehler, aber
  keinen späteren Verlust.
- **Entscheidung**:
  1. Ändert ein Manifest, das **allein der Hauptschlüssel** signiert hat, die Log-Regeln, zählt für **seinen**
     Übergangs-Kopf (Größe j + 1) statt der Zeugen-Mehrheit auch ein gültiges `cosign` des Hauptschlüssels. Der Kopf
     bleibt vom Log-Führer der alten Regeln signiert. Für jeden anderen Kopf zählt ein `cosign` des Hauptschlüssels
     nie; die Netz-ID darf deshalb nie Zeuge oder Log-Führer sein.
  2. Das gilt überall gleich (Log-Führer, Zeugen, folgende Knoten: `NetState::check_witnessed`); der Zustand merkt
     sich je Regel-Wechsel, ob das Manifest allein vom Hauptschlüssel kam.
  3. Der Log-Führer nimmt ein solches Manifest auch an, während er noch auf einen früheren Übergangs-Kopf wartet.
  4. Werkzeug: `bridge-node net rescue` fragt die 24 Wörter ab (nie angezeigt, nie gespeichert), prüft das ganze Log
     selbst und gibt Manifest und `cosign` ab.
- **Folgen**:
  - Wer die 24 Wörter hat, kann für genau einen Kopf die Zeugen übergehen. Das ist keine neue Macht: Der
    Hauptschlüssel darf ohnehin jedes Manifest ausstellen (und damit beliebige Zeugen einsetzen). Neu ist nur, dass
    die alten Zeugen den Übergangs-Kopf nicht mehr sehen müssen.
  - Gabelungen bleiben erkennbar: Köpfe signiert weiter nur der Log-Führer; zwei unvereinbare Köpfe sind wie bisher
    ein Beweis (ADR 0009). Ein Fälscher braucht die Wörter **und** den Schlüssel des Log-Führers – *das stimmte erst
    mit ADR 0013* (Prüfung 5, Befund 1): Vorher prüfte ein nachhängender Knoten den Übergangs-Kopf eines Wechsels gar
    nicht, die Wörter allein reichten für eine Gabelung.
- **Nachtrag (Prüfung 5, ADR 0013)**: Ein Knoten, der über einen Wechsel hinweg aufholt, verlangt dessen Übergangs-Kopf
  unter den Regeln davor; für ein Manifest allein vom Hauptschlüssel zählt dabei die Not-Form (alter Log-Führer +
  `cosign` des Hauptschlüssels). Hing vor der Not-Wiederherstellung ein Wechsel (sein Übergangs-Kopf wurde nie
  bezeugt), bestätigt der Not-Übergangs-Kopf ihn mit, wenn er von einem Log-Führer der Regeln vor dem hängenden
  Wechsel signiert ist. Damit gilt: Gabelung eines folgenden Knotens nur mit den Wörtern **und** dem Schlüssel des
  alten Log-Führers (oder mit der alten Zeugen-Mehrheit). `net rescue` liest die Wörter seit Prüfung 5 am globalen
  Eingabe-Puffer vorbei (docs/06 §10).
  - Nicht gelöst: ein für immer verlorener einziger Log-Führer (dafür vorbeugend einen zweiten in `logs`).
- **Nachtrag (Prüfung 6, ADR 0014)**: „Der Kopf bleibt vom Log-Führer der alten Regeln signiert“ war als „von
  irgendeinem Log-Führer der alten Regeln“ gebaut. Mit den Wörtern allein ließ sich vorher im echten Log ein eigener
  zweiter Log-Führer eintragen und mit ihm die Not-Form erfüllen – wieder eine Gabelung allein mit den Wörtern. Jetzt
  zählt die Not-Form (und die Bestätigung eines hängenden Wechsels über sie) nur für einen Kopf des **ersten**
  Log-Führers der alten Regeln (`logs[0]`). Damit stimmt: Fälscher brauchen die Wörter **und** den Schlüssel dieses
  Log-Führers. Folge für den Punkt oben: Ein zweiter Log-Führer hilft der Not-Wiederherstellung **nicht** mehr – ist
  der erste weg, geht es nur noch mit der alten Zeugen-Mehrheit.
