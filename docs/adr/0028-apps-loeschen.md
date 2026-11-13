# ADR 0028 – Apps und Websites löschen (Rückzug im Log)

- **Status**: angenommen (13.11.2026, Paddy: „mach rein, dass man Apps/Websites löschen kann – gerade kann man nur
  sperren, das ist nervig“).
- **Kontext**: Bisher endet eine App nur durch Ablauf (höchstens 1 Jahr), eine neue Version ohne einen Host (nur dieser
  hört auf) oder eine **Sperre** des Admins (`ban`, Maßnahme gegen fremde Inhalte, bleibt sichtbar). App-Versionen
  stehen nicht im Log; ein Host, der beim Löschen aus ist, erführe ein „Stopp-Signal“ von den anderen Hosts nicht mehr,
  wenn diese die App schon vergessen haben – er würde die alte Version bis zu einem Jahr weiter ausliefern.
- **Entscheidung**: Eine neue Log-Art **`retire`** („Rückzug“): `{app, owner, card, owner_card}`, unterschrieben von
  **App-Schlüssel und Owner** (wie die Versionen), Laufzeit mindestens 1 Jahr (so lange gilt höchstens eine Version, die
  es davor gab). Solange der Rückzug gilt, ist **jede** Version dieser App ungültig: alle Hosts hören auf und geben die
  Dateien frei (dieselbe Prüfung wie bei einer Sperre, `check_standing`), der Leser liefert nichts mehr aus. Alle
  **Namen**, die auf die App zeigen, enden mit dem Rückzug (frei für andere, mit der üblichen Untergrenze gegen alte
  Aussagen); neue Namen für sie werden abgelehnt. Ein Rückzug ist **nicht widerrufbar** (nur der Hauptschlüssel könnte
  ihn widerrufen) und bleibt auch bei `revoke … cascade` seines Owners bestehen (wie Widerrufe).
  BridgeControll („Löschen“) und `bridge-node app delete` löschen danach den App-Schlüssel (`apps/<id>.json`) – eine
  gelöschte App kommt nicht wieder.
- **Alternativen**: Eine letzte Version mit kurzer Laufzeit (nicht im Log – erreicht ausgeschaltete Hosts nicht);
  Sperre durch den Owner selbst (vermischt Moderation und Aufräumen; der Owner ist nicht immer Admin); Löschen nur auf
  dem eigenen Knoten (andere Hosts liefern weiter aus).
- **Folgen**: Jeder Knoten erfährt das Löschen über das Log, auch nach Wochen offline. Ein Eintrag je gelöschter App
  (Topf der Namen, zählt nicht gegen Admins); höchstens 100.000 gelten gleichzeitig (darüber: kein weiterer Rückzug,
  fail closed). Ältere Knoten kennen die Art nicht und überspringen den Eintrag – sie liefern die App weiter aus, bis
  sie aktualisiert sind. Eine gesperrte App kann ihr Owner nicht löschen (gesperrte Unterzeichner zählen nicht); sie
  ist ohnehin aus.
