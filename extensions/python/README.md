# Bridge für Python

Eine einzelne Datei ohne Abhängigkeiten (Python 3.10+, nur die Standardbibliothek), mit der ein Python-Programm ein
Bridge-Client wird. Objektorientiert: jedes `BridgeClient` ist ein eigener Bridge-Client (eigene Client-IP) – ein
Programm kann beliebig viele haben.

Was die Bibliothek automatisch macht (wie die Java- und die Roblox-Erweiterung):

- **Registrieren + Einloggen** im Hintergrund (`auto_start`)
- **Session-Tokens**: Erneuerung 2 Minuten vor Ablauf, bei `SESSION_INVALID` sofort neu einloggen
- **Bridge-Neustart ohne Backup**: neu registrieren und Realms, Topics und Commands wiederherstellen
  (`on_client_ip_changed` meldet die neue IP). Erst danach gilt der Client wieder als bereit.
- **Empfangen** im Hintergrund per Long Polling, bis zu 50 Nachrichten pro Anfrage
- **safe**-Nachrichten: Chunks holen + SHA-256 prüfen, **compressed**: entpacken (zlib)
- **Senden**: `auto` = `fast` wenn klein, sonst `safe`
- **Nur der neueste Stand** (`publish_latest` / `subscribe(..., latest_only=True)`): für Zustände, die sich dauernd
  ändern (Positionen …). Ein noch nicht gesendeter älterer Wert wird ersetzt, ältere wartende Events werden übersprungen.
- **close()**: kurzlebige Clients werden auf dem Server gelöscht, die anderen melden Topics/Commands ab und loggen aus.
  Beim Programmende passiert das von selbst (`close_on_exit`).
- **Server-URL mit Pfad**: `https://pc.ts.net:10000/momentum/admin` wird zu `https://pc.ts.net:10000/momentum` – mehrere
  Server auf einem Host und Port funktionieren
- Offene Verbindungen werden wiederverwendet (Keep-Alive, wichtig bei HTTPS über Tailscale Funnel), Antworten kommen
  gzip-komprimiert
- Fehler als `BridgeError` mit Bridge-Fehler-ID (`error.id`)

## Einbauen

Einfach `bridge_client.py` neben dein Programm kopieren (oder den Ordner `extensions/python` in den `sys.path`
nehmen):

```python
from bridge_client import BridgeClient, BridgeError
```

## Schnellstart

```python
from bridge_client import BridgeClient

client = BridgeClient("https://muttchen.tail91b057.ts.net", name="Mein Programm")

# Topics (ohne realm = der öffentliche Realm des Servers)
client.subscribe("chat", lambda data, event: print(event.sender_ip, data))
client.publish("chat", {"text": "Hallo"})

# Direkte Nachrichten
@client.on_message
def antworten(message):
    message.reply({"danke": True})

client.send(andere_client_ip, {"hallo": True})

# Commands
client.host_command("add", lambda args, task: args["a"] + args["b"])
drei = client.call("add", {"a": 1, "b": 2})   # 3

client.close()
```

Oder mit `with` – am Ende wird `close()` aufgerufen:

```python
with BridgeClient("https://muttchen.tail91b057.ts.net", name="Mein Programm") as client:
    client.subscribe("chat", lambda data, event: print(data))
    client.wait_closed()   # wartet, bis ein Handler client.close() aufruft (Strg+C geht auch)
```

Alle Methoden warten, bis Bridge geantwortet hat. Für Spiel-Schleifen gibt es `publish_async`, `send_async`,
`call_async` (geben ein `concurrent.futures.Future` zurück) und `publish_latest` (wartet nie: der Wert ersetzt einen
älteren, noch nicht gesendeten desselben Topics; ein Sende-Thread schickt immer den neuesten, sobald der letzte Request
durch ist). Listener und Topic-Handler laufen nacheinander auf dem Callback-Thread des Clients, in der Reihenfolge, in
der die Nachrichten kamen. Command-Handler laufen auf eigenen Threads. Alle Threads des Clients sind Daemon-Threads:
ein Programm, das nur auf Nachrichten reagiert, hält sich mit `client.wait_closed()` am Leben.

Den Realm gibst du immer als Schlüsselwort an (`realm=adresse`), ohne ihn gilt der öffentliche Realm des Servers –
bei Java ist er das erste Argument.

## Konstruktor

| Argument | Standard | Bedeutung |
|---|---|---|
| `server` | – | URL des Bridge-Servers (`/admin`, `/site` usw. wird abgeschnitten, ein Server-Pfad wie `/momentum` bleibt, `https://` wird ergänzt) |
| `name` | `Python client` | Name des Clients |
| `password` | zufällig | ohne `password`, `identity_secret` und `client_ip` ist der Client **kurzlebig** |
| `identity_secret` | – | 32+ Zeichen: **immer dieselbe Client-IP** (auch nach einem Neustart) |
| `client_ip` | – | in einen bestehenden Client einloggen (mit `password`) |
| `ephemeral` | automatisch | `True` = beim `close()` auf dem Server löschen |
| `poll_wait_seconds` / `poll_interval` / `max_messages` | 20 / 0,05 s / 50 | Long Polling |
| `connect_timeout` | 30 s | so lange wartet ein Aufruf auf die Verbindung, dann `NOT_CONNECTED` |
| `session_margin_seconds` | 120 | so lange vor Ablauf wird die Session erneuert (höchstens die halbe Session-Dauer) |
| `ignore_own_events` | `True` | eigene Events (mit `include_self`) nicht an die Handler geben |
| `auto_start` / `receive` | `True` / `True` | sofort verbinden / im Hintergrund empfangen |
| `debug` / `warn` | – / `logging` | wohin Meldungen gehen (eine Funktion, die einen Text bekommt; `None` = nirgends) |
| `close_on_exit` | `True` | beim Programmende `close()` aufrufen |

**Listener** (jeder gibt die Funktion zurück, geht also auch als Dekorator: `@client.on_message`):
`on_connected(ip)`, `on_disconnected(grund)`, `on_client_ip_changed(neu, alt)`, `on_message(message)`,
`on_event(event)`, `on_task(task)` (Commands ohne Handler – mit `task.respond(...)` antworten), `on_response(response)`,
`on_progress(progress)`, `on_error(error)`, `on_close()` (läuft am Anfang von `close()`, noch verbunden).

**Methoden:** `send`, `send_async`, `broadcast`, `subscribe(topic, handler, realm=None, latest_only=False)` (gibt eine
`Subscription` mit `close()`; mit `latest_only=True` nur das neueste Event pro Absender), `publish`, `publish_async`,
`publish_latest`, `host_command(name, handler, realm=None, description=None, signature=None, allowed_roles=None)`
(gibt ein `HostedCommand` mit `close()`), `call` / `call_async` / `call_no_wait` (Optionen `realm`, `timeout`, `mode`,
`strategy`, `progress`, `server_wait_seconds`), `get_commands`, `create_realm`, `join_realm`, `leave_realm`,
`get_realm_info`, `create_code`, `get_me`, `set_direct_policy`, `raw(pfad, body)` für jeden anderen Endpunkt,
`connect`, `wait_for_connection`, `wait_closed`, `close`.

**Eigenschaften:** `client_ip`, `server`, `server_url`, `public_realm`, `state` (`State.CONNECTED` …), `online`,
`request_count`, `limits`.

Ein Command-Handler bekommt `(args, task)` und gibt die Antwort zurück; wirft er eine Exception, bekommt der Aufrufer
`COMMAND_FAILED` mit dem Text. `task.progress(prozent, inhalt)` meldet Zwischenstände (nur wenn der Aufrufer mit
`progress="latest"` oder `"all"` ruft).

Eigene Fehler-IDs der Bibliothek: `UNREACHABLE`, `NOT_CONNECTED`, `TIMEOUT`, `COMMAND_FAILED`, `DESTROYED`,
`HASH_MISMATCH`, `ALREADY_ANSWERED`, `HANDLER_ERROR`, `SCRIPT_ERROR`, `HTTP_<status>`; Inhalt, der kein JSON ist, gibt
sofort `ARGUMENT_ERROR`.

## Test

```
python extensions/python/run_tests.py
```

Startet echte Bridge-Server (Port 8501, dazu einer hinter dem Pfad-Proxy auf 8502/8503 mit der öffentlichen URL
`http://127.0.0.1:8502/alpha`). Dagegen laufen 72 Checks: Server-URLs (auch mit Pfad und `/site`), Topics und
Batch-Poll, `publish_latest` und `subscribe` mit nur dem neuesten Event, alle Nachrichten-Modi, Commands (Fehler,
Timeout, späte Antwort, 10 parallele Aufrufe, Progress, `on_task`), Realms und Einladungscodes, Session-Erneuerung, feste
Identität, Abo vor der Verbindung, Server-Reset (neu registrieren und wiederherstellen), Aufräumen, Server mit Pfad
hinter einem Proxy. Braucht die Pakete des Bridge-Servers (`fastapi`, `uvicorn`, `httpx`, `argon2-cffi`,
`cryptography`); die Erweiterung selbst braucht keine.
