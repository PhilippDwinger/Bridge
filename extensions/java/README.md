# Bridge für Java

Eine kleine Bibliothek ohne Abhängigkeiten (Java 21+), mit der ein Java-Programm ein Bridge-Client wird. Sie läuft in
normalen Java-Programmen genauso wie in Minecraft-Mods. Objektorientiert: jedes `BridgeClient` ist ein eigener
Bridge-Client (eigene Client-IP) – ein Programm kann beliebig viele haben.

Was die Bibliothek automatisch macht (wie das Roblox-Modul):

- **Registrieren + Einloggen** im Hintergrund (`autoStart`)
- **Session-Tokens**: Erneuerung 2 Minuten vor Ablauf, bei `SESSION_INVALID` sofort neu einloggen
- **Bridge-Neustart ohne Backup**: neu registrieren und Realms, Topics und Commands wiederherstellen
  (`onClientIpChanged` meldet die neue IP). Erst danach gilt der Client wieder als bereit.
- **Empfangen** im Hintergrund per Long Polling, bis zu 50 Nachrichten pro Anfrage
- **safe**-Nachrichten: Chunks holen + SHA-256 prüfen, **compressed**: entpacken (java.util.zip)
- **Senden**: `auto` = `fast` wenn klein, sonst `safe`
- **close()**: kurzlebige Clients werden auf dem Server gelöscht, die anderen melden Topics/Commands ab und loggen aus
- Eigener JSON-Leser/-Schreiber (`Json`), Fehler als `BridgeException` mit Bridge-Fehler-ID

## Einbauen

Die drei Dateien in `src/main/java/io/github/philippdwinger/bridge/` (`BridgeClient`, `Json`, `BridgeException`)
gehören in dein Projekt. Mit Gradle direkt aus diesem Ordner, ohne Kopie (so macht es die Minecraft-Mod):

```groovy
sourceSets {
	main {
		java {
			srcDir '../Bridge/extensions/java/src/main/java'
		}
	}
}
```

## Schnellstart

```java
BridgeClient client = BridgeClient.builder("https://muttchen.tail91b057.ts.net").name("Mein Programm").build();

// Topics (null = der öffentliche Realm des Servers)
client.subscribe(null, "chat", (data, event) -> System.out.println(event.senderIp() + ": " + data));
client.publish(null, "chat", Json.obj("text", "Hallo"));

// Direkte Nachrichten
client.onMessage(message -> message.reply(Json.obj("danke", true)));
client.send(andereClientIp, Json.obj("hallo", true));

// Commands
client.hostCommand(null, "add", (args, task) ->
		Json.asLong(Json.asMap(args).get("a"), 0) + Json.asLong(Json.asMap(args).get("b"), 0));
Object drei = client.call("add", Json.obj("a", 1, "b", 2));   // 3

client.close();
```

Alle Methoden warten, bis Bridge geantwortet hat. Für Spiel-Schleifen gibt es `publishAsync`, `sendAsync` und
`callAsync`. Listener und Topic-Handler laufen nacheinander auf dem Callback-Thread des Clients, in der Reihenfolge,
in der die Nachrichten kamen. Command-Handler laufen auf eigenen virtuellen Threads.

## Builder

| Methode | Standard | Bedeutung |
|---|---|---|
| `builder(server)` | – | URL des Bridge-Servers (`/admin` usw. wird abgeschnitten, `https://` ergänzt) |
| `name` | `Java client` | Name des Clients |
| `password` | zufällig | ohne `password`, `identitySecret` und `clientIp` ist der Client **kurzlebig** |
| `identitySecret` | – | 32+ Zeichen: **immer dieselbe Client-IP** (auch nach einem Neustart) |
| `clientIp` | – | in einen bestehenden Client einloggen (mit `password`) |
| `pollWaitSeconds` / `pollIntervalMillis` / `maxMessages` | 20 / 50 / 50 | Long Polling |
| `connectTimeout` | 30 s | so lange wartet ein Aufruf auf die Verbindung, dann `NOT_CONNECTED` |
| `autoStart` / `receive` | true / true | sofort verbinden / im Hintergrund empfangen |
| `debug` / `warn` | – / System.err | wohin Meldungen gehen |

**Listener:** `onConnected`, `onDisconnected`, `onClientIpChanged`, `onMessage`, `onEvent`, `onTask` (Commands ohne
Handler – mit `task.respond(...)` antworten), `onResponse`, `onProgress`, `onError`, `onClose` (läuft am Anfang von
`close()`, noch verbunden).

**Methoden:** `send`, `broadcast`, `subscribe` (gibt eine `Subscription` mit `close()`), `publish`, `hostCommand`
(gibt ein `HostedCommand` mit `close()`), `call` / `callAsync` / `callNoWait`, `getCommands`, `createRealm`,
`joinRealm`, `leaveRealm`, `getRealmInfo`, `getMe`, `raw(pfad, body)` für jeden anderen Endpunkt, `connect`,
`waitForConnection`, `close`.

## Test

```
python extensions/java/run_tests.py
```

Kompiliert die Bibliothek und startet einen echten Bridge-Server. Dagegen laufen 39 Checks: JSON, Topics und
Batch-Poll, alle Nachrichten-Modi, Commands (Fehler, Timeout, späte Antwort, 10 parallele Aufrufe),
Session-Erneuerung, feste Identität, Abo vor der Verbindung, Server-Reset (neu registrieren und wiederherstellen),
Aufräumen.
