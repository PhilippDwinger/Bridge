# Bridge Extensions

Alle Extensions machen die Verbindung selbst: Registrieren/Einloggen, Session erneuern, nach einem Bridge-Neustart
ohne Backup neu registrieren und Realms/Topics/Commands wiederherstellen, im Hintergrund pollen, safe/compressed
empfangen. Server-URLs dürfen einen Pfad haben (`https://pc.ts.net:10000/momentum` – mehrere Server pro Host und Port).

## Roblox
- Folder: [extensions/roblox](extensions/roblox/README.md) – ModuleScript `Bridge` (Luau, server only)
- Status: Works (tested in Roblox Studio)
- Test: `python extensions/roblox/tests/run_tests.py lune`

## Java
- Folder: [extensions/java](extensions/java/README.md) – `BridgeClient` (Java 21+, no dependencies)
- Status: Works (Minecraft mod)
- Test: `python extensions/java/run_tests.py`

## Python
- Folder: [extensions/python](extensions/python/README.md) – `bridge_client.py` (Python 3.10+, standard library only)
- Status: Ready to use (live test against a real server)
- Test: `python extensions/python/run_tests.py`

## JavaScript (browser + Node 18+)
- Folder: [extensions/javascript](extensions/javascript/README.md) – `bridge.js` (ES module, no dependencies)
- Every Bridge server serves it itself at `<server url>/server/extensions/bridge.js` – a website under
  `<server url>/site/` imports `../server/extensions/bridge.js` and connects with `BridgeClient.serverFromPage()`
- Status: Ready to use (live test in Node + Chromium)
- Test: `python extensions/javascript/run_tests.py`
