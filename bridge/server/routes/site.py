"""The reserved path /site - where a host app (e.g. BridgeControll) can mount a website next to this server.

A Bridge server owns its whole URL (the start page, /admin, /server, /client, /message, ...). A host app may put a
website in front of the SAME public URL under /site/ (BridgeControll does that with Tailscale Funnel: "/" goes to
Bridge, "/site" to the website). Two rules make that safe:

  1. /site belongs to the website, never to Bridge: no Bridge route may ever start with /site. create_app() checks
     this at start (check_reserved) - a new router with e.g. /site/... stops the server with a clear error.
  2. If no website is mounted, the request lands here: Bridge answers with a small page "no website assigned"
     instead of a bare 404 - so the "Website" button of the admin dashboard always leads somewhere.

Bridge itself knows nothing about the website (it runs fine without any host app).
"""
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

SITE_PATH = "/site"

Router = APIRouter()

_PAGE = """<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Keine Website</title>
<style>
 :root { color-scheme: light dark; }
 * { box-sizing: border-box; }
 body { margin:0; min-height:100vh; display:grid; place-items:center;
        font-family:-apple-system,"Segoe UI",Roboto,sans-serif; background:#0E1A33; color:#F7F8FB; }
 .card { text-align:center; padding:40px 20px; max-width:480px; }
 .mark { font-weight:700; font-size:48px; letter-spacing:-.03em; color:#3369FF; }
 .mark b { color:#F7F8FB; }
 h1 { font-size:21px; margin:18px 0 8px; }
 p { font-size:15px; line-height:1.6; opacity:.75; margin:0; }
 a { display:inline-block; margin-top:22px; padding:11px 20px; border-radius:12px; background:#3369FF; color:#fff;
     font-weight:600; font-size:15px; text-decoration:none; }
 a:hover { background:#2a5be6; }
</style></head>
<body><div class="card">
 <div class="mark">br<b>.</b></div>
 <h1>Diesem Server ist keine Website zugewiesen</h1>
 <p>Unter /site/ liegt die Website, die der Host (z.&nbsp;B. BridgeControll) diesem Bridge-Server zuweist.
    Gerade ist hier keine eingerichtet &ndash; oder sie ist gestoppt.</p>
 <a href="/admin">&larr; Zum Server-Dashboard</a>
</div></body></html>"""


def _placeholder() -> HTMLResponse:
    return HTMLResponse(_PAGE, status_code=404, headers={"Cache-Control": "no-store"})


@Router.get(SITE_PATH, include_in_schema=False)
async def site_root() -> HTMLResponse:
    return _placeholder()


@Router.get(SITE_PATH + "/{rest:path}", include_in_schema=False)
async def site_any(rest: str) -> HTMLResponse:
    return _placeholder()


def is_reserved(path: str) -> bool:
    """True if a URL path belongs to the website (/site or anything below it)."""
    return path == SITE_PATH or path.startswith(SITE_PATH + "/")


def _paths(item):
    """All route paths of a FastAPI app or APIRouter, with the endpoint. Newer FastAPI (0.16x) keeps included
    routers as one wrapper object in app.routes (with .original_router), so we walk into those."""
    for route in getattr(item, "routes", []) or []:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from _paths(inner)
        elif hasattr(route, "path"):
            yield route.path, getattr(route, "endpoint", None)


def check_reserved(*items) -> None:
    """Stops the start if any Bridge route (other than the placeholder above) uses the reserved /site path.
    Takes the app and/or routers."""
    own = (site_root, site_any)
    for item in items:
        for path, endpoint in _paths(item):
            if endpoint not in own and is_reserved(path):
                raise RuntimeError(f"Bridge route {path!r} uses the reserved path {SITE_PATH} (belongs to the "
                                   f"website of the host app) - give the route another path")
