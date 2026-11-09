import html
import os

from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse, Response

from bridge.core import backup, protocol
from bridge.core.status import get_server_status
from bridge.realm import service as realm_service
from bridge.server import url_env

Router = APIRouter()


@Router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root_page() -> str:
    """A small, friendly landing page, so opening the server URL in a browser shows that Bridge is running instead
    of a bare 404. Bridge is an API - everything else lives under /server/status, /client/, /s2s/ etc."""
    ready = backup.is_ready()
    state = "läuft" if ready else "startet…"
    dot = "#2ECC71" if ready else "#F5A623"
    version = protocol.current_protocol.version
    url = url_env.base_root or ""
    # Links with the server's base path (several servers behind one host and port: https://pc.ts.net/momentum)
    base = html.escape(url_env.base_path(), quote=True)
    return f"""<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bridge</title>
<style>
 :root {{ color-scheme: light dark; }}
 * {{ box-sizing: border-box; }}
 body {{ margin:0; min-height:100vh; display:grid; place-items:center;
        font-family:-apple-system,"Segoe UI",Roboto,sans-serif; background:#0E1A33; color:#F7F8FB; }}
 .card {{ text-align:center; padding:40px 20px; }}
 .mark {{ font-weight:700; font-size:48px; letter-spacing:-.03em; color:#3369FF; }}
 .mark b {{ color:#F7F8FB; }}
 .state {{ margin-top:16px; font-size:19px; display:inline-flex; align-items:center; gap:10px; }}
 .dot {{ width:12px; height:12px; border-radius:50%; background:{dot}; box-shadow:0 0 0 4px {dot}22; }}
 .dash {{ display:inline-block; margin-top:22px; padding:11px 20px; border-radius:12px; background:#3369FF; color:#fff;
          font-weight:600; font-size:15px; text-decoration:none; }}
 .dash:hover {{ background:#2a5be6; }}
 .meta {{ margin-top:22px; font-size:13px; opacity:.6; line-height:1.9; word-break:break-all; }}
 a.j {{ color:#6B9BFF; text-decoration:none; }}
 a.j:hover {{ text-decoration:underline; }}
</style></head>
<body><div class="card">
 <div class="mark">br<b>.</b></div>
 <div class="state"><span class="dot"></span>Bridge {state}</div>
 <a class="dash" href="{base}/admin">Server-Dashboard →</a>
 <div class="meta">Protokoll {version}{("<br>" + html.escape(url)) if url else ""}<br>
   <a class="j" href="{base}/server/status">Status (JSON)</a></div>
</div></body></html>"""


# The JavaScript extension, straight from this server: a website next to the server (<server url>/site/, same
# origin) imports it with  import { BridgeClient } from "../server/extensions/bridge.js"  - always the version that
# fits this server, nothing to copy. Only this one fixed file is served.
_JS_EXTENSION = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
                             "extensions", "javascript", "bridge.js")


@Router.get("/server/extensions/bridge.js", include_in_schema=False)
async def javascript_extension():
    if not os.path.isfile(_JS_EXTENSION):
        return Response("// the JavaScript extension is not part of this installation\n", status_code=404,
                        media_type="text/javascript")
    return FileResponse(_JS_EXTENSION, media_type="text/javascript; charset=utf-8",
                        headers={"Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"})


@Router.get("/server/status")
async def get_server_status_dict() -> dict:
    status_msg = "unknown"
    status = get_server_status()
    if status:
        status_msg = status
    return {
        "status": status_msg,
        # False while the server restores its backup after a start (client requests get 503 SERVER_STARTING)
        "ready": backup.is_ready(),
        "url": url_env.base_root,
        "protocol_version": protocol.current_protocol.version,
        "public_realm_address": realm_service.get_public_realm_address(),
        "limits": {
            "chunk_size_kib": protocol.current_protocol.chunk_size_kib,
            "max_fast_message_kib": protocol.current_protocol.max_fast_message_kib,
            "max_safe_message_kib": protocol.current_protocol.max_safe_message_kib,
            "max_wait_seconds": protocol.max_wait_seconds,
            "max_poll_messages": protocol.max_poll_messages,
            # > 0: /message/poll takes "publish" (older servers do not have this key)
            "max_poll_publishes": protocol.max_poll_publishes,
            "session_lifetime_minutes": protocol.session_lifetime_minutes,
        },
    }
