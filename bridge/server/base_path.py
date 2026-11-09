"""Several Bridge servers behind one host and port, each under its own path.

A server's public URL may have a path, e.g. https://pc.ts.net:10000/momentum (BridgeControll mounts every server under
/<server id> on a Tailscale Funnel port). A request for that server then looks like one of these, depending on the
proxy in front:

  - path stripped (Tailscale serve/funnel, most reverse proxies with a prefix): /admin, /client/login ...
  - path kept (a proxy that forwards the full path):                            /momentum/admin, /momentum/client/login

Bridge accepts both: this ASGI middleware removes the server's own base path from the front of a request path, so the
routes (and every other middleware) always see /admin, /client/login ... - exactly as on a server without a path.
Requests straight to the local port (other servers of the same PC, BridgeControll) work with or without the prefix.

It is a pure ASGI middleware (no response buffering), so long polls and streamed answers are untouched.
"""
from bridge.server import url_env


class BasePathMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") in ("http", "websocket"):
            base = url_env.base_path()
            path = scope.get("path") or "/"
            if base and (path == base or path.startswith(base + "/")):
                rest = path[len(base):] or "/"
                scope = dict(scope, path=rest)
                raw = scope.get("raw_path")
                if isinstance(raw, (bytes, bytearray)):
                    raw_base = base.encode("utf-8")
                    if raw.startswith(raw_base):
                        scope["raw_path"] = bytes(raw[len(raw_base):]) or b"/"
            elif not path:
                scope = dict(scope, path="/")
        await self.app(scope, receive, send)
