"""Test helper: a small reverse proxy that behaves like Tailscale serve/funnel with path mounts.

    python tests/path_proxy.py <port> <strip|keep> /alpha=8262 /beta=8263 ...

Requests go to the mount with the longest matching path (whole segments: /alpha matches /alpha and /alpha/..., not
/alphabet). "strip" removes the mount path before forwarding (what Tailscale does), "keep" forwards the full path.
Unknown paths get 404. Adds X-Forwarded-For like a real proxy. Used by tests/e2e_paths.py.
"""
import sys

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.responses import Response
from starlette.routing import Route

PORT = int(sys.argv[1])
STRIP = sys.argv[2] == "strip"
MOUNTS = sorted(((m.split("=")[0].rstrip("/"), int(m.split("=")[1])) for m in sys.argv[3:]),
                key=lambda item: len(item[0]), reverse=True)
_client = httpx.AsyncClient(timeout=90)
_HOP = {"host", "content-length", "connection", "transfer-encoding", "keep-alive"}


def _pick(path):
    for mount, port in MOUNTS:
        if path == mount or path.startswith(mount + "/"):
            return mount, port
    return None, None


async def proxy(request):
    path = request.url.path
    mount, port = _pick(path)
    if mount is None:
        return Response("no mount", status_code=404)
    target_path = (path[len(mount):] or "/") if STRIP else path
    url = f"http://127.0.0.1:{port}{target_path}"
    if request.url.query:
        url += "?" + request.url.query
    headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP}
    headers["x-forwarded-for"] = request.client.host if request.client else "127.0.0.1"
    answer = await _client.request(request.method, url, content=await request.body(), headers=headers)
    out = {k: v for k, v in answer.headers.items() if k.lower() not in _HOP | {"content-encoding"}}
    return Response(answer.content, status_code=answer.status_code, headers=out)


app = Starlette(routes=[Route("/{path:path}", proxy, methods=["GET", "POST", "HEAD", "PUT", "DELETE"])])

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
