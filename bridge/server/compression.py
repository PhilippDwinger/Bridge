"""Small data on the wire for every client and server.

- Answers from 1 KiB on are gzip compressed if the client sends "Accept-Encoding: gzip" (most HTTP clients do).
- Requests may be compressed: "Content-Encoding: gzip" (or deflate) - Bridge unpacks them before reading.
  Roblox: HttpService:PostAsync(url, body, Enum.HttpContentType.ApplicationJson, true) compresses with gzip.
- Server to server requests from 4 KiB on are sent gzip compressed.
"""
import asyncio
import zlib

from bridge.core import protocol

GZIP_MIN_RESPONSE_BYTES = 1024
GZIP_MIN_REQUEST_BYTES = 4096


BACKUP_STORE_PATH = "/s2s/backup/store"


def max_request_bytes(path=None):
    """Biggest JSON body we accept after unpacking: a compressed message may have up to 8 MiB + overhead.
    A backup of another server may be as big as max_backup_mb (otherwise backups between ~17 and 50 MB were lost)."""
    limit = protocol.max_compressed_original_kib * 1024 * 2 + 1024 * 1024
    if path == BACKUP_STORE_PATH:
        limit = max(limit, protocol.max_backup_mb * 1024 * 1024 + 1024 * 1024)
    return limit


async def _read_body(receive, limit):
    """The whole body, or None if it is bigger than limit. Collects the parts in a list and joins them once
    (adding bytes to bytes again and again costs quadratic time with many small parts)."""
    parts, size, more = [], 0, True
    while more:
        message = await receive()
        part = message.get("body", b"")
        size += len(part)
        if size > limit:
            return None
        parts.append(part)
        more = message.get("more_body", False)
    return b"".join(parts)


class GzipRequestMiddleware:
    """Size limit for every request body, and unpacking of bodies with Content-Encoding gzip / deflate
    (with a limit after unpacking against "zip bombs")."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = [(name, value) for name, value in scope["headers"]]
        limit = max_request_bytes(scope.get("path"))
        length = next((value for name, value in headers if name == b"content-length"), None)
        if length is not None and (not length.isdigit() or int(length) > limit):
            return await _plain_error(send, 413, "Request too large")
        encoding = next((value.decode("latin-1").strip().lower() for name, value in headers if name == b"content-encoding"), "")
        if encoding not in ("gzip", "deflate"):
            if length is not None:
                return await self.app(scope, receive, send)
            # No Content-Length (chunked): count while reading, stop at the limit
            body = await _read_body(receive, limit)
            if body is None:
                return await _plain_error(send, 413, "Request too large")
            return await self.app(scope, _replay(body, receive), send)
        body = await _read_body(receive, limit)
        if body is None:
            return await _plain_error(send, 413, "Request too large")
        def unpack():
            inflater = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS)
            data = inflater.decompress(body, limit + 1)
            return None if len(data) > limit or inflater.unconsumed_tail else data

        try:
            # Big bodies (backups) are unpacked in a thread - the server keeps answering meanwhile
            data = await asyncio.to_thread(unpack) if len(body) > 1024 * 1024 else unpack()
        except zlib.error:
            return await _plain_error(send, 400, "Broken compressed request body")
        if data is None:
            return await _plain_error(send, 413, "Request too large after unpacking")
        headers = [(name, value) for name, value in headers if name not in (b"content-encoding", b"content-length")]
        headers.append((b"content-length", str(len(data)).encode()))
        await self.app(dict(scope, headers=headers), _replay(data, receive), send)


def _replay(data, receive):
    sent = False

    async def replay_receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": data, "more_body": False}
        return await receive()

    return replay_receive


async def _plain_error(send, status, text):
    body = ('{"detail": {"error": "CLIENT_PAYLOAD_ERROR", "name": "Client Payload Error", "message": "' + text + '"}}').encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})
