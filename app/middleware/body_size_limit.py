"""
Pure-ASGI request body size limiter.

Starlette's multipart parser consumes the entire request body (spooling to a
temporary file past a small threshold) before an endpoint function ever runs.
For that reason a size check performed inside an endpoint is too late to bound
memory/disk use. This middleware observes the ASGI ``receive`` channel and
rejects oversized uploads before multipart parsing happens.

Only the protected upload endpoints are bounded; every other request is passed
through untouched. When a body is within the limit it is fully buffered and
replayed to the downstream app so that no data is lost.
"""

import json
from typing import Optional, Sequence, Tuple

UPLOAD_ENDPOINTS: Tuple[Tuple[str, str], ...] = (
    ("/api/files/upload", "POST"),
    ("/api/analyses", "POST"),
    ("/api/dashboard/analyze", "POST"),
)


class BodySizeLimitMiddleware:
    """Reject oversized request bodies for known upload endpoints."""

    def __init__(
        self,
        app,
        max_body_size: int,
        protected_endpoints: Sequence[Tuple[str, str]] = UPLOAD_ENDPOINTS,
    ):
        self.app = app
        self.max_body_size = int(max_body_size)
        self.protected = {
            (str(path).upper(), str(method).upper())
            for path, method in protected_endpoints
        }

    def _is_protected(self, scope) -> bool:
        method = str(scope.get("method", "")).upper()
        path = str(scope.get("path", "")).rstrip("/") or "/"
        return (path.upper(), method) in self.protected

    async def _send_413(self, send) -> None:
        body = json.dumps(
            {"detail": "Request body exceeds the maximum allowed size."}
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or not self._is_protected(scope):
            await self.app(scope, receive, send)
            return

        headers = {
            key.lower(): value for key, value in (scope.get("headers") or [])
        }
        content_length: Optional[bytes] = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except (TypeError, ValueError):
                await self._send_413(send)
                return
            if declared > self.max_body_size:
                await self._send_413(send)
                return

        buffered = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                continue
            buffered.extend(message.get("body", b"") or b"")
            if len(buffered) > self.max_body_size:
                await self._send_413(send)
                return
            more_body = bool(message.get("more_body", False))

        body_bytes = bytes(buffered)
        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {
                    "type": "http.request",
                    "body": body_bytes,
                    "more_body": False,
                }
            return await receive()

        await self.app(scope, replay_receive, send)
