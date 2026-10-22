"""
P1 / SEC-05 regression tests: bounded upload request bodies.

Verifies:
  - the ASGI BodySizeLimitMiddleware rejects oversized upload bodies with 413
    BEFORE the downstream application (and therefore multipart parsing) runs;
  - bodies are bounded even when no Content-Length header is present
    (chunked transfer);
  - within-limit bodies are replayed losslessly to the downstream app;
  - non-upload paths are never buffered or rejected by the middleware;
  - read_upload_bounded raises HTTP 413 once its byte ceiling is exceeded.
"""

import unittest

from fastapi import HTTPException

from app.middleware.body_size_limit import BodySizeLimitMiddleware
from app.utils.upload_guard import read_upload_bounded


LIMIT = 100
PROTECTED_PATH = "/api/files/upload"
UNPROTECTED_PATH = "/api/auth/login"


class _RecordingDownstream:
    """Minimal ASGI app that records the body it receives and returns 200."""

    def __init__(self):
        self.called = False
        self.body = b""

    async def __call__(self, scope, receive, send):
        self.called = True
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            self.body += message.get("body", b"") or b""
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


async def _invoke(middleware, scope, messages):
    sent = []
    iterator = iter(messages)

    async def receive():
        return next(iterator, {"type": "http.request", "body": b"", "more_body": False})

    async def send(message):
        sent.append(message)

    await middleware(scope, receive, send)
    return sent


def _scope(path=PROTECTED_PATH, method="POST", headers=None):
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers or [],
    }


def _status(sent):
    for message in sent:
        if message["type"] == "http.response.start":
            return message["status"]
    return None


def _request(body, more_body=False):
    return {"type": "http.request", "body": body, "more_body": more_body}


class TestBodySizeLimitMiddleware(unittest.IsolatedAsyncioTestCase):
    """Direct ASGI-level tests for the request body size limiter."""

    async def test_declared_content_length_over_limit_rejected(self):
        downstream = _RecordingDownstream()
        middleware = BodySizeLimitMiddleware(downstream, max_body_size=LIMIT)
        scope = _scope(headers=[(b"content-length", str(LIMIT + 1).encode())])

        sent = await _invoke(middleware, scope, [_request(b"x" * (LIMIT + 1))])

        self.assertEqual(_status(sent), 413)
        self.assertFalse(downstream.called, "Downstream must not run for oversized body.")

    async def test_chunked_body_over_limit_rejected_without_content_length(self):
        downstream = _RecordingDownstream()
        middleware = BodySizeLimitMiddleware(downstream, max_body_size=LIMIT)
        scope = _scope()  # no content-length header

        sent = await _invoke(
            middleware,
            scope,
            [_request(b"a" * 60, more_body=True), _request(b"b" * 60, more_body=False)],
        )

        self.assertEqual(_status(sent), 413)
        self.assertFalse(downstream.called)

    async def test_within_limit_body_replayed_intact(self):
        downstream = _RecordingDownstream()
        middleware = BodySizeLimitMiddleware(downstream, max_body_size=LIMIT)
        payload = b"hello-world-payload"
        scope = _scope(headers=[(b"content-length", str(len(payload)).encode())])

        sent = await _invoke(middleware, scope, [_request(payload)])

        self.assertEqual(_status(sent), 200)
        self.assertTrue(downstream.called)
        self.assertEqual(downstream.body, payload)

    async def test_chunked_within_limit_reassembled(self):
        downstream = _RecordingDownstream()
        middleware = BodySizeLimitMiddleware(downstream, max_body_size=LIMIT)
        scope = _scope()

        sent = await _invoke(
            middleware,
            scope,
            [_request(b"aaaa", more_body=True), _request(b"bbbb", more_body=False)],
        )

        self.assertEqual(_status(sent), 200)
        self.assertEqual(downstream.body, b"aaaabbbb")

    async def test_unprotected_path_not_bounded(self):
        downstream = _RecordingDownstream()
        middleware = BodySizeLimitMiddleware(downstream, max_body_size=LIMIT)
        oversized = b"y" * (LIMIT * 5)
        scope = _scope(path=UNPROTECTED_PATH, headers=[(b"content-length", str(len(oversized)).encode())])

        sent = await _invoke(middleware, scope, [_request(oversized)])

        self.assertEqual(_status(sent), 200)
        self.assertTrue(downstream.called)
        self.assertEqual(downstream.body, oversized)

    async def test_invalid_content_length_rejected(self):
        downstream = _RecordingDownstream()
        middleware = BodySizeLimitMiddleware(downstream, max_body_size=LIMIT)
        scope = _scope(headers=[(b"content-length", b"not-a-number")])

        sent = await _invoke(middleware, scope, [_request(b"")])

        self.assertEqual(_status(sent), 413)
        self.assertFalse(downstream.called)


class _FakeUploadFile:
    """Async file-like object that yields fixed data in chunks."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    async def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            chunk = self._data[self._pos:]
        else:
            chunk = self._data[self._pos:self._pos + size]
        self._pos += len(chunk)
        return chunk


class TestReadUploadBounded(unittest.IsolatedAsyncioTestCase):
    """Unit tests for the endpoint-level bounded read helper."""

    async def test_under_limit_returns_bytes(self):
        data = b"small payload"
        result = await read_upload_bounded(_FakeUploadFile(data), max_bytes=1024, chunk_size=4)
        self.assertEqual(result, data)

    async def test_over_limit_raises_413(self):
        data = b"z" * 500
        with self.assertRaises(HTTPException) as ctx:
            await read_upload_bounded(_FakeUploadFile(data), max_bytes=100, chunk_size=16)
        self.assertEqual(ctx.exception.status_code, 413)

    async def test_exact_limit_allowed(self):
        data = b"q" * 100
        result = await read_upload_bounded(_FakeUploadFile(data), max_bytes=100, chunk_size=8)
        self.assertEqual(result, data)


if __name__ == "__main__":
    unittest.main()
