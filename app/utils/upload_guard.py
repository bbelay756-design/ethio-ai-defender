"""
Defense-in-depth helper for reading uploaded files with a hard byte ceiling.

The ASGI middleware in ``app.middleware.body_size_limit`` already rejects
oversized request bodies before multipart parsing, but endpoints should still
never buffer an unbounded amount of data. This helper reads an ``UploadFile``
in chunks and raises HTTP 413 as soon as the configured maximum is exceeded.
"""

from fastapi import HTTPException, status

DEFAULT_CHUNK_SIZE = 1024 * 1024


async def read_upload_bounded(file, max_bytes: int, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    """Read ``file`` up to ``max_bytes``; raise HTTP 413 if it is larger.

    Reading is done in ``chunk_size`` increments so that an unexpectedly large
    payload cannot be fully materialized in memory before being rejected.
    """
    if max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")

    buffer = bytearray()
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        buffer.extend(chunk)
        if len(buffer) > max_bytes:
            limit_mb = max_bytes // (1024 * 1024)
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=(
                    "Uploaded file exceeds the maximum allowed size of "
                    f"{limit_mb} MB."
                ),
            )
    return bytes(buffer)
