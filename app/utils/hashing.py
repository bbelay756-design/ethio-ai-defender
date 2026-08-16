"""
Cryptographic Hashing Utilities.
Calculates SHA-256, SHA-1, and MD5 hashes safely using streaming chunks.
"""

import hashlib
from pathlib import Path
from typing import Dict, Union


def compute_hashes_from_bytes(data: bytes) -> Dict[str, str]:
    """
    Computes cryptographic hashes directly from a byte buffer.

    Args:
        data: Raw binary content.

    Returns:
        Dictionary containing md5, sha1, and sha256 hex strings.
    """
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    return {
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
    }


def compute_hashes_from_file(file_path: Union[str, Path], chunk_size: int = 65536) -> Dict[str, str]:
    """
    Computes cryptographic hashes from a file path using streaming chunks
    to maintain a constant, minimal memory footprint.

    Args:
        file_path: Path to the target file.
        chunk_size: Read buffer size in bytes (default: 64KB).

    Returns:
        Dictionary containing md5, sha1, and sha256 hex strings.
    """
    target = Path(file_path)
    if not target.is_file():
        raise FileNotFoundError(f"File not found for hash calculation: {file_path}")

    md5_obj = hashlib.md5()
    sha1_obj = hashlib.sha1()
    sha256_obj = hashlib.sha256()

    with open(target, "rb") as f:
        while chunk := f.read(chunk_size):
            md5_obj.update(chunk)
            sha1_obj.update(chunk)
            sha256_obj.update(chunk)

    return {
        "md5": md5_obj.hexdigest(),
        "sha1": sha1_obj.hexdigest(),
        "sha256": sha256_obj.hexdigest(),
    }
