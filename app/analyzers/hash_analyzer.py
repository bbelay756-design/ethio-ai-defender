"""
Module 02: File Hash Analyzer

Responsibility:
Provides a secure, high-performance cryptographic hashing service for PE binaries.
- Calculates SHA-256 (primary unique identifier), SHA-1, and MD5 hashes.
- Uses streaming / chunked binary reads to maintain a constant, minimal memory footprint.
- Never executes, executes via shell, or modifies any analyzed files.
- Resiliently handles missing files, permission errors, and I/O failures.
- Provides SHA-256 deduplication and historical lookup functions.
"""

import hashlib
from pathlib import Path
from typing import Dict, Optional, Union
from dataclasses import dataclass, asdict

from app.core.logger import logger
from app.core.storage import analysis_store, AnalysisStore, FileRecord


class HashAnalyzerError(Exception):
    """Base exception for file hashing errors."""
    pass


class FileNotFoundErrorCustom(HashAnalyzerError):
    """Raised when the target file does not exist on disk."""
    pass


class FileAccessError(HashAnalyzerError):
    """Raised when file reading fails due to permissions or I/O locks."""
    pass


@dataclass
class HashResult:
    """
    Standardized cryptographic hash outcome.
    """
    sha256: str
    sha1: str
    md5: str
    file_size_bytes: int = 0
    is_previously_analyzed: bool = False
    existing_analysis_id: Optional[str] = None

    def to_dict(self) -> Dict[str, str]:
        """Returns the exact hash contract dictionary."""
        return {
            "sha256": self.sha256,
            "sha1": self.sha1,
            "md5": self.md5,
        }


class FileHashAnalyzer:
    """
    Cryptographic Hash Analyzer for static binary analysis.
    Uses chunked streaming to safely hash files of any size without memory exhaustion.
    """

    DEFAULT_CHUNK_SIZE: int = 65536  # 64 KB

    def __init__(self, store: Optional[AnalysisStore] = None):
        self.store = store or analysis_store

    def compute_from_bytes(self, data: bytes) -> HashResult:
        """
        Calculates SHA-256, SHA-1, and MD5 hashes from an in-memory byte buffer.

        Args:
            data: Binary byte buffer.

        Returns:
            HashResult object.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"Expected bytes or bytearray, got {type(data).__name__}")

        sha256_hash = hashlib.sha256(data).hexdigest()
        sha1_hash = hashlib.sha1(data).hexdigest()
        md5_hash = hashlib.md5(data).hexdigest()

        # Deduplication check
        prev_record = self.get_sample_by_sha256(sha256_hash)
        is_known = prev_record is not None
        prev_id = prev_record.analysis_id if prev_record else None

        return HashResult(
            sha256=sha256_hash,
            sha1=sha1_hash,
            md5=md5_hash,
            file_size_bytes=len(data),
            is_previously_analyzed=is_known,
            existing_analysis_id=prev_id,
        )

    def compute_from_file(
        self,
        file_path: Union[str, Path],
        chunk_size: Optional[int] = None
    ) -> HashResult:
        """
        Streams a file from disk in chunks to compute cryptographic hashes with minimal RAM usage.

        Args:
            file_path: Path to the target binary file.
            chunk_size: Stream buffer size in bytes (defaults to 64KB).

        Returns:
            HashResult object.

        Raises:
            FileNotFoundErrorCustom: If target file does not exist.
            FileAccessError: If access is denied or an I/O error occurs.
        """
        target = Path(file_path)
        buffer_size = chunk_size or self.DEFAULT_CHUNK_SIZE

        if buffer_size <= 0:
            buffer_size = self.DEFAULT_CHUNK_SIZE

        # 1. Existence Validation
        if not target.exists():
            logger.error(f"Hash calculation failed: File not found at '{target}'")
            raise FileNotFoundErrorCustom(f"Target file does not exist: {target}")

        if not target.is_file():
            logger.error(f"Hash calculation failed: Target is not a regular file at '{target}'")
            raise FileAccessError(f"Target path is not a file: {target}")

        # 2. Streaming Hash Computation
        sha256_obj = hashlib.sha256()
        sha1_obj = hashlib.sha1()
        md5_obj = hashlib.md5()
        total_bytes = 0

        try:
            with open(target, "rb") as f:
                while chunk := f.read(buffer_size):
                    sha256_obj.update(chunk)
                    sha1_obj.update(chunk)
                    md5_obj.update(chunk)
                    total_bytes += len(chunk)
        except PermissionError as pe:
            logger.error(f"Permission denied while reading file '{target}': {pe}")
            raise FileAccessError(f"Permission denied accessing file: {pe}")
        except (OSError, IOError) as ioe:
            logger.error(f"I/O read error while hashing file '{target}': {ioe}")
            raise FileAccessError(f"I/O error while reading file: {ioe}")

        sha256_hex = sha256_obj.hexdigest()
        sha1_hex = sha1_obj.hexdigest()
        md5_hex = md5_obj.hexdigest()

        # 3. Deduplication Check
        prev_record = self.get_sample_by_sha256(sha256_hex)
        is_known = prev_record is not None
        prev_id = prev_record.analysis_id if prev_record else None

        logger.debug(f"Computed hashes for '{target.name}': SHA-256={sha256_hex}, Size={total_bytes} bytes")

        return HashResult(
            sha256=sha256_hex,
            sha1=sha1_hex,
            md5=md5_hex,
            file_size_bytes=total_bytes,
            is_previously_analyzed=is_known,
            existing_analysis_id=prev_id,
        )

    def is_sha256_analyzed(self, sha256: str) -> bool:
        """
        Determines whether a given SHA-256 hash has already been processed in the system.

        Args:
            sha256: 64-character hexadecimal SHA-256 string.

        Returns:
            True if sample was previously analyzed, False otherwise.
        """
        return self.store.has_sha256(sha256)

    def get_sample_by_sha256(self, sha256: str) -> Optional[FileRecord]:
        """
        Retrieves the prior analysis record matching a given SHA-256 hash.

        Args:
            sha256: 64-character hexadecimal SHA-256 string.

        Returns:
            FileRecord if found, None otherwise.
        """
        return self.store.get_record_by_sha256(sha256)


# Global default instance
hash_analyzer_service = FileHashAnalyzer()


if __name__ == "__main__":
    print("=" * 65)
    print("  ETHIO-AI Defender - Module 02: File Hash Analyzer Demo")
    print("=" * 65)

    analyzer = FileHashAnalyzer()

    # 1. Test In-Memory Buffer Hashing (NIST Standard Test Vector)
    sample_text = b"The quick brown fox jumps over the lazy dog"
    print("\n[1] Hashing standard test vector buffer...")
    res = analyzer.compute_from_bytes(sample_text)
    print(f"SHA-256 : {res.sha256}")
    print(f"SHA-1   : {res.sha1}")
    print(f"MD5     : {res.md5}")
    print(f"Size    : {res.file_size_bytes} bytes")
    print(f"Known?  : {res.is_previously_analyzed}")

    # 2. Test Empty Buffer Hashing
    print("\n[2] Hashing empty buffer (0 bytes)...")
    empty_res = analyzer.compute_from_bytes(b"")
    print(f"SHA-256 : {empty_res.sha256}")
    print(f"SHA-1   : {empty_res.sha1}")
    print(f"MD5     : {empty_res.md5}")

    # 3. Test Deduplication Check
    print("\n[3] Testing Deduplication Lookup for SHA-256...")
    is_known = analyzer.is_sha256_analyzed(res.sha256)
    print(f"Has SHA-256 been analyzed previously? -> {is_known}")

    print("\n" + "=" * 65)
    print("  [SUCCESS] Module 02 File Hash Analyzer demonstration complete.")
    print("=" * 65)

