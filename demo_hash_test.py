"""
Live End-to-End Demonstration for Module 02: File Hash Analyzer.
"""

import os
import tempfile
from pathlib import Path
from app.analyzers.hash_analyzer import (
    FileHashAnalyzer,
    FileNotFoundErrorCustom,
    FileAccessError,
)
from app.core.storage import AnalysisStore, FileRecord


def run_live_test():
    print("=" * 70)
    print("  [+] ETHIO-AI DEFENDER - MODULE 02 LIVE TEST DEMONSTRATION")
    print("=" * 70)

    analyzer = FileHashAnalyzer()

    # 1. Test In-Memory Buffer Hashing (NIST Standard Test Vector)
    print("\n[1] Testing Standard NIST Test Vector Hashing (In-Memory)...")
    sample_text = b"The quick brown fox jumps over the lazy dog"
    res = analyzer.compute_from_bytes(sample_text)
    print(f"    Input Payload : {sample_text.decode('ascii')}")
    print(f"    SHA-256 Hash  : {res.sha256}")
    print(f"    SHA-1 Hash    : {res.sha1}")
    print(f"    MD5 Hash      : {res.md5}")
    print(f"    Payload Size  : {res.file_size_bytes} bytes")
    print(f"    Contract Dict : {res.to_dict()}")

    # 2. Test Empty File Hashing
    print("\n[2] Testing Empty Data (0-byte) Hashing...")
    empty_res = analyzer.compute_from_bytes(b"")
    print(f"    SHA-256 : {empty_res.sha256}")
    print(f"    SHA-1   : {empty_res.sha1}")
    print(f"    MD5     : {empty_res.md5}")

    # 3. Test Chunked Streaming on Disk
    print("\n[3] Testing Chunked Streaming on Disk (128 KB synthetic file)...")
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        # Write 128KB in a file
        payload = b"ETHIO_DEFENDER_STREAMING_SECURITY_CHECK_2026!" * 3000
        tmp.write(payload)
        tmp_path = Path(tmp.name)

    try:
        # Compute using 8KB chunk size
        stream_res = analyzer.compute_from_file(tmp_path, chunk_size=8192)
        print(f"    Temporary File   : {tmp_path.name}")
        print(f"    Calculated Size  : {stream_res.file_size_bytes} bytes (~{stream_res.file_size_bytes // 1024} KB)")
        print(f"    Streamed SHA-256 : {stream_res.sha256}")
        print(f"    Streamed SHA-1   : {stream_res.sha1}")
        print(f"    Streamed MD5     : {stream_res.md5}")
    finally:
        if tmp_path.exists():
            os.unlink(tmp_path)

    # 4. Test Error Handling (Missing File)
    print("\n[4] Testing Error Handling for Missing File...")
    fake_path = Path("storage/quarantine/non_existent_file_999.bin")
    try:
        analyzer.compute_from_file(fake_path)
    except FileNotFoundErrorCustom as err:
        print(f"    Safely Caught Expected Error : {err}")

    # 5. Test SHA-256 Deduplication Database Lookup
    print("\n[5] Testing SHA-256 Deduplication Database Preparation...")
    target_hash = "3aca6c684a39c9ecaf3de614663d9c2240be7869d5ed5642b49140034ca9db9e"
    is_analyzed = analyzer.is_sha256_analyzed(target_hash)
    sample_rec = analyzer.get_sample_by_sha256(target_hash)
    print(f"    Queried SHA-256 : {target_hash}")
    print(f"    Is Analyzed?    : {is_analyzed}")
    if sample_rec:
        print(f"    Existing Record : ID={sample_rec.analysis_id}, Filename={sample_rec.filename}, Status={sample_rec.status}")

    print("\n" + "=" * 70)
    print("  [SUCCESS] ALL MODULE 02 LIVE TESTS COMPLETED")
    print("=" * 70)


if __name__ == "__main__":
    run_live_test()
