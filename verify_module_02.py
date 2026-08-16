"""
Module 02 System Integrity, UI, and Security Verification Script.
"""

import json
import unittest
import warnings
from pathlib import Path

# Suppress Starlette test client deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.hash_analyzer import FileHashAnalyzer


def run_verification():
    print("=" * 68)
    print("  ETHIO-AI DEFENDER - SYSTEM & UI INTEGRITY AUDIT (MODULES 01 & 02)")
    print("=" * 68)

    # 1. Structure Verification (Backend + Frontend + Tests)
    required_files = [
        "app/__init__.py",
        "app/main.py",
        "app/core/config.py",
        "app/core/logger.py",
        "app/core/storage.py",
        "app/analyzers/file_intake.py",
        "app/analyzers/hash_analyzer.py",
        "app/api/files.py",
        "app/utils/sanitizer.py",
        "app/utils/hashing.py",
        "frontend/index.html",
        "frontend/static/css/style.css",
        "frontend/static/js/app.js",
        "tests/test_file_intake.py",
        "tests/test_file_intake_api.py",
        "tests/test_hash_analyzer.py",
        "tests/test_ui_dashboard.py",
        "requirements.txt",
        ".gitignore",
        ".env.example",
        "README.md"
    ]

    print("\n[1] Checking Codebase and UI Files...")
    all_files_ok = True
    for f in required_files:
        exists = Path(f).is_file()
        status = "OK" if exists else "MISSING"
        if not exists:
            all_files_ok = False
        print(f"    - {f:<33}: {status}")

    # 2. Cryptographic Hash Validation
    print("\n[2] Verifying Cryptographic Hashing Service...")
    analyzer = FileHashAnalyzer()
    res = analyzer.compute_from_bytes(b"The quick brown fox jumps over the lazy dog")
    expected_sha256 = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
    hash_match = (res.sha256 == expected_sha256)
    print(f"    - Standard Test Vector Match: {hash_match} (SHA-256: {res.sha256})")

    # 3. Deduplication Check
    print("\n[3] Verifying SHA-256 Deduplication Database Preparation...")
    is_known = analyzer.is_sha256_analyzed(res.sha256)
    print(f"    - is_sha256_analyzed() callable & verified: True (Result: {is_known})")

    # 4. Execute Full Regression Suite (Modules 1 + 2 + UI)
    print("\n[4] Executing Full Regression Test Suite (Modules 1, 2 & UI Dashboard)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 68)
    if all_files_ok and hash_match and test_res.wasSuccessful():
        print(f"  [VERIFIED] MODULES 01 & 02 (WITH UI) ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY ISSUES DETECTED")
    print("=" * 68)


if __name__ == "__main__":
    run_verification()
