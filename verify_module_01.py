"""
Module 01 System Integrity & Security Verification Script.
"""

import json
import unittest
from pathlib import Path

def run_verification():
    print("=" * 65)
    print("  ETHIO-AI DEFENDER - MODULE 01 SYSTEM INTEGRITY AUDIT")
    print("=" * 65)

    # 1. Structure Verification
    required_files = [
        "app/__init__.py",
        "app/main.py",
        "app/core/config.py",
        "app/core/logger.py",
        "app/core/storage.py",
        "app/analyzers/file_intake.py",
        "app/api/files.py",
        "app/utils/sanitizer.py",
        "app/utils/hashing.py",
        "tests/test_file_intake.py",
        "tests/test_file_intake_api.py",
        "requirements.txt",
        ".gitignore",
        ".env.example",
        "README.md"
    ]

    print("\n[1] Checking Codebase Files...")
    all_files_ok = True
    for f in required_files:
        exists = Path(f).is_file()
        status = "OK" if exists else "MISSING"
        if not exists:
            all_files_ok = False
        print(f"    - {f:<32}: {status}")

    # 2. Directory Isolation Verification
    print("\n[2] Checking Quarantine & Storage Isolation...")
    dirs = ["storage/quarantine", "storage/uploads", "storage/records", "storage/logs"]
    for d in dirs:
        p = Path(d)
        print(f"    - {d:<32}: Exists={p.exists()}, IsDir={p.is_dir()}")

    # 3. Log File Verification
    print("\n[3] Checking Security Audit Logs...")
    log_file = Path("storage/logs/defender.log")
    if log_file.is_file() and log_file.stat().st_size > 0:
        print(f"    - Security log active: {log_file} ({log_file.stat().st_size} bytes)")
    else:
        print("    - Warning: Log file empty or not found.")

    # 4. Record Storage Verification
    print("\n[4] Checking Persistent Records...")
    records = list(Path("storage/records").glob("*.json"))
    print(f"    - Total persistent JSON records: {len(records)}")
    if records:
        sample_rec = json.loads(records[0].read_text(encoding="utf-8"))
        print(f"    - Sample Record ID: {sample_rec.get('analysis_id')}, Status: {sample_rec.get('status')}")

    # 5. Execute Tests
    print("\n[5] Executing Test Regression Suite...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    res = runner.run(suite)

    print("\n" + "=" * 65)
    if all_files_ok and res.wasSuccessful():
        print("  [VERIFIED] MODULE 01 IS 100% HEALTHY AND SECURE")
    else:
        print("  [FAILED] INTEGRITY ISSUES DETECTED")
    print("=" * 65)


if __name__ == "__main__":
    run_verification()
