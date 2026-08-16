"""
Module 06 System Integrity, String Analysis, and Full Regression Verification Script.
"""

import json
import unittest
import warnings
from pathlib import Path

# Suppress Starlette test client deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.string_analyzer import StringAnalyzer


def run_verification():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 06: STRING ANALYZER VERIFICATION")
    print("=" * 72)

    # 1. Structure Verification
    required_files = [
        "app/__init__.py",
        "app/main.py",
        "app/core/config.py",
        "app/core/logger.py",
        "app/core/storage.py",
        "app/analyzers/file_intake.py",
        "app/analyzers/hash_analyzer.py",
        "app/analyzers/pe_analyzer.py",
        "app/analyzers/section_analyzer.py",
        "app/analyzers/entropy_analyzer.py",
        "app/analyzers/string_analyzer.py",
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
        "tests/test_pe_analyzer.py",
        "tests/test_section_analyzer.py",
        "tests/test_entropy_analyzer.py",
        "tests/test_string_analyzer.py",
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
        print(f"    - {f:<33}: {status}")

    # 2. String Analyzer Validation
    print("\n[2] Verifying String Extraction and Categorization...")
    analyzer = StringAnalyzer()

    sample = (
        b"https://cyber.gov.et/feed\x00"
        b"10.0.0.1\x00"
        b"cert.gov.et\x00"
        b"HKLM\\Software\\Test\x00"
        b"cmd.exe /c whoami\x00"
        b"powershell -enc AAAA\x00"
    )
    res = analyzer.analyze_bytes(sample)

    check_cat = (
        len(res.urls) == 1 and
        len(res.ip_addresses) == 1 and
        len(res.registry_paths) == 1 and
        len(res.commands) == 1 and
        len(res.powershell_references) == 1
    )
    print(f"    - Categorization Accuracy Check: {check_cat}")

    # Output Schema Contract Match Check
    d = res.to_dict()
    expected_keys = {
        "total_strings", "urls", "ip_addresses", "domains",
        "registry_paths", "commands", "powershell_references"
    }
    schema_ok = (set(d.keys()) == expected_keys)
    print(f"    - Output Schema Contract Match : {schema_ok}")

    # 3. Execute Complete Regression Test Suite (Modules 01, 02, 03, 04, 05, 06 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01 to 06 & UI)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 72)
    all_ok = all_files_ok and check_cat and schema_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 06 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
