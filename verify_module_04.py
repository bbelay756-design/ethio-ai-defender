"""
Module 04 System Integrity, Section Analysis, and Full Regression Verification Script.
"""

import json
import unittest
import warnings
from pathlib import Path

# Suppress Starlette test client deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.section_analyzer import PESectionAnalyzer
from tests.test_section_analyzer import build_custom_sections_pe


def run_verification():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 04: PE SECTION ANALYZER VERIFICATION")
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

    # 2. Section Analyzer Validation
    print("\n[2] Verifying PE Section Analyzer...")
    analyzer = PESectionAnalyzer()

    # Test clean binary
    clean_spec = [
        (".text", 0x1000, 0x1000, 0x60000020),
        (".data", 0x1000, 0x1000, 0xC0000040)
    ]
    pe_clean = build_custom_sections_pe(clean_spec)
    res_clean = analyzer.analyze_bytes(pe_clean)
    check_clean = (res_clean.is_valid and res_clean.total_sections == 2 and not res_clean.has_wx_sections)
    print(f"    - Clean Sections Analysis Check: {check_clean}")

    # Test anomalous W+X binary
    wx_spec = [
        (".text", 0x1000, 0x1000, 0x60000020),
        (".wx_sec", 0x1000, 0x1000, 0xE0000020)
    ]
    pe_wx = build_custom_sections_pe(wx_spec)
    res_wx = analyzer.analyze_bytes(pe_wx)
    check_wx = (res_wx.is_valid and res_wx.has_wx_sections and res_wx.anomalous_sections_count >= 1)
    print(f"    - W+X Anomaly Detection Check  : {check_wx}")

    # Output Schema Contract Validation
    sec_dict = res_clean.sections[0].to_dict()
    expected_sec_keys = {
        "name", "virtual_address", "virtual_size", "raw_size",
        "readable", "writable", "executable", "indicators"
    }
    schema_ok = (set(sec_dict.keys()) == expected_sec_keys)
    print(f"    - Output Schema Contract Match : {schema_ok}")

    # 3. Execute Complete Regression Test Suite (Modules 01, 02, 03, 04 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01, 02, 03, 04 & UI)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 72)
    all_ok = all_files_ok and check_clean and check_wx and schema_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 04 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
