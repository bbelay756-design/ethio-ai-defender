"""
Module 03 System Integrity, PE Static Analysis, and Full Regression Verification Script.
"""

import json
import unittest
import warnings
from pathlib import Path

# Suppress Starlette test client deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.pe_analyzer import PEStaticAnalyzer
from tests.test_pe_analyzer import build_synthetic_pe


def run_verification():
    print("=" * 70)
    print("  ETHIO-AI DEFENDER - MODULE 03: PE STATIC ANALYZER VERIFICATION")
    print("=" * 70)

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

    # 2. PE Static Analyzer Verification
    print("\n[2] Verifying PE Static Analyzer on Synthetic 64-bit and 32-bit Binaries...")
    analyzer = PEStaticAnalyzer()

    # 64-bit Executable
    pe64 = build_synthetic_pe(is_64bit=True, is_dll=False, subsystem=2)
    res64 = analyzer.analyze_bytes(pe64)
    check_64 = (res64.is_valid and res64.type == "PE32+" and res64.architecture == "x64" and res64.file_kind == "EXE")
    print(f"    - 64-bit PE32+ EXE Validation  : {check_64}")

    # 32-bit DLL
    pe32_dll = build_synthetic_pe(is_64bit=False, is_dll=True, subsystem=3)
    res_dll = analyzer.analyze_bytes(pe32_dll)
    check_dll = (res_dll.is_valid and res_dll.type == "PE32" and res_dll.architecture == "x86" and res_dll.file_kind == "DLL")
    print(f"    - 32-bit PE32 DLL Validation   : {check_dll}")

    # Output Schema Contract Validation
    contract = res64.to_dict()
    expected_keys = {
        "type", "architecture", "file_kind", "entry_point",
        "image_base", "number_of_sections", "subsystem",
        "characteristics", "dll_characteristics"
    }
    schema_ok = (set(contract.keys()) == expected_keys)
    print(f"    - Output Schema Contract Match : {schema_ok}")

    # 3. Execute Full Regression Test Suite (Modules 1, 2, 3 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01, 02, 03 & UI)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 70)
    all_ok = all_files_ok and check_64 and check_dll and schema_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 03 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 70)


if __name__ == "__main__":
    run_verification()
