"""
Module 07 System Integrity, API Import Analysis, and Full Regression Verification Script.
"""

import json
import unittest
import warnings
from pathlib import Path

# Suppress Starlette test client deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.import_analyzer import WindowsAPIImportAnalyzer, ImportInfo


def run_verification():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 07: IMPORT/API ANALYZER VERIFICATION")
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
        "app/analyzers/import_analyzer.py",
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
        "tests/test_import_analyzer.py",
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

    # 2. API Analyzer Validation
    print("\n[2] Verifying All 11 Required API Categories...")
    analyzer = WindowsAPIImportAnalyzer()

    category_samples = {
        "FILE": "CreateFileA",
        "PROCESS": "CreateProcessA",
        "MEMORY": "VirtualAlloc",
        "NETWORK": "InternetOpenA",
        "REGISTRY": "RegOpenKeyExA",
        "SERVICE": "CreateServiceA",
        "CRYPTOGRAPHY": "CryptEncrypt",
        "SYSTEM_INFORMATION": "GetSystemInfo",
        "GUI": "MessageBoxA",
        "THREAD": "CreateRemoteThread",
        "SECURITY": "AdjustTokenPrivileges",
    }

    all_categories_ok = True
    for expected_cat, api_name in category_samples.items():
        actual_cat, _, _ = analyzer.classify_api(api_name)
        if actual_cat != expected_cat:
            all_categories_ok = False
            print(f"    - Failed category check for {api_name}: expected {expected_cat}, got {actual_cat}")
    print(f"    - 11 Categories Accuracy Check : {all_categories_ok}")

    # Item Schema Contract Check
    sample_info = ImportInfo(
        dll="KERNEL32.dll",
        api="VirtualAlloc",
        category="MEMORY",
        risk_relevance="MEDIUM",
        explanation="Allocates virtual memory."
    )
    d = sample_info.to_dict()
    schema_ok = (set(d.keys()) == {"dll", "api", "category", "risk_relevance", "explanation"})
    print(f"    - Item Output Schema Contract  : {schema_ok}")

    # 3. Execute Complete Regression Test Suite (Modules 01 to 07 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01 to 07 & UI)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 72)
    all_ok = all_files_ok and all_categories_ok and schema_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 07 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
