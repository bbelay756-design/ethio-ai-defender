"""
Module 05 System Integrity, Shannon Entropy, and Full Regression Verification Script.
"""

import json
import unittest
import warnings
from pathlib import Path

# Suppress Starlette test client deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.entropy_analyzer import EntropyAnalyzer, calculate_shannon_entropy
from tests.test_section_analyzer import build_custom_sections_pe


def run_verification():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 05: ENTROPY ANALYZER VERIFICATION")
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

    # 2. Entropy Analyzer Validation
    print("\n[2] Verifying Mathematical Shannon Entropy Calculations...")
    analyzer = EntropyAnalyzer()

    # Zero entropy check
    h_zero = analyzer.compute_entropy(b"\x00" * 1024)
    check_zero = (abs(h_zero - 0.0) < 1e-5 and analyzer.classify(h_zero) == "LOW")
    print(f"    - Zero Entropy Check (H=0.0)   : {check_zero}")

    # Max entropy check (Uniform 256 byte distribution)
    h_max = analyzer.compute_entropy(bytes(range(256)) * 4)
    check_max = (abs(h_max - 8.0) < 1e-5 and analyzer.classify(h_max) == "VERY_HIGH")
    print(f"    - Max Entropy Check (H=8.0)    : {check_max}")

    # Section Entropy & Output Contract Check
    spec = [(".text", 0x1000, 0x200, 0x60000020)]
    pe_bytes = build_custom_sections_pe(spec)
    res_pe = analyzer.analyze_bytes(pe_bytes)
    d = res_pe.to_dict()
    schema_ok = ("file_entropy" in d and "sections" in d and len(d["sections"]) >= 1)
    if schema_ok:
        sec_d = d["sections"][0]
        schema_ok = (set(sec_d.keys()) == {"name", "entropy", "classification"})
    print(f"    - Output Schema Contract Match : {schema_ok}")

    # 3. Execute Complete Regression Test Suite (Modules 01, 02, 03, 04, 05 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01, 02, 03, 04, 05 & UI)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 72)
    all_ok = all_files_ok and check_zero and check_max and schema_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 05 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
