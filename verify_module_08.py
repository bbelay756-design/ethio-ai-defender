"""
Module 08 System Integrity, Indicator Engine, and Full Regression Verification Script.
"""

import json
import unittest
import warnings
from pathlib import Path

# Suppress Starlette test client deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.indicator_engine import (
    SuspiciousIndicatorEngine,
    SuspiciousIndicator,
    AnalysisContext,
)


def run_verification():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 08: INDICATOR ENGINE VERIFICATION")
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
        "app/analyzers/indicator_engine.py",
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
        "tests/test_indicator_engine.py",
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

    # 2. Indicator Engine Validation
    print("\n[2] Verifying Suspicious Indicator Engine Rules & Schema...")
    engine = SuspiciousIndicatorEngine()
    rules_ok = (len(engine.rules) >= 10)
    print(f"    - 10 Configured Categories Check: {rules_ok} ({len(engine.rules)} active rules)")

    sample_ind = SuspiciousIndicator(
        id="IND-001",
        name="Sample Indicator",
        category="MEMORY",
        severity="HIGH",
        evidence="VirtualAlloc + VirtualProtect",
        confidence=0.85,
        explanation="Static allocation & protection manipulation."
    )
    d = sample_ind.to_dict()
    schema_ok = (set(d.keys()) == {"id", "name", "category", "severity", "evidence", "confidence", "explanation"})
    print(f"    - Indicator Output Contract Match: {schema_ok}")

    # 3. Execute Complete Regression Test Suite (Modules 01 to 08 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01 to 08 & UI)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 72)
    all_ok = all_files_ok and rules_ok and schema_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 08 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
