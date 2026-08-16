"""
Module 10 System Integrity, Ethiopian Context Engine, and Full Regression Verification Script.
"""

import sys
import json
import unittest
import warnings
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Suppress Starlette test client deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.ethiopian_context import (
    EthiopianContextEngine,
    ContextAssessment,
    ENVIRONMENTS,
)


def run_verification():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 10: ETHIOPIAN CONTEXT VERIFICATION")
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
        "app/analyzers/threat_scoring.py",
        "app/analyzers/ethiopian_context.py",
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
        "tests/test_threat_scoring.py",
        "tests/test_ethiopian_context.py",
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
        print(f"    - {f:<35}: {status}")

    # 2. Ethiopian Context Engine Validation
    print("\n[2] Verifying Ethiopian Context Engine...")
    engine = EthiopianContextEngine()
    env_count_ok = (len(ENVIRONMENTS) == 7)
    print(f"    - 7 Target Environments Check : {env_count_ok} ({len(ENVIRONMENTS)} sectors)")

    test_assessment = ContextAssessment(
        environment="UNIVERSITY",
        relevance="MEDIUM",
        reason="Academic lab computer risk.",
        language="en"
    )
    d = test_assessment.to_dict()
    schema_ok = (set(d.keys()) == {"environment", "relevance", "reason", "language"})
    print(f"    - Output Schema Contract Match: {schema_ok}")

    # 3. Execute Complete Regression Test Suite (Modules 01 to 10 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01 to 10 & UI)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 72)
    all_ok = all_files_ok and env_count_ok and schema_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 10 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
