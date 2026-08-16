"""
Module 09 System Integrity, Threat Scoring Engine, and Full Regression Verification Script.
"""

import json
import unittest
import warnings
from pathlib import Path

# Suppress Starlette test client deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.threat_scoring import ThreatScoringEngine, classify_risk_level, ThreatScoreResult


def run_verification():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 09: THREAT SCORING VERIFICATION")
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

    # 2. Threat Scoring Engine Validation
    print("\n[2] Verifying Threat Scoring Logic & Risk Tiers...")
    tier_checks = (
        classify_risk_level(15) == "LOW" and
        classify_risk_level(30) == "MODERATE" and
        classify_risk_level(50) == "SUSPICIOUS" and
        classify_risk_level(70) == "HIGH" and
        classify_risk_level(90) == "CRITICAL"
    )
    print(f"    - 5 Risk Tiers Boundary Check  : {tier_checks}")

    engine = ThreatScoringEngine()
    empty_res = engine.calculate_score([])
    score_zero_ok = (empty_res.score == 0 and empty_res.risk_level == "LOW")
    print(f"    - Empty Indicators Zero Check  : {score_zero_ok}")

    d = empty_res.to_dict()
    schema_ok = (set(d.keys()) == {"score", "risk_level", "contributions", "top_indicators"})
    print(f"    - Output Schema Contract Match : {schema_ok}")

    # 3. Execute Complete Regression Test Suite (Modules 01 to 09 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01 to 09 & UI)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 72)
    all_ok = all_files_ok and tier_checks and score_zero_ok and schema_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 09 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
