"""
Module 11 System Integrity, AI Security Analyst, and Full Regression Verification Script.
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

from app.ai.analyst import AISecurityAnalystService, AIAnalystReport
from app.ai.provider import MockAIProvider, OfflineRuleBasedProvider, GeminiProvider


def run_verification():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 11: AI SECURITY ANALYST VERIFICATION")
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
        "app/ai/__init__.py",
        "app/ai/sanitizer.py",
        "app/ai/grounding.py",
        "app/ai/provider.py",
        "app/ai/analyst.py",
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
        "tests/test_ai_analyst.py",
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

    # 2. AI Security Analyst Validation
    print("\n[2] Verifying AI Security Analyst Logic & Schema...")
    service = AISecurityAnalystService(provider=OfflineRuleBasedProvider())
    mock_evidence = {
        "threat_score": {"score": 55, "risk_level": "SUSPICIOUS"},
        "indicators": {"indicators": []}
    }
    report = service.analyze(mock_evidence, language="en")
    d = report.to_dict()

    expected_keys = {
        "assessment", "confidence", "summary", "key_findings",
        "evidence", "possible_benign_explanations",
        "recommended_investigation", "limitations"
    }
    schema_ok = (set(d.keys()) == expected_keys)
    print(f"    - Output Schema Contract Match: {schema_ok}")
    print(f"    - Grounded Assessment Match   : {report.assessment == 'SUSPICIOUS'}")

    # 3. Execute Complete Regression Test Suite (Modules 01 to 11 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01 to 11 & UI)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 72)
    all_ok = all_files_ok and schema_ok and (report.assessment == 'SUSPICIOUS') and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 11 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
