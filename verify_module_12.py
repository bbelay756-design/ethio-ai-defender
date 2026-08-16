"""
Module 12 System Integrity, Learning Mode Engine, and Full Regression Verification Script.
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

from app.education.topics import EDUCATIONAL_TOPICS_DATABASE
from app.education.learning_mode import LearningModeEngine, EducationalLesson


def run_verification():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 12: LEARNING MODE VERIFICATION")
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
        "app/education/__init__.py",
        "app/education/topics.py",
        "app/education/learning_mode.py",
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
        "tests/test_learning_mode.py",
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

    # 2. Cybersecurity Learning Mode Validation
    print("\n[2] Verifying Learning Mode Topics & Schema Contract...")
    engine = LearningModeEngine()
    topics_ok = (len(EDUCATIONAL_TOPICS_DATABASE) >= 14)
    print(f"    - 14 Required Topics Coverage : {topics_ok} ({len(EDUCATIONAL_TOPICS_DATABASE)} topics)")

    lesson = engine.explain_finding(finding="VirtualProtect", language="en")
    d = lesson.to_dict()

    expected_keys = {
        "topic", "finding", "difficulty_level", "what_is_it",
        "why_it_matters", "evidence_found", "proves_malicious",
        "what_to_learn_next", "beginner_explanation",
        "advanced_explanation", "language"
    }
    schema_ok = (set(d.keys()) == expected_keys)
    disclaimer_ok = ("does not prove malicious behavior" in lesson.proves_malicious.lower())
    print(f"    - Output Schema Contract Match: {schema_ok}")
    print(f"    - Non-Malicious Clause Check  : {disclaimer_ok}")

    # 3. Execute Complete Regression Test Suite (Modules 01 to 12 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01 to 12 & UI)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 72)
    all_ok = all_files_ok and topics_ok and schema_ok and disclaimer_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 12 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
