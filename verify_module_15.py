"""
Module 15 System Integrity, Defensive Security Dashboard, and Full Regression Verification Script.
"""

import sys
import json
import unittest
import warnings
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Suppress Starlette test client deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.main import app
from app.core.config import BASE_DIR
from app.db.session import init_db


def run_verification():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 15: DEFENSIVE SECURITY DASHBOARD VERIFICATION")
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
        "app/reports/__init__.py",
        "app/reports/models.py",
        "app/reports/renderers.py",
        "app/reports/generator.py",
        "app/db/__init__.py",
        "app/db/session.py",
        "app/db/models.py",
        "app/db/schemas.py",
        "app/db/repository.py",
        "app/api/files.py",
        "app/api/dashboard.py",
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
        "tests/test_report_generator.py",
        "tests/test_database.py",
        "tests/test_dashboard_ui.py",
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

    # 2. Check 8 Required Views in frontend/index.html
    print("\n[2] Verifying 8 Dedicated Dashboard Views & Localization UI...")
    index_content = (BASE_DIR / "frontend" / "index.html").read_text(encoding="utf-8")
    views = [
        "view-home",
        "view-analysis",
        "view-pe-analysis",
        "view-imports",
        "view-strings",
        "view-indicators",
        "view-ai-analyst",
        "view-learning"
    ]
    views_ok = all(f'id="{v}"' in index_content for v in views)
    lang_ok = ('id="lang-btn-en"' in index_content and 'id="lang-btn-am"' in index_content)
    print(f"    - 8 Dedicated View Containers OK : {views_ok}")
    print(f"    - Dual Language Selector UI OK   : {lang_ok}")

    # 3. Execute Complete Regression Test Suite (Modules 01 to 15 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01 to 15 & UI)...")
    init_db()
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 72)
    all_ok = all_files_ok and views_ok and lang_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 15 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
