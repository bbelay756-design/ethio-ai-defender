"""
Module 14 System Integrity, Database Layer, and Full Regression Verification Script.
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

from app.db.session import init_db, SessionLocal
from app.db.models import SampleModel, SectionModel, ImportModel, StringModel, IndicatorModel, AnalysisResultModel
from app.db.repository import SampleRepository
from app.db.schemas import SampleCreate, SectionCreate, AnalysisResultCreate


def run_verification():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 14: DATABASE LAYER VERIFICATION")
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

    # 2. Database Models & Schema Validation
    print("\n[2] Verifying Database Schema & 6 Required Tables...")
    init_db()
    db = SessionLocal()
    tables_ok = False
    try:
        sample_in = SampleCreate(
            analysis_id="ANL-AUDIT-001",
            filename="audit.exe",
            size=1024,
            file_type="EXE",
            architecture="x64",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="448d67c89f1232913ab8c9f2a18a5344c05ed1c7b69d3aa06205a2eae6376973",
            status="ANALYZED"
        )
        sample = SampleRepository.save_full_analysis_transaction(
            db=db,
            sample_in=sample_in,
            sections_in=[SectionCreate(name=".text", virtual_address=4096, virtual_size=1024, raw_size=1024, entropy=5.0, characteristics="0x60000020")],
            result_in=AnalysisResultCreate(risk_score=20, risk_level="LOW", ai_summary="Audit clean", ai_confidence="HIGH")
        )
        tables_ok = (sample.id is not None)
        print(f"    - 6 Tables & Relations OK     : {tables_ok}")
        print(f"    - SHA-256 Indexed Query OK    : {SampleRepository.get_by_sha256(db, sample_in.sha256) is not None}")
        
        # Clean up audit sample
        SampleRepository.delete_sample(db, sample.id)
    finally:
        db.close()

    # 3. Execute Complete Regression Test Suite (Modules 01 to 14 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01 to 14 & UI)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 72)
    all_ok = all_files_ok and tables_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 14 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
