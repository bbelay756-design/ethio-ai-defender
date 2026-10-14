"""
Module 20 System Integrity and Full Regression Verification Script:
Ghidra Headless Static Reverse-Engineering Integration.
"""

import unittest
import warnings
from pathlib import Path

# Suppress Starlette test client deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.core.config import settings
from app.analyzers.ghidra_analyzer import ghidra_analyzer_service, GhidraAnalyzerService
from app.db.session import init_db, engine
from sqlalchemy import inspect


def run_verification():
    print("=" * 78)
    print("  ETHIO-AI DEFENDER - MODULE 20: GHIDRA HEADLESS INTEGRATION VERIFICATION")
    print("=" * 78)

    # 1. Structure Verification
    required_files = [
        "app/analyzers/ghidra_analyzer.py",
        "ghidra_scripts/dump_program_info.py",
        "tests/test_ghidra_analyzer.py",
        "verify_module_20.py",
    ]

    print("\n[1] Checking Module 20 Codebase Files...")
    all_files_ok = True
    for f in required_files:
        exists = Path(f).is_file()
        status = "OK" if exists else "MISSING"
        if not exists:
            all_files_ok = False
        print(f"    - {f:<42}: {status}")

    # 2. Ghidra availability reporting (graceful degradation)
    print("\n[2] Verifying Ghidra Availability Reporting...")
    available, reason = ghidra_analyzer_service.is_available()
    print(f"    - Configured GHIDRA_HOME : {settings.GHIDRA_HOME or '(not set)'}")
    print(f"    - Integration Available  : {available}")
    print(f"    - Status Message         : {reason[:70]}")
    availability_ok = isinstance(available, bool) and bool(reason)

    # 3. Structured result contract
    print("\n[3] Verifying Structured Result Contract...")
    svc = GhidraAnalyzerService(ghidra_home=None, workspace_dir=settings.GHIDRA_WORKSPACE_DIR)
    res = svc.analyze_file(None, analysis_id="ANL-CONTRACT")
    d = res.to_dict()
    contract_keys = {
        "available", "status", "message", "program_name", "language_id",
        "processor", "compiler", "image_base", "entry_point", "function_count",
        "import_count", "export_count", "string_count", "relationship_count",
        "functions", "imports", "exports", "strings", "relationships", "errors",
    }
    contract_ok = set(d.keys()) == contract_keys
    print(f"    - Result Schema Match     : {contract_ok}")
    print(f"    - Graceful Status         : {res.status}")

    # 4. Database tables
    print("\n[4] Verifying Database Tables...")
    init_db()
    tables = set(inspect(engine).get_table_names())
    ghidra_tables_ok = {"ghidra_analysis", "ghidra_functions"}.issubset(tables)
    print(f"    - ghidra_analysis table   : {'OK' if 'ghidra_analysis' in tables else 'MISSING'}")
    print(f"    - ghidra_functions table  : {'OK' if 'ghidra_functions' in tables else 'MISSING'}")

    # 5. Execute Complete Regression Test Suite
    print("\n[5] Executing Complete Regression Test Suite...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 78)
    all_ok = all_files_ok and availability_ok and contract_ok and ghidra_tables_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 20 INTEGRATION IS HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 78)


if __name__ == "__main__":
    run_verification()
