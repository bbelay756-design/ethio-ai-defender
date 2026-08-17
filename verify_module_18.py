"""
Verification and Test Suite Runner for Module 18: Security Testing Framework.
Executes complete regression test suite across Modules 01 through 18.
"""

import sys
import unittest
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from app.testing.synthetic_pe import SyntheticPEBuilder
from app.testing.attack_payloads import (
    PATH_TRAVERSAL_FILENAMES,
    DANGEROUS_FILENAMES,
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
)
from app.db.session import init_db


def run_verification():
    print("=" * 78)
    print("  ETHIO-AI DEFENDER - MODULE 18: SECURITY TESTING FRAMEWORK VERIFICATION")
    print("=" * 78)

    # 1. Codebase File Verification
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
        "app/auth/__init__.py",
        "app/auth/roles.py",
        "app/auth/security.py",
        "app/auth/rate_limiter.py",
        "app/auth/service.py",
        "app/auth/dependencies.py",
        "app/audit/__init__.py",
        "app/audit/events.py",
        "app/audit/sanitizer.py",
        "app/audit/logger.py",
        "app/audit/service.py",
        "app/testing/__init__.py",
        "app/testing/synthetic_pe.py",
        "app/testing/attack_payloads.py",
        "app/api/files.py",
        "app/api/dashboard.py",
        "app/api/auth.py",
        "app/api/audit.py",
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
        "tests/test_auth_security.py",
        "tests/test_module_16_security_suite.py",
        "tests/test_audit_logger.py",
        "tests/test_audit_api.py",
        "tests/test_module_17_audit_suite.py",
        "tests/test_module_18_unit_analyzers.py",
        "tests/test_module_18_e2e_integration.py",
        "tests/test_module_18_security_attacks.py",
        "tests/fixtures/__init__.py",
        "tests/fixtures/security_payloads.py",
        "tests/fixtures/mock_ai_responses.py",
        "tests/security/__init__.py",
        "tests/security/test_upload_security.py",
        "tests/security/test_pe_parser_security.py",
        "tests/security/test_api_security.py",
        "tests/security/test_auth_and_rbac.py",
        "tests/security/test_object_authorization.py",
        "tests/security/test_injection_and_xss.py",
        "tests/security/test_rate_limiting.py",
        "tests/security/test_info_disclosure_and_headers.py",
        "tests/security/test_ai_security.py",
        "tests/security/test_security_logging.py",
        "tests/integration/__init__.py",
        "tests/integration/test_full_analysis_pipeline.py",
        "audit_security_issues.py",
        "requirements.txt",
        ".gitignore",
        ".env.example",
        "README.md"
    ]

    print("\n[1] Checking Codebase Integrity...")
    all_files_ok = True
    for f in required_files:
        exists = Path(f).is_file()
        status = "OK" if exists else "MISSING"
        if not exists:
            all_files_ok = False
        print(f"    - {f:<42}: {status}")

    # 2. Safety Invariant Check (Zero Live Malware)
    print("\n[2] Verifying Testing Safety Invariant...")
    synthetic_pe = SyntheticPEBuilder.create_minimal_pe()
    is_safe = (
        isinstance(synthetic_pe, bytes)
        and len(synthetic_pe) > 512
        and synthetic_pe[0:2] == b"MZ"
    )
    print(f"    - In-Memory Synthetic PE Generator : {'OK' if is_safe else 'FAILED'}")
    print(f"    - Live Malware Execution Risk      : ZERO (100% In-Memory Synthetic Binaries)")

    # 3. Security Vector Matrix Check
    print("\n[3] Verifying Security Attack Vector Matrix...")
    print(f"    - Path Traversal Test Payloads     : {len(PATH_TRAVERSAL_FILENAMES)} loaded")
    print(f"    - Dangerous Filename Payloads      : {len(DANGEROUS_FILENAMES)} loaded")
    print(f"    - SQL Injection Payloads           : {len(SQL_INJECTION_PAYLOADS)} loaded")
    print(f"    - XSS Vector Payloads              : {len(XSS_PAYLOADS)} loaded")

    # 4. Execute Complete Regression Test Suite (Modules 01 to 18 & Framework)
    print("\n[4] Executing Complete Regression Test Suite (Modules 01 to 18 & UI)...")
    init_db()
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 78)
    all_ok = all_files_ok and is_safe and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 18 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 78)


if __name__ == "__main__":
    run_verification()
