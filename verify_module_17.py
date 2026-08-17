"""
Verification and Test Suite Runner for Module 17: Security Logging & Audit System.
Executes complete regression test suite across Modules 01 through 17.
"""

import sys
import unittest
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from app.audit.events import AuditEventType, AuditResult
from app.audit.sanitizer import scrub_audit_data
from app.audit.logger import audit_logger
from app.db.session import init_db


def run_verification():
    print("=" * 76)
    print("  ETHIO-AI DEFENDER - MODULE 17: SECURITY LOGGING & AUDIT VERIFICATION")
    print("=" * 76)

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
        "audit_security_issues.py",
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
        print(f"    - {f:<40}: {status}")

    # 2. DO NOT LOG Sanitization Verification
    print("\n[2] Verifying DO NOT LOG Sensitive Data Redaction...")
    sensitive_sample = {
        "password": "PlainPassword123!",
        "access_token": "eyJhbGciOiJIUzI1NiJ9.abc.def",
        "api_key": "AIzaSySecretGoogleApiKey",
        "normal_key": "static_pe_analysis"
    }
    scrubbed = scrub_audit_data(sensitive_sample)
    pass_scrubbed = scrubbed["password"] == "[REDACTED]"
    token_scrubbed = scrubbed["access_token"] == "[REDACTED]"
    key_scrubbed = scrubbed["api_key"] == "[REDACTED]"
    normal_kept = scrubbed["normal_key"] == "static_pe_analysis"

    print(f"    - Password Redacted OK        : {pass_scrubbed}")
    print(f"    - Token Redacted OK           : {token_scrubbed}")
    print(f"    - API Key Redacted OK         : {key_scrubbed}")
    print(f"    - Normal Fields Preserved OK  : {normal_kept}")

    # 3. Execute Complete Regression Test Suite (Modules 01 to 17 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01 to 17 & UI)...")
    init_db()
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 76)
    all_ok = all_files_ok and pass_scrubbed and token_scrubbed and key_scrubbed and normal_kept and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 17 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 76)


if __name__ == "__main__":
    run_verification()
