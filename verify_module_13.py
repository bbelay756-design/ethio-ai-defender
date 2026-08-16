"""
Module 13 System Integrity, Report Generator, and Full Regression Verification Script.
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

from app.reports.generator import SecurityReportGenerator
from app.reports.models import EvidenceTier, SecurityReport


def run_verification():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 13: REPORT GENERATOR VERIFICATION")
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

    # 2. Report Generator Validation
    print("\n[2] Verifying 16 Report Sections & Epistemological Model...")
    generator = SecurityReportGenerator()
    mock_evidence = {
        "hashes": {"sha256": "448d67c89f1232913ab8c9f2a18a5344c05ed1c7b69d3aa06205a2eae6376973"},
        "threat_score": {"score": 65, "risk_level": "HIGH"},
        "indicators": {"indicators": []}
    }
    report = generator.generate_report(mock_evidence, language="en")
    d = report.to_dict()

    expected_sections = {
        "1_executive_summary",
        "2_file_information",
        "3_hashes",
        "4_pe_information",
        "5_section_analysis",
        "6_entropy_analysis",
        "7_string_analysis",
        "8_import_api_analysis",
        "9_suspicious_indicators",
        "10_threat_score",
        "11_ethiopian_context",
        "12_ai_assessment",
        "13_evidence",
        "14_possible_benign_explanations",
        "15_recommended_investigation",
        "16_limitations"
    }
    sections_ok = (set(d["sections"].keys()) == expected_sections)
    print(f"    - 16 Required Sections Match  : {sections_ok}")

    # Check evidence classification
    tiers_present = {e.tier for e in report.evidence}
    evidence_ok = (EvidenceTier.OBSERVED in tiers_present and EvidenceTier.RULE_BASED in tiers_present)
    print(f"    - Evidence Model Classification: {evidence_ok}")

    # 3. Execute Complete Regression Test Suite (Modules 01 to 13 & UI)
    print("\n[3] Executing Complete Regression Test Suite (Modules 01 to 13 & UI)...")
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    runner = unittest.TextTestRunner(verbosity=1)
    test_res = runner.run(suite)

    print("\n" + "=" * 72)
    all_ok = all_files_ok and sections_ok and evidence_ok and test_res.wasSuccessful()
    if all_ok:
        print(f"  [VERIFIED] MODULE 13 & ALL PREVIOUS MODULES ARE 100% HEALTHY ({test_res.testsRun} TESTS PASSED)")
    else:
        print("  [FAILED] INTEGRITY OR REGRESSION ISSUES DETECTED")
    print("=" * 72)


if __name__ == "__main__":
    run_verification()
