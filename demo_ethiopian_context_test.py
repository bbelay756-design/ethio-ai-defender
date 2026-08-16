"""
Live Demonstration Script for Module 10: Ethiopian Cybersecurity Context Engine.
"""

import sys
import json
import warnings

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.ethiopian_context import EthiopianContextEngine
from app.analyzers.indicator_engine import SuspiciousIndicator
from app.analyzers.string_analyzer import StringAnalysisResult


def main():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 10: ETHIOPIAN CONTEXT ENGINE DEMO")
    print("=" * 72)

    engine = EthiopianContextEngine()

    sample_indicators = [
        SuspiciousIndicator(
            id="IND-MEM-001",
            name="Correlated Memory Staging",
            category="MEMORY",
            severity="HIGH",
            evidence="VirtualAlloc + VirtualProtect",
            confidence=0.85,
            explanation="Dynamic memory allocation and permission alteration."
        ),
        SuspiciousIndicator(
            id="IND-NET-001",
            name="Correlated Network Communication",
            category="NETWORK",
            severity="HIGH",
            evidence="External C2 URL + URLDownloadToFileA",
            confidence=0.82,
            explanation="Remote network communication."
        )
    ]

    mock_strings = StringAnalysisResult(
        domains=["telecom.et", "insa.gov.et"],
        urls=["https://c2.telecom.et/feed.bin"]
    )

    # 1. English Assessment for UNIVERSITY Environment
    print("\n[Scenario 1] English Evaluation for UNIVERSITY Environment:")
    res_uni_en = engine.analyze_context(
        indicators=sample_indicators,
        strings=None,  # No domestic strings
        threat_score=65,
        preferred_environment="UNIVERSITY",
        language="en"
    )
    print(json.dumps(res_uni_en.to_dict(), indent=2))

    # 2. English Assessment with Verified Domestic Artifacts for GOVERNMENT Environment
    print("\n[Scenario 2] Government Sector Evaluation with Verified Domestic Artifacts:")
    res_gov_en = engine.analyze_context(
        indicators=sample_indicators,
        strings=mock_strings,  # Domestic strings present
        threat_score=85,
        preferred_environment="GOVERNMENT",
        language="en"
    )
    print(json.dumps(res_gov_en.to_dict(), indent=2))

    # 3. Amharic Assessment for FINANCIAL Environment
    print("\n[Scenario 3] Amharic (Amharic) Evaluation for FINANCIAL Environment:")
    res_fin_am = engine.analyze_context(
        indicators=sample_indicators,
        strings=None,
        threat_score=75,
        preferred_environment="FINANCIAL",
        language="am"
    )
    print(json.dumps(res_fin_am.to_dict(), indent=2, ensure_ascii=False))

    print("\n" + "=" * 72)
    print("  DEMONSTRATION COMPLETE - LOCALIZED CONTEXTUAL TRIAGE")
    print("=" * 72)


if __name__ == "__main__":
    main()
