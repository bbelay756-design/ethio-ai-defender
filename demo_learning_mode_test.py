"""
Live Demonstration Script for Module 12: Cybersecurity Learning Mode.
"""

import sys
import json
import warnings

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.education.learning_mode import LearningModeEngine


def main():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 12: CYBERSECURITY LEARNING MODE DEMO")
    print("=" * 72)

    engine = LearningModeEngine()

    # 1. Educational Explanation for VirtualProtect (English)
    print("\n[Scenario 1] Educational Breakdown for 'VirtualProtect' API (English):")
    lesson_vp = engine.explain_finding(
        finding="VirtualProtect",
        topic="WINDOWS_APIS",
        evidence_found="VirtualProtect imported in KERNEL32.dll alongside VirtualAlloc",
        language="en"
    )
    print(json.dumps(lesson_vp.to_dict(), indent=2))

    # 2. Educational Breakdown for 'VirtualProtect' API (Amharic)
    print("\n[Scenario 2] Educational Breakdown for 'VirtualProtect' API (Amharic - አማርኛ):")
    lesson_vp_am = engine.explain_finding(
        finding="VirtualProtect",
        topic="WINDOWS_APIS",
        evidence_found="በ KERNEL32.dll ውስጥ ከ VirtualAlloc ጋር ተገኝቷል",
        language="am"
    )
    print(json.dumps(lesson_vp_am.to_dict(), indent=2, ensure_ascii=False))

    # 3. Batch Educational Report for a Full Sample
    print("\n[Scenario 3] Generating Multi-Topic Educational Report for Sample Binary:")
    sample_evidence = {
        "file_metadata": {"machine_type": "x64"},
        "sections": {"total_sections": 3, "has_wx_sections": True},
        "entropy": {"file_entropy": 7.42, "classification": "VERY_HIGH"},
        "imports": {"total_imports": 8},
        "indicators": {"total_indicators": 3}
    }
    report = engine.generate_learning_report(sample_evidence, language="en")
    print(f"Total Educational Lessons Generated: {report.total_lessons}")
    for idx, l in enumerate(report.lessons, 1):
        print(f"  {idx}. [{l.topic}] {l.finding}")
        print(f"     -> Beginner: {l.beginner_explanation[:80]}...")
        print(f"     -> Disclaimer: {l.proves_malicious}")

    print("\n" + "=" * 72)
    print("  DEMONSTRATION COMPLETE - SAFE REVERSE-ENGINEERING EDUCATION")
    print("=" * 72)


if __name__ == "__main__":
    main()
