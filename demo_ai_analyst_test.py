"""
Live Demonstration Script for Module 11: AI Security Analyst.
"""

import sys
import json
import warnings

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.ai.analyst import AISecurityAnalystService
from app.ai.provider import OfflineRuleBasedProvider, MockAIProvider
from app.ai.sanitizer import sanitize_evidence_payload


def main():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 11: AI SECURITY ANALYST DEMO")
    print("=" * 72)

    # 1. Prepare Rich Structured Evidence from Previous Modules (01 - 10)
    sample_evidence = {
        "file_metadata": {
            "filename": "financial_agent.exe",
            "file_size": 34816,
            "file_kind": "EXE",
            "machine_type": "x64",
            "compile_time": "2026-02-14 18:30:00"
        },
        "hashes": {
            "sha256": "448d67c89f1232913ab8c9f2a18a5344c05ed1c7b69d3aa06205a2eae6376973",
            "sha1": "7e24b7405e381b1625fdfc53ff5e6080de485efb",
            "md5": "9e107d9d372bb6826bd81d3542a419d6"
        },
        "sections": {
            "total_sections": 3,
            "has_wx_sections": True,
            "anomalous_sections_count": 1
        },
        "entropy": {
            "file_entropy": 7.45,
            "classification": "VERY_HIGH"
        },
        "strings": {
            "urls": ["https://threat-c2.net/payload.bin"],
            "ip_addresses": ["192.168.1.50"],
            "registry_paths": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
        },
        "imports": {
            "total_imports": 8,
            "categories_present": ["MEMORY", "PROCESS", "NETWORK", "REGISTRY"]
        },
        "indicators": {
            "total_indicators": 4,
            "indicators": [
                {
                    "id": "IND-STR-001",
                    "name": "Writable and Executable (W+X) Section Detected",
                    "category": "PE_STRUCTURE",
                    "severity": "HIGH",
                    "evidence": "Section '.packed' has simultaneous W+X rights"
                },
                {
                    "id": "IND-MEM-001",
                    "name": "Correlated Memory Staging and Protection Modification",
                    "category": "MEMORY",
                    "severity": "HIGH",
                    "evidence": "VirtualAlloc + VirtualProtect APIs imported"
                },
                {
                    "id": "IND-NET-001",
                    "name": "Correlated Network Endpoints and Communication Primitives",
                    "category": "NETWORK",
                    "severity": "HIGH",
                    "evidence": "URL found + InternetOpenA API imported"
                }
            ]
        },
        "threat_score": {
            "score": 85,
            "risk_level": "CRITICAL"
        },
        "ethiopian_context": {
            "environment": "FINANCIAL",
            "relevance": "CRITICAL",
            "reason": "Memory manipulation and network egress primitives critical for banking endpoint security."
        }
    }

    service = AISecurityAnalystService(provider=OfflineRuleBasedProvider())

    # 1. English Interpretation
    print("\n[Scenario 1] AI Security Analyst Report in English (en):")
    report_en = service.analyze(sample_evidence, language="en")
    print(json.dumps(report_en.to_dict(), indent=2))

    # 2. Amharic Interpretation
    print("\n[Scenario 2] AI Security Analyst Report in Amharic (am):")
    report_am = service.analyze(sample_evidence, language="am")
    print(json.dumps(report_am.to_dict(), indent=2, ensure_ascii=False))

    print("\n" + "=" * 72)
    print("  DEMONSTRATION COMPLETE - GROUNDED EVIDENCE EXPLANATION")
    print("=" * 72)


if __name__ == "__main__":
    main()
