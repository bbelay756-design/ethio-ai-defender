"""
Live Demonstration Script for Module 13: Security Report Generator.
"""

import sys
import json
import warnings
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.reports.generator import SecurityReportGenerator
from app.ai.analyst import AIAnalystReport


def main():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 13: SECURITY REPORT GENERATOR DEMO")
    print("=" * 72)

    generator = SecurityReportGenerator()

    # 1. Comprehensive Static Evidence
    sample_evidence = {
        "file_metadata": {
            "filename": "cbe_portal_updater.exe",
            "file_size": 48128,
            "file_kind": "EXE",
            "machine_type": "x64",
            "compile_time": "2026-02-16 14:22:00"
        },
        "hashes": {
            "sha256": "3aca6c684a39c9ecaf3de614663d9c2240be7869d5ed5642b49140034ca9db9e",
            "sha1": "b5d848777ff7528e10408bd3725c898c8c7d3db1",
            "md5": "eef52d1656582cb18a4f2deba3aed525"
        },
        "pe_information": {
            "subsystem": "Windows GUI",
            "machine_architecture": "x64",
            "characteristics": 0x0102
        },
        "sections": {
            "total_sections": 3,
            "has_wx_sections": True,
            "anomalous_sections_count": 1
        },
        "entropy": {
            "file_entropy": 7.62,
            "classification": "VERY_HIGH"
        },
        "strings": {
            "urls": ["https://auth.telecom.et/login.php", "https://c2-egress.net/payload.bin"],
            "ip_addresses": ["196.188.120.10"],
            "registry_paths": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
        },
        "imports": {
            "total_imports": 8,
            "categories_present": ["MEMORY", "NETWORK", "PROCESS", "REGISTRY"],
            "imports": [
                {"dll": "KERNEL32.dll", "api": "VirtualAlloc"},
                {"dll": "KERNEL32.dll", "api": "VirtualProtect"},
                {"dll": "WININET.dll", "api": "InternetOpenA"},
                {"dll": "ADVAPI32.dll", "api": "RegSetValueExA"}
            ]
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
                    "evidence": "VirtualAlloc + VirtualProtect imported"
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
            "reason": "Memory manipulation and domestic Ethiopian telecom endpoints present critical risk to financial sector."
        }
    }

    ai_report = AIAnalystReport(
        assessment="CRITICAL",
        confidence="HIGH",
        summary="Static analysis indicates a CRITICAL threat posture with packed sections, in-memory page permission modifications, and network egress capabilities.",
        key_findings=[
            "Heuristic Threat Score: 85/100 [CRITICAL].",
            "Direct reference to Ethiopian domestic network infrastructure identified."
        ],
        evidence=["VirtualAlloc + VirtualProtect APIs imported."],
        possible_benign_explanations=["Legitimate software packer / DRM compression."],
        recommended_investigation=["Execute in isolated sandbox to monitor dynamic network callbacks."],
        limitations=["Static analysis evaluates capabilities without live execution."],
        language="en"
    )

    # 1. Generate Full 16-Section Security Report
    print("\n[+] Generating Unified Security Analysis Report across 16 Sections...")
    report = generator.generate_report(
        evidence=sample_evidence,
        ai_report=ai_report,
        language="en"
    )

    print(f"Report ID : {report.report_id}")
    print(f"Sections  : {len(report.to_dict()['sections'])} / 16 Present")

    # 2. Display Epistemological Evidence Model
    print("\n[+] Tri-Tiered Evidence Model Breakdown:")
    for ev in report.evidence[:6]:
        print(f"  [{ev.tier.value:<14}] ({ev.category:<18}) {ev.statement}")

    # 3. Export to HTML Report
    html_content = generator.export(report, format="html")
    output_path = Path("sample_security_report.html")
    output_path.write_text(html_content, encoding="utf-8")
    print(f"\n[+] Standalone HTML Report exported to: {output_path.resolve()}")

    print("\n" + "=" * 72)
    print("  DEMONSTRATION COMPLETE - COMPLETE 16-SECTION REPORT GENERATION")
    print("=" * 72)


if __name__ == "__main__":
    main()
