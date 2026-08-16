"""
Unit tests for Module 13: Security Report Generator.

Tests:
1. Presence of all 16 required report sections in generated report.
2. Tri-tiered Evidence Model (OBSERVED, RULE-BASED, AI-INTERPRETED) verification.
3. JSON export rendering.
4. HTML standalone export rendering with print and badge styles.
5. PDF renderer pluggable architecture.
6. Dual language support (English and Amharic).
7. Output dictionary schema contract.
"""

import json
import unittest

from app.reports.models import SecurityReport, EvidenceTier, ClassifiedStatement
from app.reports.generator import SecurityReportGenerator
from app.reports.renderers import JSONReportRenderer, HTMLReportRenderer, PDFReportRenderer
from app.ai.analyst import AIAnalystReport


class TestSecurityReportGenerator(unittest.TestCase):
    """Unit test suite for Security Report Generator."""

    def setUp(self):
        self.generator = SecurityReportGenerator()
        self.mock_evidence = {
            "file_metadata": {
                "filename": "sample_threat.exe",
                "file_size": 24576,
                "file_kind": "EXE",
                "machine_type": "x64"
            },
            "hashes": {
                "sha256": "448d67c89f1232913ab8c9f2a18a5344c05ed1c7b69d3aa06205a2eae6376973",
                "sha1": "7e24b7405e381b1625fdfc53ff5e6080de485efb",
                "md5": "9e107d9d372bb6826bd81d3542a419d6"
            },
            "pe_information": {
                "subsystem": "Windows GUI",
                "machine_architecture": "x64",
                "compile_time": "2026-02-14 18:30:00"
            },
            "sections": {
                "total_sections": 3,
                "has_wx_sections": True,
                "anomalous_sections_count": 1
            },
            "entropy": {
                "file_entropy": 7.42,
                "classification": "VERY_HIGH"
            },
            "strings": {
                "urls": ["https://threat-c2.net/payload.bin"],
                "ip_addresses": ["192.168.1.1"],
                "registry_paths": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
            },
            "imports": {
                "total_imports": 4,
                "categories_present": ["MEMORY", "NETWORK"],
                "imports": [
                    {"dll": "KERNEL32.dll", "api": "VirtualAlloc"},
                    {"dll": "WININET.dll", "api": "InternetOpenA"}
                ]
            },
            "indicators": {
                "total_indicators": 2,
                "indicators": [
                    {
                        "id": "IND-MEM-001",
                        "name": "Memory Staging",
                        "category": "MEMORY",
                        "severity": "HIGH",
                        "evidence": "VirtualAlloc imported"
                    }
                ]
            },
            "threat_score": {
                "score": 75,
                "risk_level": "HIGH"
            },
            "ethiopian_context": {
                "environment": "FINANCIAL",
                "relevance": "HIGH",
                "reason": "Memory staging relevant for banking systems."
            }
        }
        self.mock_ai_report = AIAnalystReport(
            assessment="HIGH",
            confidence="HIGH",
            summary="AI Analysis: Sample presents high-risk memory allocation primitives.",
            key_findings=["Correlated memory and network capabilities."],
            evidence=["VirtualAlloc API imported."],
            possible_benign_explanations=["Legitimate software compression."],
            recommended_investigation=["Execute in sandbox."],
            limitations=["Static analysis only."],
            language="en"
        )

    def test_all_16_report_sections_present(self):
        """Verify that all 16 required sections are generated in the report dictionary."""
        report = self.generator.generate_report(
            evidence=self.mock_evidence,
            ai_report=self.mock_ai_report,
            language="en"
        )
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

        self.assertEqual(set(d["sections"].keys()), expected_sections)
        self.assertEqual(report.language, "en")
        self.assertTrue(len(report.report_id) > 0)

    def test_tri_tier_evidence_model_classification(self):
        """Verify that findings are accurately partitioned into OBSERVED, RULE-BASED, and AI-INTERPRETED tiers."""
        report = self.generator.generate_report(
            evidence=self.mock_evidence,
            ai_report=self.mock_ai_report,
            language="en"
        )

        tiers_found = {ev.tier for ev in report.evidence}
        self.assertIn(EvidenceTier.OBSERVED, tiers_found)
        self.assertIn(EvidenceTier.RULE_BASED, tiers_found)
        self.assertIn(EvidenceTier.AI_INTERPRETED, tiers_found)

        # Check observed statements contain verified facts
        observed_statements = [e.statement for e in report.evidence if e.tier == EvidenceTier.OBSERVED]
        self.assertTrue(any("448d67c89f1232913ab8c9f2a18a5344c05ed1c7b69d3aa06205a2eae6376973" in s for s in observed_statements))
        self.assertTrue(any("VirtualAlloc" in s for s in observed_statements))

        # Check rule-based statements contain heuristic findings
        rule_statements = [e.statement for e in report.evidence if e.tier == EvidenceTier.RULE_BASED]
        self.assertTrue(any("75/100" in s for s in rule_statements))

        # Check AI-interpreted statements contain qualified explanations
        ai_statements = [e.statement for e in report.evidence if e.tier == EvidenceTier.AI_INTERPRETED]
        self.assertTrue(any("AI Analysis:" in s for s in ai_statements))

    def test_json_export_rendering(self):
        """Verify exporting report to JSON string format."""
        report = self.generator.generate_report(
            evidence=self.mock_evidence,
            ai_report=self.mock_ai_report,
            language="en"
        )
        json_output = self.generator.export(report, format="json")

        self.assertIsInstance(json_output, str)
        parsed = json.loads(json_output)
        self.assertIn("sections", parsed)
        self.assertEqual(parsed["report_id"], report.report_id)

    def test_html_export_rendering(self):
        """Verify exporting report to standalone responsive HTML markup."""
        report = self.generator.generate_report(
            evidence=self.mock_evidence,
            ai_report=self.mock_ai_report,
            language="en"
        )
        html_output = self.generator.export(report, format="html")

        self.assertIsInstance(html_output, str)
        self.assertIn("<!DOCTYPE html>", html_output)
        self.assertIn("badge-observed", html_output)
        self.assertIn("badge-rule", html_output)
        self.assertIn("badge-ai", html_output)
        self.assertIn("1. Executive Summary", html_output)
        self.assertIn("13. Epistemological Evidence Model", html_output)

    def test_pdf_renderer_pluggable_architecture(self):
        """Verify PDF renderer architecture stub."""
        report = self.generator.generate_report(
            evidence=self.mock_evidence,
            ai_report=self.mock_ai_report,
            language="en"
        )
        pdf_markup = self.generator.export(report, format="pdf")
        self.assertIsInstance(pdf_markup, str)
        self.assertIn("<html", pdf_markup)

    def test_amharic_report_generation(self):
        """Verify generating a full report in Amharic."""
        report = self.generator.generate_report(
            evidence=self.mock_evidence,
            ai_report=None,
            language="am"
        )
        self.assertEqual(report.language, "am")
        d = report.to_dict()
        self.assertIn("1_executive_summary", d["sections"])
        self.assertTrue(len(d["sections"]["1_executive_summary"]) > 0)


if __name__ == "__main__":
    unittest.main()
