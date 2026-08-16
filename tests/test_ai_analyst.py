"""
Unit tests for Module 11: AI Security Analyst.

Tests:
1. Valid AI response interpretation and schema validation.
2. Malformed AI response recovery (graceful degradation).
3. Missing fields completion with safe defaults.
4. AI Timeout handling without crashing.
5. API Failure / 500 error handling with deterministic fallback.
6. Hallucinated evidence & fake threat actor prevention.
7. Privacy & data sanitization (redacts raw bytes, user paths, API keys).
8. Dual language localization (English and Amharic).
9. Output JSON schema contract verification.
"""

import json
import unittest

from app.ai.analyst import AISecurityAnalystService, AIAnalystReport
from app.ai.provider import MockAIProvider, OfflineRuleBasedProvider
from app.ai.sanitizer import sanitize_evidence_payload, sanitize_text_string
from app.ai.grounding import GroundingValidator


class TestAISecurityAnalyst(unittest.TestCase):
    """Unit test suite for AI Security Analyst."""

    def setUp(self):
        self.mock_evidence = {
            "file_metadata": {
                "filename": "sample_agent.exe",
                "file_size": 20480,
                "file_kind": "EXE",
                "machine_type": "x64"
            },
            "hashes": {
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "md5": "d41d8cd98f00b204e9800998ecf8427e"
            },
            "threat_score": {
                "score": 75,
                "risk_level": "HIGH"
            },
            "indicators": {
                "indicators": [
                    {
                        "id": "IND-MEM-001",
                        "name": "Memory Injection",
                        "category": "MEMORY",
                        "severity": "HIGH",
                        "evidence": "VirtualAlloc + VirtualProtect"
                    }
                ]
            },
            "ethiopian_context": {
                "environment": "FINANCIAL",
                "relevance": "HIGH",
                "reason": "Memory manipulation relevant for financial endpoints."
            }
        }

    def test_valid_ai_response_parsing(self):
        """Verify successful generation and parsing of valid AI report."""
        service = AISecurityAnalystService(provider=MockAIProvider(mode="valid"))
        report = service.analyze(self.mock_evidence, language="en")

        self.assertIsInstance(report, AIAnalystReport)
        self.assertEqual(report.assessment, "HIGH")
        self.assertIn(report.confidence, ["LOW", "MEDIUM", "HIGH"])
        self.assertTrue(len(report.summary) > 0)
        self.assertTrue(len(report.key_findings) > 0)
        self.assertTrue(len(report.evidence) > 0)
        self.assertTrue(len(report.possible_benign_explanations) > 0)
        self.assertTrue(len(report.recommended_investigation) > 0)
        self.assertTrue(len(report.limitations) > 0)

    def test_malformed_ai_response_recovery(self):
        """Verify graceful fallback when AI returns invalid non-JSON string."""
        service = AISecurityAnalystService(provider=MockAIProvider(mode="malformed"))
        report = service.analyze(self.mock_evidence, language="en")

        self.assertTrue(report.is_valid)
        self.assertEqual(report.assessment, "HIGH")  # Fallback matches threat score
        self.assertTrue(len(report.summary) > 0)

    def test_missing_fields_defaults(self):
        """Verify default completion when AI omits required schema keys."""
        service = AISecurityAnalystService(provider=MockAIProvider(mode="missing_fields"))
        report = service.analyze(self.mock_evidence, language="en")

        self.assertTrue(len(report.key_findings) > 0)
        self.assertTrue(len(report.possible_benign_explanations) > 0)
        self.assertTrue(len(report.recommended_investigation) > 0)
        self.assertTrue(len(report.limitations) > 0)

    def test_ai_timeout_handling(self):
        """Verify graceful degradation on provider timeout."""
        service = AISecurityAnalystService(provider=MockAIProvider(mode="timeout"))
        report = service.analyze(self.mock_evidence, language="en")

        self.assertTrue(report.is_valid)
        self.assertEqual(report.assessment, "HIGH")

    def test_api_failure_fallback(self):
        """Verify deterministic offline fallback on upstream 500 error."""
        service = AISecurityAnalystService(provider=MockAIProvider(mode="api_failure"))
        report = service.analyze(self.mock_evidence, language="en")

        self.assertTrue(report.is_valid)
        self.assertIn("HIGH", report.assessment)

    def test_hallucination_and_actor_prevention(self):
        """Verify removal of ungrounded hashes and invented threat actors."""
        fake_response = json.dumps({
            "assessment": "CRITICAL",
            "confidence": "HIGH",
            "summary": "Sample matching 1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff was developed by Lazarus Group.",
            "key_findings": ["Attributed to Cozy Bear during an Ethiopian Cyber Army operation."],
            "evidence": ["VirtualAlloc"],
            "possible_benign_explanations": ["None"],
            "recommended_investigation": ["Inspect"],
            "limitations": []
        })

        service = AISecurityAnalystService(provider=MockAIProvider(custom_response=fake_response))
        report = service.analyze(self.mock_evidence, language="en")

        # Fake hash must be sanitized out
        self.assertNotIn("1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff", report.summary)
        # Fake actors must be scrubbed
        self.assertNotIn("Lazarus Group", report.summary)
        self.assertNotIn("Cozy Bear", str(report.key_findings))
        self.assertNotIn("Ethiopian Cyber Army", str(report.key_findings))

    def test_privacy_and_data_sanitization(self):
        """Verify stripping of raw bytes, user paths, and API keys."""
        dirty_evidence = {
            "raw_bytes": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00",
            "file_metadata": {
                "path": "C:\\Users\\JohnDoe\\Desktop\\malware.exe",
                "secret_key": "api_key='sk-1234567890abcdef1234567890'"
            },
            "strings": [
                "Authorization: Bearer mySecretToken123456789",
                "C:\\Users\\Administrator\\AppData\\Local\\Temp\\drop.exe"
            ]
        }

        sanitized = sanitize_evidence_payload(dirty_evidence)

        # Raw bytes removed
        self.assertNotIn("raw_bytes", sanitized)
        # User directories redacted
        self.assertNotIn("JohnDoe", str(sanitized))
        self.assertNotIn("Administrator", str(sanitized))
        # Secret tokens redacted
        self.assertNotIn("sk-1234567890abcdef1234567890", str(sanitized))
        self.assertNotIn("mySecretToken123456789", str(sanitized))

    def test_amharic_language_support(self):
        """Verify Amharic localized explanation output."""
        service = AISecurityAnalystService(provider=OfflineRuleBasedProvider())
        report = service.analyze(self.mock_evidence, language="am")

        self.assertEqual(report.language, "am")
        # Technical keywords must be preserved
        self.assertTrue("PE" in report.summary or "ስጋት" in report.summary)

    def test_output_schema_contract(self):
        """Verify exact schema contract matching the specification."""
        service = AISecurityAnalystService(provider=MockAIProvider())
        report = service.analyze(self.mock_evidence, language="en")
        d = report.to_dict()

        expected_keys = {
            "assessment",
            "confidence",
            "summary",
            "key_findings",
            "evidence",
            "possible_benign_explanations",
            "recommended_investigation",
            "limitations"
        }
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertIn(d["assessment"], ["LOW", "MODERATE", "SUSPICIOUS", "HIGH", "CRITICAL"])
        self.assertIn(d["confidence"], ["LOW", "MEDIUM", "HIGH"])
        self.assertIsInstance(d["key_findings"], list)
        self.assertIsInstance(d["evidence"], list)
        self.assertIsInstance(d["possible_benign_explanations"], list)
        self.assertIsInstance(d["recommended_investigation"], list)
        self.assertIsInstance(d["limitations"], list)


if __name__ == "__main__":
    unittest.main()
