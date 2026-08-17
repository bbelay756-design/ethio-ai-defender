"""
Module 18 - Security Testing: Step 14 - AI Security & Grounding Validation.
Tests evidence sanitization, non-exposure of raw binaries/secrets, hallucination prevention, provider failovers, and contradictory evidence rejection.
"""

import unittest
from app.ai.analyst import AISecurityAnalystService
from app.ai.sanitizer import sanitize_evidence_payload, sanitize_text_string
from app.ai.grounding import GroundingValidator
from app.ai.provider import MockAIProvider, OfflineRuleBasedProvider
from tests.fixtures.mock_ai_responses import (
    MOCK_VALID_AI_REPORT,
    MOCK_HALLUCINATED_FAMILY_AI_REPORT,
    MOCK_RUNTIME_CLAIM_AI_REPORT,
    MOCK_CONTRADICTORY_AI_REPORT,
)


class TestAISecurity(unittest.TestCase):
    """AI security, sanitization, grounding, and provider failure robustness suite."""

    def setUp(self):
        self.validator = GroundingValidator()
        self.analyst = AISecurityAnalystService(provider=MockAIProvider())

    def test_01_raw_binary_and_byte_streams_never_passed_to_ai(self):
        """Verify evidence payload sanitizer completely strips raw byte streams and binary keys."""
        raw_evidence = {
            "file_metadata": {"filename": "sample.exe", "file_size": 2048},
            "raw_bytes": b"MZ\x90\x00\x03" + (b"\x00" * 500),
            "binary_content": b"\x55\x8b\xec\x83\xec\x10",
            "byte_stream": [0x4D, 0x5A, 0x90, 0x00],
            "pe_bytes": b"PE\x00\x00",
        }
        sanitized = sanitize_evidence_payload(raw_evidence)

        self.assertNotIn("raw_bytes", sanitized)
        self.assertNotIn("binary_content", sanitized)
        self.assertNotIn("byte_stream", sanitized)
        self.assertNotIn("pe_bytes", sanitized)
        self.assertIn("file_metadata", sanitized)

    def test_02_secrets_and_personal_paths_redacted_before_ai(self):
        """Verify API keys, tokens, passwords, and user filesystem paths are redacted."""
        raw_evidence = {
            "strings": {
                "urls": ["https://api.soc.et/v1?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"],
                "commands": ["C:\\Users\\JohnDoe\\AppData\\Local\\Temp\\agent.exe --api_key=sk-1234567890abcdef12345678"],
            }
        }
        sanitized = sanitize_evidence_payload(raw_evidence)
        urls_str = str(sanitized["strings"]["urls"])
        cmds_str = str(sanitized["strings"]["commands"])

        self.assertNotIn("JohnDoe", cmds_str)
        self.assertIn("<USER>", cmds_str)
        self.assertIn("[REDACTED]", cmds_str)

    def test_03_hallucinated_threat_actor_rejection(self):
        """Verify grounding validator flags and suppresses ungrounded APT / threat actor hallucinations."""
        evidence = {"hashes": {"sha256": "3aca6c684a39c9ecaf3de614663d9c2240be7869d5ed5642b49140034ca9db9e"}}
        # AI report containing hallucinated actor
        report_data = {
            "summary": "Attributed to Lazarus Group APT38 campaign.",
            "key_findings": ["Detected Ethiopian Cyber Army payload."],
            "evidence": [],
            "possible_benign_explanations": [],
            "recommended_investigation": [],
            "limitations": [],
        }
        cleaned_report = self.validator.validate_and_clean(report_data, evidence)

        self.assertNotIn("Lazarus Group", cleaned_report["summary"])
        self.assertIn("[UNVERIFIED_ATTRIBUTION]", cleaned_report["summary"])
        self.assertTrue(any("Unverified" in f for f in cleaned_report["key_findings"]))

    def test_04_contradictory_evidence_handling(self):
        """Verify contradictory AI claims (claiming network egress when evidence has 0 network imports) are validated."""
        evidence = {
            "imports": {"imports": []},
            "strings": {"urls": [], "ip_addresses": []},
            "threat_score": {"score": 0, "risk_level": "LOW"},
        }
        cleaned_report = self.validator.validate_and_clean(MOCK_CONTRADICTORY_AI_REPORT, evidence)
        self.assertIsNotNone(cleaned_report)
        self.assertIn("limitations", cleaned_report)

    def test_05_offline_rule_provider_fallback_on_provider_error(self):
        """Verify offline rule-based provider deterministically generates grounded reports when external AI is unavailable."""
        offline_service = AISecurityAnalystService(provider=OfflineRuleBasedProvider())
        evidence = {
            "file_metadata": {"filename": "calc.exe", "file_size": 4096},
            "hashes": {"sha256": "448d67c89f1232913ab8c9f2a18a5344c05ed1c7b69d3aa06205a2eae6376973"},
            "threat_score": {"score": 10, "risk_level": "LOW"},
            "indicators": {"indicators": []},
        }
        report = offline_service.analyze(evidence, language="en")
        self.assertEqual(report.assessment, "LOW")
        self.assertIn("LOW", report.summary)
        self.assertTrue(report.is_valid)


if __name__ == "__main__":
    unittest.main()

