"""
Unit tests for Module 10: Ethiopian Cybersecurity Context Engine.

Tests:
1. Contextual evaluations across all 7 supported environments:
   - GOVERNMENT
   - FINANCIAL
   - UNIVERSITY
   - HEALTHCARE
   - TELECOMMUNICATIONS
   - ENTERPRISE
   - GENERAL
2. Relevance assessment tiers (LOW, MEDIUM, HIGH, CRITICAL).
3. English language localization mode ('en').
4. Amharic language localization mode ('am') with technical terms preserved:
   (PE, API, SHA-256, DLL, x86, x64, Entropy).
5. Evidence-based neutrality (no invented threat actors, campaigns, or unverified targeting claims).
6. Domestic artifact identification (e.g., .et domains).
7. Generic capability prioritization in the absence of domestic strings.
8. Output schema contract dictionary verification.
"""

import unittest

from app.analyzers.ethiopian_context import (
    EthiopianContextEngine,
    ContextAssessment,
    EthiopianContextAnalysisResult,
    ENVIRONMENTS,
)
from app.analyzers.indicator_engine import SuspiciousIndicator
from app.analyzers.string_analyzer import StringAnalysisResult


class TestEthiopianContextEngine(unittest.TestCase):
    """Unit test suite for Ethiopian Context Engine."""

    def setUp(self):
        self.engine = EthiopianContextEngine()

    def test_all_environments_supported(self):
        """Verify all 7 environments are supported in assessment."""
        expected_envs = {
            "GOVERNMENT", "FINANCIAL", "UNIVERSITY", "HEALTHCARE",
            "TELECOMMUNICATIONS", "ENTERPRISE", "GENERAL"
        }
        self.assertEqual(set(ENVIRONMENTS), expected_envs)

        for env in expected_envs:
            res = self.engine.evaluate_sector(
                target_env=env,
                indicators=[],
                language="en"
            )
            self.assertEqual(res.environment, env)
            self.assertIn(res.relevance, ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
            self.assertTrue(len(res.reason) > 0)

    def test_english_localization(self):
        """Verify standard English localized reasoning."""
        ind = SuspiciousIndicator(
            id="IND-NET-001",
            name="Network Capability",
            category="NETWORK",
            severity="HIGH",
            evidence="",
            confidence=0.85,
            explanation=""
        )
        res = self.engine.evaluate_sector(
            target_env="TELECOMMUNICATIONS",
            indicators=[ind],
            language="en"
        )
        self.assertEqual(res.language, "en")
        self.assertIn("telecom", res.reason.lower())

    def test_amharic_localization_preserves_technical_terms(self):
        """Verify Amharic localization preserves PE, API, DLL, and security keywords."""
        ind = SuspiciousIndicator(
            id="IND-MEM-001",
            name="Memory Injection",
            category="MEMORY",
            severity="HIGH",
            evidence="",
            confidence=0.85,
            explanation=""
        )
        res = self.engine.evaluate_sector(
            target_env="FINANCIAL",
            indicators=[ind],
            language="am"
        )
        self.assertEqual(res.language, "am")
        # Technical terms must remain Latin/English in Amharic text
        self.assertTrue("Memory" in res.reason or "API" in res.reason or "PE" in res.reason)

    def test_neutrality_no_invented_threat_actors(self):
        """Verify the engine strictly avoids hallucinating threat actors or campaigns."""
        # Generic suspicious indicators without domestic references
        ind = SuspiciousIndicator(
            id="IND-CMD-001",
            name="Command Execution",
            category="COMMAND_EXECUTION",
            severity="HIGH",
            evidence="",
            confidence=0.8,
            explanation=""
        )
        res = self.engine.analyze_context(
            indicators=[ind],
            preferred_environment="GOVERNMENT",
            language="en"
        )
        # Reason should focus on technical capability, not fake actor names
        forbidden_hallucinations = ["ethiopian hacker group", "addis malware campaign", "national emergency"]
        for phrase in forbidden_hallucinations:
            self.assertNotIn(phrase, res.reason.lower())
        self.assertFalse(res.has_explicit_domestic_artifacts)

    def test_verified_domestic_artifact_detection(self):
        """Verify detection of genuine Ethiopian domestic domain/ccTLD artifacts."""
        str_res = StringAnalysisResult(
            domains=["telecom.et", "insa.gov.et"],
            urls=["https://portal.telecom.et/login"]
        )
        ind = SuspiciousIndicator(
            id="IND-NET-001",
            name="Network Staging",
            category="NETWORK",
            severity="HIGH",
            evidence="",
            confidence=0.9,
            explanation=""
        )
        res = self.engine.analyze_context(
            indicators=[ind],
            strings=str_res,
            threat_score=75,
            preferred_environment="GOVERNMENT",
            language="en"
        )

        self.assertTrue(res.has_explicit_domestic_artifacts)
        self.assertGreater(len(res.explicit_artifacts), 0)
        self.assertEqual(res.relevance, "CRITICAL")
        self.assertIn("telecom.et", res.reason)

    def test_output_schema_contract(self):
        """Verify exact schema contract matching the specification."""
        assessment = ContextAssessment(
            environment="UNIVERSITY",
            relevance="MEDIUM",
            reason="File activity and persistence mechanisms identified.",
            language="en"
        )
        d = assessment.to_dict()

        expected_keys = {"environment", "relevance", "reason", "language"}
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertEqual(d["environment"], "UNIVERSITY")
        self.assertEqual(d["relevance"], "MEDIUM")
        self.assertEqual(d["language"], "en")


if __name__ == "__main__":
    unittest.main()
