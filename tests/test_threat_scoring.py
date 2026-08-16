"""
Unit tests for Module 09: Threat Scoring Engine.

Tests:
1. Exact Risk Level boundary classification tests:
   - 0-20   : LOW
   - 21-40  : MODERATE
   - 41-60  : SUSPICIOUS
   - 61-80  : HIGH
   - 81-100 : CRITICAL
2. Empty indicators handling (score = 0, risk_level = 'LOW').
3. Multi-indicator score computation and weighting.
4. Category diminishing returns and duplicate evidence dampening.
5. Max score boundary clamping (score is capped at strictly 100).
6. Configurable severity weights override.
7. Presence of mandatory heuristic analyst-support disclaimer.
8. Structured JSON output schema contract verification.
"""

import unittest

from app.analyzers.threat_scoring import (
    ThreatScoringEngine,
    ThreatScoreResult,
    classify_risk_level,
    HEURISTIC_DISCLAIMER,
)
from app.analyzers.indicator_engine import SuspiciousIndicator


class TestThreatScoringEngine(unittest.TestCase):
    """Unit test suite for Threat Scoring Engine."""

    def setUp(self):
        self.engine = ThreatScoringEngine()

    # 1. Boundary & Classification Tier Tests
    def test_risk_level_boundaries(self):
        """Verify the exact 5 risk level boundary tiers."""
        self.assertEqual(classify_risk_level(0), "LOW")
        self.assertEqual(classify_risk_level(10), "LOW")
        self.assertEqual(classify_risk_level(20), "LOW")

        self.assertEqual(classify_risk_level(21), "MODERATE")
        self.assertEqual(classify_risk_level(30), "MODERATE")
        self.assertEqual(classify_risk_level(40), "MODERATE")

        self.assertEqual(classify_risk_level(41), "SUSPICIOUS")
        self.assertEqual(classify_risk_level(50), "SUSPICIOUS")
        self.assertEqual(classify_risk_level(60), "SUSPICIOUS")

        self.assertEqual(classify_risk_level(61), "HIGH")
        self.assertEqual(classify_risk_level(70), "HIGH")
        self.assertEqual(classify_risk_level(80), "HIGH")

        self.assertEqual(classify_risk_level(81), "CRITICAL")
        self.assertEqual(classify_risk_level(95), "CRITICAL")
        self.assertEqual(classify_risk_level(100), "CRITICAL")

    def test_empty_indicators_zero_score(self):
        """Verify that an empty indicator list yields score 0 and LOW risk level."""
        res = self.engine.calculate_score([])
        self.assertEqual(res.score, 0)
        self.assertEqual(res.risk_level, "LOW")
        self.assertEqual(len(res.contributions), 0)
        self.assertEqual(len(res.top_indicators), 0)
        self.assertEqual(res.disclaimer, HEURISTIC_DISCLAIMER)

    def test_single_low_indicator(self):
        """Verify score for a single LOW severity indicator."""
        ind = SuspiciousIndicator(
            id="IND-REG-001",
            name="Registry Query",
            category="REGISTRY",
            severity="LOW",
            evidence="RegOpenKeyExA",
            confidence=0.80,
            explanation="Registry query."
        )
        res = self.engine.calculate_score([ind])
        self.assertGreater(res.score, 0)
        self.assertLessEqual(res.score, 20)
        self.assertEqual(res.risk_level, "LOW")

    def test_duplicate_category_dampening(self):
        """Verify that multiple repetitive indicators in the same category are dampened and capped."""
        # Create 10 indicators all in MEMORY category
        many_memory_inds = [
            SuspiciousIndicator(
                id=f"IND-MEM-00{i}",
                name=f"Memory Indicator {i}",
                category="MEMORY",
                severity="HIGH",
                evidence="VirtualAlloc",
                confidence=1.0,
                explanation="Memory manipulation."
            )
            for i in range(10)
        ]
        res = self.engine.calculate_score(many_memory_inds)

        # Ensure points from MEMORY do not exceed the category max cap (default 40.0)
        total_memory_points = sum(c.points for c in res.contributions if c.category == "MEMORY")
        self.assertLessEqual(total_memory_points, 40.0)
        self.assertLessEqual(res.score, 40)

    def test_max_score_clamping_at_100(self):
        """Verify that excessive high-severity indicators across many categories clamp at 100."""
        extreme_indicators = [
            SuspiciousIndicator(
                id=f"IND-CAT-{i}",
                name=f"Severe finding {i}",
                category=f"CATEGORY_{i}",
                severity="CRITICAL",
                evidence="Extreme finding",
                confidence=1.0,
                explanation=""
            )
            for i in range(10)  # 10 categories * 35 pts each = 350 pts
        ]
        res = self.engine.calculate_score(extreme_indicators)

        self.assertEqual(res.score, 100)
        self.assertEqual(res.risk_level, "CRITICAL")

    def test_configurable_severity_weights(self):
        """Verify overriding severity point weights."""
        custom_weights = {"LOW": 1.0, "MEDIUM": 2.0, "HIGH": 3.0, "CRITICAL": 4.0}
        custom_engine = ThreatScoringEngine(severity_weights=custom_weights)

        ind = SuspiciousIndicator(
            id="IND-001",
            name="Test",
            category="MEMORY",
            severity="HIGH",
            evidence="",
            confidence=1.0,
            explanation=""
        )
        res = custom_engine.calculate_score([ind])
        self.assertEqual(res.score, 3)

    def test_disclaimer_presence(self):
        """Verify mandatory scientific disclaimer statement."""
        res = self.engine.calculate_score([])
        self.assertIn("heuristic analyst-support metric", res.disclaimer)
        self.assertIn("not a confirmed probability", res.disclaimer)

    def test_output_schema_contract(self):
        """Verify exact schema contract matching the specification."""
        ind = SuspiciousIndicator(
            id="IND-MEM-001",
            name="Memory Staging",
            category="MEMORY",
            severity="HIGH",
            evidence="VirtualAlloc + VirtualProtect",
            confidence=0.85,
            explanation="Dynamic memory allocation."
        )
        res = self.engine.calculate_score([ind])
        d = res.to_dict()

        expected_keys = {"score", "risk_level", "contributions", "top_indicators"}
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertIsInstance(d["score"], int)
        self.assertIsInstance(d["risk_level"], str)
        self.assertIsInstance(d["contributions"], list)
        self.assertIsInstance(d["top_indicators"], list)


if __name__ == "__main__":
    unittest.main()
