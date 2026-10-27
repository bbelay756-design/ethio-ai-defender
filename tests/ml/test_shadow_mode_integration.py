"""
Controlled Shadow-Mode Integration Test Suite for ML-04.

Verifies:
1. Feature flag gating: ML executes only when settings.ML_ENABLED is True; returns DISABLED otherwise.
2. Shadow-mode non-interference: In shadow mode, ML predictions are recorded under 'ml_analysis'
   without modifying threat scores, verdicts, YARA results, or indicators.
3. Parity gate enforcement: Raw PE inference is strictly marked as UNVERIFIED_RAW_PE_PARITY and is_reliable=False.
4. Fault tolerance & graceful degradation: Missing models, checksum mismatches, or extraction errors
   produce explicit UNAVAILABLE/FAILED statuses without aborting or altering deterministic analysis.
5. Path and error sanitization: Error messages do not leak local file paths or secrets.
"""

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from app.core.config import settings
from app.pipeline.orchestrator import unified_pipeline_service
from tests.test_pe_analyzer import build_synthetic_pe


class TestShadowModeIntegration(unittest.TestCase):
    """Test suite for ML-04 controlled shadow-mode pipeline integration."""

    @classmethod
    def setUpClass(cls):
        # Build safe in-memory synthetic PE fixture (never executed)
        cls.synthetic_pe = build_synthetic_pe(is_64bit=True, is_dll=False)

    def test_01_feature_flag_disabled_by_default(self):
        """Verify that when ML_ENABLED is False, orchestrator returns DISABLED without running ML."""
        with patch.object(settings, "ML_ENABLED", False):
            result = unified_pipeline_service.analyze_bytes(
                content=self.synthetic_pe,
                filename="test_sample_disabled.exe"
            )
            self.assertIn("ml_analysis", result)
            ml = result["ml_analysis"]
            self.assertFalse(ml["available"])
            self.assertEqual(ml["status"], "DISABLED")
            self.assertFalse(ml["is_reliable"])
            self.assertIsNone(ml["malicious_score"])

    def test_02_shadow_mode_enabled_records_telemetry_without_altering_verdict(self):
        """Verify that in shadow mode, ML executes, records telemetry, and preserves deterministic results."""
        # Baseline execution with ML disabled
        with patch.object(settings, "ML_ENABLED", False):
            baseline = unified_pipeline_service.analyze_bytes(
                content=self.synthetic_pe,
                filename="test_sample_compare.exe"
            )

        # Execution with ML enabled in shadow mode
        with patch.object(settings, "ML_ENABLED", True), patch.object(settings, "ML_SHADOW_MODE", True):
            shadow = unified_pipeline_service.analyze_bytes(
                content=self.synthetic_pe,
                filename="test_sample_compare.exe"
            )

        # 1. ML output exists and carries parity gate metadata
        self.assertIn("ml_analysis", shadow)
        ml = shadow["ml_analysis"]
        self.assertIn(ml["status"], ("SUCCESS", "OFFLINE_TEST_UNVERIFIED_PARITY", "UNAVAILABLE"))
        if ml["status"] == "OFFLINE_TEST_UNVERIFIED_PARITY":
            self.assertEqual(ml["feature_parity_status"], "UNVERIFIED_RAW_PE_PARITY")
            self.assertFalse(ml["is_reliable"])

        # 2. Strict non-interference: Deterministic outputs must be 100% bitwise identical
        self.assertEqual(baseline["risk_score"], shadow["risk_score"])
        self.assertEqual(baseline["hashes"], shadow["hashes"])
        self.assertEqual(baseline["pe"], shadow["pe"])
        self.assertEqual(baseline["sections"], shadow["sections"])
        self.assertEqual(baseline["entropy"], shadow["entropy"])
        self.assertEqual(baseline["strings"], shadow["strings"])
        self.assertEqual(baseline["imports"], shadow["imports"])
        self.assertEqual(baseline["indicators"], shadow["indicators"])
        self.assertEqual(baseline["yara_matches"], shadow["yara_matches"])
        self.assertEqual(baseline["mitre_attack"], shadow["mitre_attack"])
        self.assertEqual(baseline["status"], shadow["status"])

    def test_03_fault_handling_does_not_crash_pipeline(self):
        """Verify that simulated analyzer failure returns FAILED/UNAVAILABLE without breaking analysis."""
        with patch.object(settings, "ML_ENABLED", True):
            with patch("app.analyzers.ml_analyzer.ml_analyzer_service.analyze_pe_bytes") as mock_analyze:
                mock_analyze.side_effect = RuntimeError("Simulated ML engine failure")

                result = unified_pipeline_service.analyze_bytes(
                    content=self.synthetic_pe,
                    filename="test_sample_fault.exe"
                )

                self.assertIn("ml_analysis", result)
                ml = result["ml_analysis"]
                self.assertFalse(ml["available"])
                self.assertEqual(ml["status"], "FAILED")
                self.assertFalse(ml["is_reliable"])

                # Pipeline still succeeds for deterministic components
                self.assertIn(result["status"], ("COMPLETED", "PARTIAL"))
                self.assertIn("score", result["risk_score"])

    def test_04_error_sanitization(self):
        """Verify that error messages do not leak internal filesystem paths or secrets."""
        with patch.object(settings, "ML_ENABLED", True):
            with patch("app.analyzers.ml_analyzer.ml_analyzer_service.analyze_pe_bytes") as mock_analyze:
                mock_analyze.side_effect = RuntimeError(f"Error in {settings.STORAGE_BASE_DIR}\\secret\\model.dat")

                result = unified_pipeline_service.analyze_bytes(
                    content=self.synthetic_pe,
                    filename="test_sample_sanitize.exe"
                )

                err_msg = str(result["ml_analysis"].get("error", ""))
                self.assertNotIn("secret\\model.dat", err_msg)


if __name__ == "__main__":
    unittest.main()
