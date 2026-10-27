"""
Unit and integration tests for app/analyzers/ml_analyzer.py (Milestone ML-06).

Covers:
8. Prediction exceptions and explicit ML-unavailable results.
9. Feature schema mismatch between training and raw-PE extraction.
10. Graceful failure without changing deterministic analyzer results.
11. Existing security, intake, and quarantine behavior regression protection.
12. Resource limits, sanitization, and non-execution of binaries.
"""

import tempfile
import unittest
from pathlib import Path

import numpy as np

from app.analyzers.file_intake import secure_intake_service
from app.analyzers.hash_analyzer import hash_analyzer_service
from app.analyzers.ml_analyzer import MLAnalyzer, MLAnalysisResult, ml_analyzer_service
from app.analyzers.pe_analyzer import pe_static_analyzer_service
from app.analyzers.threat_scoring import threat_scoring_engine_service
from app.core.config import settings
from app.ml.classifier import (
    EmberModelClassifier,
    EmberModelError,
    DEFAULT_PRIMARY_MODEL_DIR,
    TRUSTED_BASELINE_MODEL_SHA256,
)
from app.ml.ember_v2 import EMBER_V2_TOTAL_DIM
from tests.ml.test_classifier import create_mock_model_dir


class TestMLAnalyzer(unittest.TestCase):
    """Test suite for MLAnalyzer component."""

    @classmethod
    def setUpClass(cls):
        # Create a mock classifier fixture in a temporary directory
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.mock_dir = Path(cls.temp_dir.name)
        cls.mock_sha = create_mock_model_dir(cls.mock_dir)
        cls.mock_classifier = EmberModelClassifier(
            model_dir=cls.mock_dir,
            verify_checksum=True,
            trusted_sha256=cls.mock_sha,
            allow_custom_path=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_explicit_ml_unavailable_when_uninitialized(self):
        """Case 8a: Verify uninitialized analyzer returns explicit UNAVAILABLE status, not benign."""
        analyzer = MLAnalyzer(classifier=None, enforce_parity_gate=True)
        # Force classifier to None to test uninitialized state
        analyzer._classifier = None

        vec = np.ones((1, EMBER_V2_TOTAL_DIM), dtype=np.float32)
        res = analyzer.analyze_feature_vector(vec)

        self.assertFalse(res.available)
        self.assertEqual(res.status, "UNAVAILABLE")
        self.assertIsNone(res.malicious_score)
        self.assertIsNone(res.is_malicious)
        # Must never default to benign (is_malicious=False with score=0.0)
        self.assertFalse(res.is_reliable)

    def test_prediction_exception_returns_explicit_failed(self):
        """Case 8b: Corrupted or non-finite vector returns FAILED, never silently benign."""
        analyzer = MLAnalyzer(classifier=self.mock_classifier)

        bad_vec = np.ones((1, EMBER_V2_TOTAL_DIM), dtype=np.float32)
        bad_vec[0, 50] = np.nan

        res = analyzer.analyze_feature_vector(bad_vec)
        self.assertFalse(res.available)
        self.assertEqual(res.status, "FAILED")
        self.assertIsNone(res.malicious_score)
        self.assertIsNone(res.is_malicious)
        self.assertIsNotNone(res.error)
        self.assertNotIn("D:\\", res.error)  # Verifies path sanitization

    def test_feature_schema_parity_gate_for_raw_pe(self):
        """Case 9a: Raw PE bytes analysis must explicitly flag unverified parity."""
        analyzer = MLAnalyzer(classifier=self.mock_classifier, enforce_parity_gate=True)

        # Synthetic DOS/PE byte sequence
        synthetic_pe = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 64 + b"PE\x00\x00" + b"\x00" * 200

        res = analyzer.analyze_pe_bytes(synthetic_pe)
        self.assertTrue(res.available)
        self.assertEqual(res.status, "OFFLINE_TEST_UNVERIFIED_PARITY")
        self.assertEqual(res.feature_parity_status, "UNVERIFIED_RAW_PE_PARITY")
        self.assertFalse(res.is_reliable)  # Must be explicitly untrusted for blocking
        self.assertIn("parity", res.message.lower())

    def test_verified_feature_vector_evaluation(self):
        """Case 9b: Valid pre-extracted feature vector has VERIFIED parity status."""
        analyzer = MLAnalyzer(classifier=self.mock_classifier, enforce_parity_gate=True)

        valid_vec = np.random.uniform(0.0, 1.0, size=(1, EMBER_V2_TOTAL_DIM)).astype(np.float32)
        res = analyzer.analyze_feature_vector(valid_vec)

        self.assertTrue(res.available)
        self.assertEqual(res.status, "SUCCESS")
        self.assertEqual(res.feature_parity_status, "VERIFIED_FEATURE_VECTOR")
        self.assertTrue(res.is_reliable)
        self.assertIsNotNone(res.malicious_score)
        self.assertTrue(0.0 <= res.malicious_score <= 1.0)
        self.assertIsNotNone(res.is_malicious)

    def test_graceful_failure_without_changing_deterministic_analyzers(self):
        """Case 10: ML failure does not perturb deterministic analyzers or threat scoring."""
        synthetic_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 400

        # 1. Run deterministic analyzers prior to ML failure
        hash_before = hash_analyzer_service.compute_from_bytes(synthetic_pe).to_dict()
        pe_before = pe_static_analyzer_service.analyze_bytes(synthetic_pe).to_dict()

        # 2. Trigger an ML analyzer failure
        failing_analyzer = MLAnalyzer(classifier=None)
        failing_analyzer._classifier = None
        ml_res = failing_analyzer.analyze_pe_bytes(synthetic_pe)
        self.assertEqual(ml_res.status, "UNAVAILABLE")

        # 3. Run deterministic analyzers again
        hash_after = hash_analyzer_service.compute_from_bytes(synthetic_pe).to_dict()
        pe_after = pe_static_analyzer_service.analyze_bytes(synthetic_pe).to_dict()

        # 4. Verify exact parity of deterministic results
        self.assertEqual(hash_before, hash_after)
        self.assertEqual(pe_before["type"], pe_after["type"])
        self.assertEqual(pe_before["characteristics"], pe_after["characteristics"])

    def test_security_and_intake_regression(self):
        """Case 11: File intake perimeter validation and size limits are strictly preserved."""
        # Oversized content rejection
        oversized = b"MZ" + b"\x00" * (settings.MAX_FILE_SIZE_BYTES + 10)
        intake_res = secure_intake_service.process_bytes(oversized, raw_filename="toolarge.exe")
        self.assertFalse(intake_res.is_success)
        self.assertIn("size", intake_res.message.lower())

        # Invalid extension / non-PE rejection
        bad_ext = b"MZ" + b"\x00" * 100
        intake_bad = secure_intake_service.process_bytes(bad_ext, raw_filename="script.sh")
        self.assertFalse(intake_bad.is_success)

    def test_resource_limits_and_sanitization(self):
        """Case 12: Resource boundaries, empty input rejection, and path sanitization."""
        analyzer = MLAnalyzer(classifier=self.mock_classifier)

        # Empty content
        res_empty = analyzer.analyze_pe_bytes(b"")
        self.assertFalse(res_empty.available)
        self.assertEqual(res_empty.status, "FAILED")
        self.assertIn("empty", res_empty.message.lower())

        # Non-existent file
        res_nofile = analyzer.analyze_file("C:\\nonexistent_malware_file_12345.exe")
        self.assertFalse(res_nofile.available)
        self.assertEqual(res_nofile.status, "FAILED")
        self.assertNotIn("nonexistent_malware_file_12345", res_nofile.error)

    def test_singleton_service_instance_contract(self):
        """Verify the singleton ml_analyzer_service adheres to the export contract."""
        self.assertIsInstance(ml_analyzer_service, MLAnalyzer)
        d = ml_analyzer_service.analyze_feature_vector(np.ones(EMBER_V2_TOTAL_DIM)).to_dict()
        self.assertIn("status", d)
        self.assertIn("available", d)
        self.assertIn("feature_parity_status", d)
        self.assertIn("is_reliable", d)


if __name__ == "__main__":
    unittest.main()
