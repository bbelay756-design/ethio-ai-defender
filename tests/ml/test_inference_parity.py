"""
Inference Parity and Model Validation Test Suite for Milestone ML-07.

Compares direct scikit-learn estimator inference with EmberModelClassifier adapter
inference using verified reference vectors from staged validation data.
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from app.core.config import BASE_DIR
from app.ml.classifier import (
    EmberModelClassifier,
    EmberModelError,
    ClassifierPredictionResult,
    DEFAULT_PRIMARY_MODEL_DIR,
    TRUSTED_BASELINE_MODEL_SHA256,
)
from app.ml.ember_v2 import EMBER_V2_TOTAL_DIM
from tests.ml.test_classifier import create_mock_model_dir

STAGED_DIR = Path(r"D:\ethio_ai_defender_artifacts\staged")


class TestInferenceParity(unittest.TestCase):
    """Test suite validating inference parity between raw model and classifier adapter."""

    @classmethod
    def setUpClass(cls):
        if not DEFAULT_PRIMARY_MODEL_DIR.exists():
            raise unittest.SkipTest(f"Primary model directory missing: {DEFAULT_PRIMARY_MODEL_DIR}")

        cls.model_path = DEFAULT_PRIMARY_MODEL_DIR / "model.joblib"
        cls.raw_clf = joblib.load(cls.model_path)
        cls.classes = list(cls.raw_clf.classes_)
        cls.pos_idx = cls.classes.index(1)

        # Load real reference feature vectors
        x_val_path = STAGED_DIR / "X_val.mmap"
        if x_val_path.exists():
            cls.X_val = np.memmap(x_val_path, dtype="float32", mode="r", shape=(52073, EMBER_V2_TOTAL_DIM))
        else:
            cls.X_val = None

        cls.classifier = EmberModelClassifier(
            model_dir=DEFAULT_PRIMARY_MODEL_DIR,
            verify_checksum=True,
            trusted_sha256=TRUSTED_BASELINE_MODEL_SHA256,
        )

    def test_direct_estimator_versus_adapter_exact_parity(self):
        """Case 1: Compare direct estimator predictions with EmberModelClassifier outputs."""
        if self.X_val is None:
            self.skipTest("Staged X_val.mmap not found on disk.")

        # Test on 100 diverse validation samples
        test_samples = np.array(self.X_val[:100], dtype=np.float32)

        # Direct raw estimator inference
        raw_proba_matrix = self.raw_clf.predict_proba(test_samples)
        expected_scores = raw_proba_matrix[:, self.pos_idx].astype(np.float64)

        # Adapter inference
        actual_scores = self.classifier.predict_proba(test_samples)

        # Assert exact bitwise numerical match
        np.testing.assert_array_equal(actual_scores, expected_scores)
        self.assertEqual(float(np.max(np.abs(actual_scores - expected_scores))), 0.0)

    def test_malicious_class_probability_mapping(self):
        """Case 2: Verify positive-class probability mapping uses estimator's actual class labels."""
        self.assertIn(1, self.classes)
        self.assertEqual(self.classifier._malicious_class_index, self.pos_idx)

        # Verify inverted classes handling
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            real_sha = create_mock_model_dir(tmp_path, inverted_classes=True)
            mock_clf = EmberModelClassifier(
                model_dir=tmp_path,
                verify_checksum=True,
                trusted_sha256=real_sha,
                allow_custom_path=True,
            )
            # Inverted estimator has classes_ = [1, 0]; index 0 must be selected
            self.assertEqual(mock_clf._malicious_class_index, 0)
            dummy = np.random.uniform(0.0, 1.0, size=(1, EMBER_V2_TOTAL_DIM)).astype(np.float32)
            prob = mock_clf.predict_proba(dummy)[0]
            self.assertTrue(0.0 <= prob <= 1.0)

    def test_score_finiteness_schema_and_determinism(self):
        """Case 3: Verify score finiteness, output schema, threshold metadata, and determinism."""
        dummy = np.random.uniform(0.0, 1.0, size=(1, EMBER_V2_TOTAL_DIM)).astype(np.float32)

        res1 = self.classifier.predict_single(dummy[0])
        res2 = self.classifier.predict_single(dummy[0])

        # Determinism
        self.assertEqual(res1.malicious_score, res2.malicious_score)
        self.assertEqual(res1.is_malicious, res2.is_malicious)

        # Finiteness
        self.assertTrue(np.isfinite(res1.malicious_score))
        self.assertTrue(0.0 <= res1.malicious_score <= 1.0)

        # Typed Schema
        self.assertIsInstance(res1, ClassifierPredictionResult)
        self.assertEqual(res1.feature_dim, EMBER_V2_TOTAL_DIM)
        self.assertEqual(res1.model_sha256, TRUSTED_BASELINE_MODEL_SHA256)
        self.assertIn("1pct_fpr", res1.thresholds)
        self.assertAlmostEqual(res1.thresholds["1pct_fpr"], 0.800395, places=3)

    def test_negative_boundaries_and_rejections(self):
        """Case 4: Test invalid dimensions, NaN/Inf, oversized batches, corrupted artifacts."""
        # 1. Invalid dimensions
        bad_dim = np.ones((1, 1000), dtype=np.float32)
        with self.assertRaises(EmberModelError) as ctx:
            self.classifier.predict_proba(bad_dim)
        self.assertIn("dimension mismatch", str(ctx.exception).lower())

        # 2. NaN values
        nan_vec = np.ones((1, EMBER_V2_TOTAL_DIM), dtype=np.float32)
        nan_vec[0, 42] = np.nan
        with self.assertRaises(EmberModelError) as ctx:
            self.classifier.predict_proba(nan_vec)
        self.assertIn("non-finite", str(ctx.exception).lower())

        # 3. Inf values
        inf_vec = np.ones((1, EMBER_V2_TOTAL_DIM), dtype=np.float32)
        inf_vec[0, 42] = np.inf
        with self.assertRaises(EmberModelError) as ctx:
            self.classifier.predict_proba(inf_vec)
        self.assertIn("non-finite", str(ctx.exception).lower())

        # 4. Oversized batches (> 1000)
        oversized = np.ones((1005, EMBER_V2_TOTAL_DIM), dtype=np.float32)
        with self.assertRaises(EmberModelError) as ctx:
            self.classifier.validate_features(oversized)
        self.assertIn("exceeds maximum supported limit", str(ctx.exception).lower())

    def test_corrupted_model_rejected_before_deserialization(self):
        """Case 6: Corrupted model artifact is rejected before unpickling/deserialization."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            real_sha = create_mock_model_dir(tmp_path, tampered=True)

            with self.assertRaises(EmberModelError) as ctx:
                EmberModelClassifier(
                    model_dir=tmp_path,
                    verify_checksum=True,
                    trusted_sha256=real_sha,
                    allow_custom_path=True,
                )
            self.assertIn("tampering detected", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
