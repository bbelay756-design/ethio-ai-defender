"""
Unit tests for app/ml/classifier.py (Milestone ML-06 Controlled Offline Integration).

Covers:
1. Correct checksum and valid artifact loading.
2. Incorrect checksum and artifact tampering.
3. Missing artifact and incompatible metadata.
4. Correct feature dimensions (2,381) and incorrect dimensions.
5. NaN, positive infinity, and negative infinity rejection.
6. Malicious-class probability mapping using estimator's actual class labels.
7. Valid predictions with finite scores in expected range [0.0, 1.0].
8. Untrusted upload/quarantine path rejection.
9. Bounded batch size enforcement.
10. Real artifact loading from approved primary artifact directory.
"""

import hashlib
import json
import os
import tempfile
from pathlib import Path
import unittest

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from app.core.config import BASE_DIR
from app.ml.classifier import (
    EmberModelClassifier,
    EmberModelError,
    ClassifierPredictionResult,
    TRUSTED_BASELINE_MODEL_SHA256,
    DEFAULT_PRIMARY_MODEL_DIR,
)
from app.ml.ember_v2 import EMBER_V2_TOTAL_DIM


def create_mock_model_dir(
    tmp_path: Path,
    tampered: bool = False,
    missing_checksum: bool = False,
    incompatible_dim: bool = False,
    incompatible_version: bool = False,
    inverted_classes: bool = False,
    missing_malicious_class: bool = False,
) -> str:
    """Helper to create a synthetic model artifact directory for testing."""
    # Synthetic dataset
    X_toy = np.random.uniform(0.0, 1.0, size=(20, EMBER_V2_TOTAL_DIM)).astype(np.float32)
    if missing_malicious_class:
        y_toy = np.array([0] * 20, dtype=np.int32)
    elif inverted_classes:
        # Fit with classes in reverse order [1, 0]
        y_toy = np.array([1] * 10 + [0] * 10, dtype=np.int32)
    else:
        y_toy = np.array([0] * 10 + [1] * 10, dtype=np.int32)

    clf = HistGradientBoostingClassifier(max_iter=5, random_state=42)
    clf.fit(X_toy, y_toy)

    if inverted_classes:
        # Force classes_ ordering to be [1, 0]
        clf.classes_ = np.array([1, 0], dtype=np.int32)

    model_file = tmp_path / "model.joblib"
    joblib.dump(clf, model_file)

    real_sha = hashlib.sha256(model_file.read_bytes()).hexdigest().lower()

    if not missing_checksum:
        checksum_file = tmp_path / "model.joblib.sha256"
        if tampered:
            checksum_file.write_text("bad_hash_0000000000000000000000000000000000000000000000000000000000", encoding="utf-8")
        else:
            checksum_file.write_text(f"{real_sha}  model.joblib\n", encoding="utf-8")

    feature_dim = 999 if incompatible_dim else EMBER_V2_TOTAL_DIM
    feature_ver = 1 if incompatible_version else 2

    metadata_file = tmp_path / "metadata.json"
    metadata = {
        "model_name": "ember-v2-mock-hgb",
        "model_version": "1.0.0",
        "dataset": {
            "feature_dim": feature_dim,
            "feature_version": feature_ver,
        },
        "calibrated_thresholds": {
            "fpr_1pct_target": {"threshold": 0.80},
            "fpr_01pct_target": {"threshold": 0.95},
            "default_05": {"threshold": 0.50},
        },
    }
    metadata_file.write_text(json.dumps(metadata), encoding="utf-8")

    return real_sha


class TestEmberModelClassifier(unittest.TestCase):
    """Test suite for EmberModelClassifier."""

    def test_correct_checksum_and_valid_loading(self):
        """Case 1: Verify correct checksum and valid artifact loading."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            real_sha = create_mock_model_dir(tmp_path)

            classifier = EmberModelClassifier(
                model_dir=tmp_path,
                verify_checksum=True,
                trusted_sha256=real_sha,
                allow_custom_path=True,
            )
            self.assertTrue(classifier.is_loaded)
            self.assertEqual(classifier.trusted_sha256, real_sha)
            self.assertEqual(classifier.calibrated_thresholds["1pct_fpr"], 0.80)
            self.assertEqual(classifier.calibrated_thresholds["01pct_fpr"], 0.95)

    def test_incorrect_checksum_and_tampering(self):
        """Case 2: Verify tampered model is rejected prior to unpickling."""
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

    def test_missing_checksum_file_rejected(self):
        """Case 3a: Verify missing checksum file with no configured trusted digest is rejected."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            create_mock_model_dir(tmp_path, missing_checksum=True)

            with self.assertRaises(EmberModelError) as ctx:
                EmberModelClassifier(
                    model_dir=tmp_path,
                    verify_checksum=True,
                    allow_custom_path=True,
                )
            self.assertIn("checksum file missing", str(ctx.exception).lower())

    def test_incompatible_metadata_rejected(self):
        """Case 3b: Verify incompatible metadata (feature_dim != 2381) is rejected."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            real_sha = create_mock_model_dir(tmp_path, incompatible_dim=True)

            with self.assertRaises(EmberModelError) as ctx:
                EmberModelClassifier(
                    model_dir=tmp_path,
                    verify_checksum=True,
                    trusted_sha256=real_sha,
                    allow_custom_path=True,
                )
            self.assertIn("incompatible feature_dim", str(ctx.exception).lower())

    def test_feature_dimensions_validation(self):
        """Case 4: Verify correct 2,381 dimensions succeed, incorrect dimensions rejected."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            real_sha = create_mock_model_dir(tmp_path)
            clf = EmberModelClassifier(
                model_dir=tmp_path,
                verify_checksum=True,
                trusted_sha256=real_sha,
                allow_custom_path=True,
            )

            # Valid dimension
            valid_vec = np.ones((1, EMBER_V2_TOTAL_DIM), dtype=np.float32)
            validated = clf.validate_features(valid_vec)
            self.assertEqual(validated.shape, (1, EMBER_V2_TOTAL_DIM))

            # Invalid dimensions
            for bad_dim in [500, 2380, 2382, 0]:
                bad_vec = np.ones((1, bad_dim), dtype=np.float32)
                with self.assertRaises(EmberModelError) as ctx:
                    clf.validate_features(bad_vec)
                self.assertIn("dimension mismatch", str(ctx.exception).lower())

    def test_nan_and_inf_rejected(self):
        """Case 5: Verify NaN, +Inf, -Inf vectors are strictly rejected."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            real_sha = create_mock_model_dir(tmp_path)
            clf = EmberModelClassifier(
                model_dir=tmp_path,
                verify_checksum=True,
                trusted_sha256=real_sha,
                allow_custom_path=True,
            )

            # NaN
            nan_vec = np.ones((1, EMBER_V2_TOTAL_DIM), dtype=np.float32)
            nan_vec[0, 100] = np.nan
            with self.assertRaises(EmberModelError) as ctx:
                clf.validate_features(nan_vec)
            self.assertIn("non-finite", str(ctx.exception).lower())

            # +Inf
            pos_inf_vec = np.ones((1, EMBER_V2_TOTAL_DIM), dtype=np.float32)
            pos_inf_vec[0, 200] = np.inf
            with self.assertRaises(EmberModelError) as ctx:
                clf.validate_features(pos_inf_vec)
            self.assertIn("non-finite", str(ctx.exception).lower())

            # -Inf
            neg_inf_vec = np.ones((1, EMBER_V2_TOTAL_DIM), dtype=np.float32)
            neg_inf_vec[0, 300] = -np.inf
            with self.assertRaises(EmberModelError) as ctx:
                clf.validate_features(neg_inf_vec)
            self.assertIn("non-finite", str(ctx.exception).lower())

    def test_malicious_class_index_mapping(self):
        """Case 6: Verify positive-class probability mapping uses estimator.classes_."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            real_sha = create_mock_model_dir(tmp_path, inverted_classes=True)
            clf = EmberModelClassifier(
                model_dir=tmp_path,
                verify_checksum=True,
                trusted_sha256=real_sha,
                allow_custom_path=True,
            )

            # Estimator has classes_ = [1, 0]; index 0 must be selected for malicious class
            self.assertEqual(clf._malicious_class_index, 0)

            vec = np.random.uniform(0.0, 1.0, size=(1, EMBER_V2_TOTAL_DIM)).astype(np.float32)
            probs = clf.predict_proba(vec)
            self.assertEqual(probs.shape, (1,))
            self.assertTrue(0.0 <= probs[0] <= 1.0)

    def test_valid_predictions_finite_scores(self):
        """Case 7: Verify valid predictions with finite scores in expected range [0.0, 1.0]."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            real_sha = create_mock_model_dir(tmp_path)
            clf = EmberModelClassifier(
                model_dir=tmp_path,
                verify_checksum=True,
                trusted_sha256=real_sha,
                allow_custom_path=True,
            )

            vec = np.random.uniform(0.0, 1.0, size=(5, EMBER_V2_TOTAL_DIM)).astype(np.float32)
            probs = clf.predict_proba(vec)
            self.assertEqual(len(probs), 5)
            self.assertTrue(np.all(np.isfinite(probs)))
            self.assertTrue(np.all((probs >= 0.0) & (probs <= 1.0)))

            # Single typed prediction
            single_res = clf.predict_single(vec[0])
            self.assertIsInstance(single_res, ClassifierPredictionResult)
            self.assertTrue(0.0 <= single_res.malicious_score <= 1.0)
            self.assertIn("1pct_fpr", single_res.thresholds)
            self.assertEqual(single_res.feature_dim, EMBER_V2_TOTAL_DIM)

    def test_untrusted_upload_path_strictly_prohibited(self):
        """Case 12: Verify model loading from upload or quarantine paths is blocked."""
        upload_mock_dir = BASE_DIR / "storage" / "uploads" / "malicious_model"
        with self.assertRaises(EmberModelError) as ctx:
            EmberModelClassifier(model_dir=upload_mock_dir, allow_custom_path=False)
        self.assertIn("prohibited", str(ctx.exception).lower())

        quarantine_mock_dir = BASE_DIR / "storage" / "quarantine" / "quarantined_model"
        with self.assertRaises(EmberModelError) as ctx:
            EmberModelClassifier(model_dir=quarantine_mock_dir, allow_custom_path=False)
        self.assertIn("prohibited", str(ctx.exception).lower())

    def test_batch_size_limit_enforced(self):
        """Verify unbounded inference batch requests are rejected."""
        with tempfile.TemporaryDirectory() as td:
            tmp_path = Path(td)
            real_sha = create_mock_model_dir(tmp_path)
            clf = EmberModelClassifier(
                model_dir=tmp_path,
                verify_checksum=True,
                trusted_sha256=real_sha,
                allow_custom_path=True,
            )

            too_large = np.ones((1001, EMBER_V2_TOTAL_DIM), dtype=np.float32)
            with self.assertRaises(EmberModelError) as ctx:
                clf.validate_features(too_large)
            self.assertIn("exceeds maximum supported limit", str(ctx.exception).lower())

    def test_real_baseline_artifact_if_present(self):
        """Verify loading the real trained baseline model if artifact exists on disk."""
        if not DEFAULT_PRIMARY_MODEL_DIR.exists():
            self.skipTest(f"Primary artifact dir {DEFAULT_PRIMARY_MODEL_DIR} not found.")

        clf = EmberModelClassifier(
            model_dir=DEFAULT_PRIMARY_MODEL_DIR,
            verify_checksum=True,
            trusted_sha256=TRUSTED_BASELINE_MODEL_SHA256,
        )
        self.assertTrue(clf.is_loaded)
        self.assertEqual(clf.model_file_sha256, TRUSTED_BASELINE_MODEL_SHA256)
        self.assertIn("1pct_fpr", clf.calibrated_thresholds)
        self.assertAlmostEqual(clf.calibrated_thresholds["1pct_fpr"], 0.800395, places=3)

        dummy = np.ones((1, EMBER_V2_TOTAL_DIM), dtype=np.float32)
        score = clf.predict_proba(dummy)[0]
        self.assertTrue(0.0 <= score <= 1.0)


if __name__ == "__main__":
    unittest.main()
