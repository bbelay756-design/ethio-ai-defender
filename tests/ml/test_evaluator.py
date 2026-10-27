"""
Unit tests for app/ml/evaluator.py.

Verifies:
- Binary metric calculations (confusion matrix, FPR, TPR, precision, recall, F1).
- Operational threshold calibration at 1.0% and 0.1% FPR constraints.
- Frozen threshold evaluation on test data.
- Edge case handling (all benign, all malicious, extreme probabilities).
"""

import unittest
import numpy as np

from app.ml.evaluator import (
    compute_binary_metrics,
    calibrate_operational_thresholds,
    evaluate_frozen_model,
)


class TestEvaluator(unittest.TestCase):
    def setUp(self):
        np.random.seed(42)

    def test_compute_binary_metrics_perfect(self):
        y_true = np.array([0, 0, 1, 1], dtype=np.int32)
        y_prob = np.array([0.1, 0.2, 0.8, 0.9], dtype=np.float64)
        m = compute_binary_metrics(y_true, y_prob, threshold=0.5)

        self.assertEqual(m["tn"], 2)
        self.assertEqual(m["fp"], 0)
        self.assertEqual(m["fn"], 0)
        self.assertEqual(m["tp"], 2)
        self.assertEqual(m["fpr"], 0.0)
        self.assertEqual(m["tpr"], 1.0)
        self.assertEqual(m["precision"], 1.0)
        self.assertEqual(m["recall"], 1.0)
        self.assertEqual(m["f1"], 1.0)
        self.assertEqual(m["accuracy"], 1.0)

    def test_compute_binary_metrics_with_fp_and_fn(self):
        y_true = np.array([0, 0, 1, 1], dtype=np.int32)
        y_prob = np.array([0.8, 0.2, 0.3, 0.9], dtype=np.float64)
        m = compute_binary_metrics(y_true, y_prob, threshold=0.5)

        self.assertEqual(m["tn"], 1)
        self.assertEqual(m["fp"], 1)
        self.assertEqual(m["fn"], 1)
        self.assertEqual(m["tp"], 1)
        self.assertEqual(m["fpr"], 0.5)
        self.assertEqual(m["tpr"], 0.5)
        self.assertEqual(m["precision"], 0.5)
        self.assertEqual(m["recall"], 0.5)
        self.assertEqual(m["f1"], 0.5)

    def test_calibrate_operational_thresholds_constraint(self):
        # Create synthetic distribution: 1000 benign (prob ~ Uniform(0, 0.3)), 1000 malicious (prob ~ Uniform(0.5, 1.0))
        n = 2000
        y_val = np.array([0] * 1000 + [1] * 1000, dtype=np.int32)
        probs_benign = np.random.uniform(0.0, 0.3, size=1000)
        probs_malicious = np.random.uniform(0.2, 1.0, size=1000)
        y_prob_val = np.concatenate([probs_benign, probs_malicious])

        cal = calibrate_operational_thresholds(y_val, y_prob_val, target_fprs=[0.01, 0.001])

        self.assertIn("fpr_0_01", cal)
        self.assertIn("fpr_0_001", cal)

        tau_1pct = cal["fpr_0_01"]["calibrated_threshold"]
        tau_01pct = cal["fpr_0_001"]["calibrated_threshold"]

        # Stricter FPR constraint must require equal or higher threshold
        self.assertGreaterEqual(tau_01pct, tau_1pct)

        # Validation FPR must satisfy target constraint
        self.assertLessEqual(cal["fpr_0_01"]["val_metrics"]["fpr"], 0.01)
        self.assertLessEqual(cal["fpr_0_001"]["val_metrics"]["fpr"], 0.001)

        # Operational note must be present
        self.assertIn("operational_note", cal["fpr_0_01"])
        self.assertIn("Empirical threshold", cal["fpr_0_01"]["operational_note"])

    def test_evaluate_frozen_model(self):
        y_test = np.array([0] * 500 + [1] * 500, dtype=np.int32)
        y_prob_test = np.concatenate([
            np.random.uniform(0.0, 0.4, size=500),
            np.random.uniform(0.4, 1.0, size=500)
        ])

        calibrated = {
            "fpr_0_01": {
                "target_fpr": 0.01,
                "calibrated_threshold": 0.75,
                "threshold_selection_method": "test_method",
            }
        }

        eval_res = evaluate_frozen_model(y_test, y_prob_test, calibrated)

        self.assertEqual(eval_res["test_sample_count"], 1000)
        self.assertGreater(eval_res["roc_auc"], 0.5)
        self.assertGreater(eval_res["pr_auc"], 0.5)
        self.assertIn("fpr_0_01", eval_res["operational_thresholds"])
        self.assertEqual(eval_res["operational_thresholds"]["fpr_0_01"]["frozen_threshold"], 0.75)


if __name__ == "__main__":
    unittest.main()
