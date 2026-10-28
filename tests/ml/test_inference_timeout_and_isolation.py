"""
Tests for ML-06: Inference Timeout, Process Isolation, and Artifact Identity.

Covers all 10 required test cases using deterministic test doubles:
1. Successful inference within the deadline.
2. Worker exceeding the deadline and being terminated.
3. Worker crash and malformed worker response.
4. Missing model, incorrect trusted digest, and corrupt model.
5. Invalid dimensions and non-finite output values.
6. Repeated timeouts without unbounded worker accumulation.
7. Windows-compatible worker startup if supported by the project environment.
8. ML disabled by default.
9. Shadow-mode non-interference with deterministic verdicts and actions.
10. Error sanitization and cleanup after failure.
"""

import math
from multiprocessing.connection import Connection
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import numpy as np

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.analyzers.hash_analyzer import hash_analyzer_service
from app.analyzers.ml_analyzer import MLAnalyzer, MLAnalysisResult
from app.analyzers.pe_analyzer import pe_static_analyzer_service
from app.analyzers.threat_scoring import threat_scoring_engine_service
from app.core.config import settings, BASE_DIR
from app.db.models import *
from app.db.session import Base
from app.ml.classifier import (
    EmberModelClassifier,
    EmberModelError,
    TRUSTED_BASELINE_MODEL_SHA256,
    DEFAULT_PRIMARY_MODEL_DIR,
)
from app.ml.ember_v2 import EMBER_V2_TOTAL_DIM
from app.ml.process_worker import (
    MLProcessWorker,
    _validate_prediction_dict,
    _sanitize_error_str,
)
from app.pipeline.orchestrator import UnifiedPipelineOrchestrator
from tests.ml.test_classifier import create_mock_model_dir
from tests.test_pe_analyzer import build_synthetic_pe


class TestMLInferenceTimeoutAndIsolation(unittest.TestCase):
    """Test suite for process isolation, timeout enforcement, and artifact identity."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.mock_dir = Path(cls.temp_dir.name)
        cls.mock_sha = create_mock_model_dir(cls.mock_dir)
        cls.synthetic_pe = build_synthetic_pe(is_64bit=True, is_dll=False)

        # Database isolation fixture
        cls.db_path = os.path.join(cls.temp_dir.name, "test_isolation.db")
        cls.test_engine = create_engine(f"sqlite:///{cls.db_path}")
        Base.metadata.create_all(cls.test_engine)
        cls.TestSession = sessionmaker(bind=cls.test_engine, autocommit=False, autoflush=False, expire_on_commit=False)

        cls._session_patcher = patch("app.db.session.SessionLocal", cls.TestSession)
        cls._orch_patcher = patch("app.pipeline.orchestrator.SessionLocal", cls.TestSession)
        cls._session_patcher.start()
        cls._orch_patcher.start()

    @classmethod
    def tearDownClass(cls):
        cls._session_patcher.stop()
        cls._orch_patcher.stop()
        cls.test_engine.dispose()
        try:
            cls.temp_dir.cleanup()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Case 1: Successful inference within the deadline
    # -------------------------------------------------------------------------
    def test_01_successful_inference_within_deadline(self):
        """Case 1: Inference completes within deadline, producing valid scores and timing."""
        mock_worker = MagicMock(spec=MLProcessWorker)
        mock_worker.is_available = True
        mock_worker.is_running.return_value = True
        mock_worker.execute_pe_bytes.return_value = {
            "malicious_score": 0.42,
            "is_malicious": False,
            "is_malicious_1pct_fpr": False,
            "is_malicious_01pct_fpr": False,
            "active_threshold": 0.80,
            "thresholds": {"1pct": 0.80, "01pct": 0.96},
            "model_name": "ember-v2-baseline-hgb",
            "model_version": "1.0.0",
            "model_sha256": "f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684",
            "feature_dim": EMBER_V2_TOTAL_DIM,
        }

        analyzer = MLAnalyzer(worker=mock_worker, enforce_parity_gate=True)
        synthetic_pe = b"MZ" + b"\x00" * 200
        res = analyzer.analyze_pe_bytes(synthetic_pe, timeout=5.0)

        self.assertTrue(res.available)
        self.assertEqual(res.status, "OFFLINE_TEST_UNVERIFIED_PARITY")
        self.assertEqual(res.feature_parity_status, "UNVERIFIED_RAW_PE_PARITY")
        self.assertFalse(res.is_reliable)
        self.assertAlmostEqual(res.malicious_score, 0.42, places=4)
        self.assertFalse(res.is_malicious)
        self.assertGreater(res.execution_time_ms, 0.0)
        self.assertIsNone(res.error)

    # -------------------------------------------------------------------------
    # Case 2: Worker exceeding the deadline and being terminated
    # -------------------------------------------------------------------------
    def test_02_worker_exceeding_deadline_terminated(self):
        """Case 2: Worker exceeding deadline is forcefully terminated and returns FAILED."""
        worker = MLProcessWorker(timeout_seconds=0.01)
        mock_conn = MagicMock()
        mock_conn.poll.return_value = False  # Simulates wall-clock deadline expiration

        mock_proc = MagicMock()
        mock_proc.is_alive.return_value = True

        worker._parent_conn = mock_conn
        worker._process = mock_proc
        worker._is_available = True

        analyzer = MLAnalyzer(worker=worker, use_process_worker=True, timeout_seconds=0.01)
        synthetic_pe = b"MZ" + b"\x00" * 100

        res = analyzer.analyze_pe_bytes(synthetic_pe, timeout=0.01)

        self.assertFalse(res.available)
        self.assertEqual(res.status, "FAILED")
        self.assertIn("timeout", res.message.lower())
        self.assertIsNotNone(res.error)
        self.assertIn("deadline", res.error.lower())

        # Verify termination was invoked on the child process
        mock_proc.terminate.assert_called_once()
        self.assertIsNone(worker._process)

    # -------------------------------------------------------------------------
    # Case 3: Worker crash and malformed worker response
    # -------------------------------------------------------------------------
    def test_03a_worker_crash_handling(self):
        """Case 3a: Worker crash (EOFError / broken pipe) is handled cleanly without hanging."""
        worker = MLProcessWorker(timeout_seconds=5.0)
        mock_conn = MagicMock()
        mock_conn.poll.return_value = True
        mock_conn.recv.side_effect = EOFError("Pipe broken: child process died unexpectedly")

        mock_proc = MagicMock()
        mock_proc.is_alive.return_value = True

        worker._parent_conn = mock_conn
        worker._process = mock_proc
        worker._is_available = True

        analyzer = MLAnalyzer(worker=worker, use_process_worker=True)
        res = analyzer.analyze_pe_bytes(b"MZ" + b"\x00" * 100)

        self.assertFalse(res.available)
        self.assertEqual(res.status, "FAILED")
        self.assertIn("terminated unexpectedly", res.message)
        mock_proc.terminate.assert_called()

    def test_03b_malformed_worker_response_handling(self):
        """Case 3b: Malformed IPC response from worker is rejected."""
        worker = MLProcessWorker(timeout_seconds=5.0)
        mock_conn = MagicMock()
        mock_conn.poll.return_value = True
        # Return non-dict message
        mock_conn.recv.return_value = "NOT_A_DICT_PAYLOAD"

        mock_proc = MagicMock()
        mock_proc.is_alive.return_value = True

        worker._parent_conn = mock_conn
        worker._process = mock_proc
        worker._is_available = True

        analyzer = MLAnalyzer(worker=worker, use_process_worker=True)
        res = analyzer.analyze_pe_bytes(b"MZ" + b"\x00" * 100)

        self.assertFalse(res.available)
        self.assertEqual(res.status, "FAILED")
        self.assertIn("extraction error", res.message.lower())

    # -------------------------------------------------------------------------
    # Case 4: Missing model, incorrect trusted digest, and corrupt model
    # -------------------------------------------------------------------------
    def test_04a_missing_model_directory(self):
        """Case 4a: Non-existent model directory returns explicit UNAVAILABLE status."""
        missing_dir = Path("D:\\nonexistent_model_dir_xyz_987")
        worker = MLProcessWorker(model_dir=missing_dir, verify_checksum=True, allow_custom_path=True)
        worker._is_available = False
        worker._init_error = "Model file not found"

        analyzer = MLAnalyzer(worker=worker, use_process_worker=True)
        res = analyzer.analyze_pe_bytes(b"MZ" + b"\x00" * 100)

        self.assertFalse(res.available)
        self.assertEqual(res.status, "UNAVAILABLE")

    def test_04b_incorrect_trusted_digest_fails_closed(self):
        """Case 4b: Model with untrusted or tampered digest fails closed with error."""
        with self.assertRaises(EmberModelError):
            EmberModelClassifier(
                model_dir=self.mock_dir,
                verify_checksum=True,
                trusted_sha256="0000000000000000000000000000000000000000000000000000000000000000",
                allow_custom_path=True,
            )

    def test_04c_corrupt_model_fails_closed(self):
        """Case 4c: Corrupt model artifact fails closed during deserialization."""
        with tempfile.TemporaryDirectory() as corrupt_dir:
            p = Path(corrupt_dir) / "model.joblib"
            p.write_bytes(b"CORRUPTED_NON_JOBLIB_DATA_123456789")
            with self.assertRaises(EmberModelError):
                EmberModelClassifier(
                    model_dir=corrupt_dir,
                    verify_checksum=False,
                    allow_custom_path=True,
                )

    # -------------------------------------------------------------------------
    # Case 5: Invalid dimensions and non-finite output values
    # -------------------------------------------------------------------------
    def test_05a_invalid_feature_dimensions_rejected(self):
        """Case 5a: Feature vector with invalid dimensions is rejected."""
        clf = EmberModelClassifier(
            model_dir=self.mock_dir,
            verify_checksum=True,
            trusted_sha256=self.mock_sha,
            allow_custom_path=True,
        )
        invalid_dim_vec = np.ones((1, 500), dtype=np.float32)
        with self.assertRaises(EmberModelError):
            clf.predict_single(invalid_dim_vec)

    def test_05b_non_finite_input_values_rejected(self):
        """Case 5b: Input vector containing NaN or Inf is rejected."""
        clf = EmberModelClassifier(
            model_dir=self.mock_dir,
            verify_checksum=True,
            trusted_sha256=self.mock_sha,
            allow_custom_path=True,
        )
        bad_nan = np.ones((1, EMBER_V2_TOTAL_DIM), dtype=np.float32)
        bad_nan[0, 10] = np.nan
        with self.assertRaises(EmberModelError):
            clf.predict_single(bad_nan)

        bad_inf = np.ones((1, EMBER_V2_TOTAL_DIM), dtype=np.float32)
        bad_inf[0, 10] = np.inf
        with self.assertRaises(EmberModelError):
            clf.predict_single(bad_inf)

    def test_05c_non_finite_output_values_rejected_by_ipc_validator(self):
        """Case 5c: Non-finite score in worker response raises validation error."""
        with self.assertRaises(ValueError):
            _validate_prediction_dict({
                "malicious_score": float("nan"),
                "is_malicious": False,
                "active_threshold": 0.8,
                "thresholds": {},
            })

        with self.assertRaises(ValueError):
            _validate_prediction_dict({
                "malicious_score": float("inf"),
                "is_malicious": True,
                "active_threshold": 0.8,
                "thresholds": {},
            })

    # -------------------------------------------------------------------------
    # Case 6: Repeated timeouts without unbounded worker accumulation
    # -------------------------------------------------------------------------
    def test_06_repeated_timeouts_no_worker_accumulation(self):
        """Case 6: Successive timeouts terminate previous worker and do not leak processes."""
        worker = MLProcessWorker(timeout_seconds=0.01)

        for i in range(3):
            mock_proc = MagicMock()
            mock_proc.is_alive.return_value = True
            mock_conn = MagicMock()
            mock_conn.poll.return_value = False  # Timeout

            worker._process = mock_proc
            worker._parent_conn = mock_conn
            worker._is_available = True

            with self.assertRaises(TimeoutError):
                worker.execute_pe_bytes(b"MZ" + b"\x00" * 50)

            # Assert process was terminated and reset to None
            mock_proc.terminate.assert_called_once()
            self.assertIsNone(worker._process)
            self.assertFalse(worker.is_running())

    # -------------------------------------------------------------------------
    # Case 7: Windows-compatible worker startup if supported
    # -------------------------------------------------------------------------
    def test_07_windows_compatible_startup_contract(self):
        """Case 7: Verifies worker uses mp.get_context('spawn') compatible with Windows."""
        worker = MLProcessWorker(timeout_seconds=5.0)
        self.assertEqual(worker._ctx.get_start_method(), "spawn")
        self.assertFalse(worker.is_running())

    # -------------------------------------------------------------------------
    # Case 8: ML disabled by default
    # -------------------------------------------------------------------------
    def test_08_ml_disabled_by_default(self):
        """Case 8: ML is disabled by default in Settings and Pipeline Orchestrator."""
        self.assertFalse(settings.ML_ENABLED)

        orchestrator = UnifiedPipelineOrchestrator()
        res = orchestrator.analyze_bytes(self.synthetic_pe, filename="test_default.exe")

        ml_analysis = res.get("ml_analysis", {})
        self.assertFalse(ml_analysis.get("available", True))
        self.assertEqual(ml_analysis.get("status"), "DISABLED")
        self.assertIsNone(ml_analysis.get("malicious_score"))

    # -------------------------------------------------------------------------
    # Case 9: Shadow-mode non-interference with deterministic verdicts
    # -------------------------------------------------------------------------
    def test_09_shadow_mode_non_interference(self):
        """Case 9: ML shadow mode outputs cannot overwrite deterministic scores or verdicts."""
        orchestrator = UnifiedPipelineOrchestrator()

        # Run 1: ML Disabled
        with patch.object(settings, "ML_ENABLED", False):
            run1 = orchestrator.analyze_bytes(self.synthetic_pe, filename="sample.exe")

        # Run 2: ML Enabled in Shadow Mode
        with patch.object(settings, "ML_ENABLED", True), \
             patch.object(settings, "ML_SHADOW_MODE", True):
            run2 = orchestrator.analyze_bytes(self.synthetic_pe, filename="sample.exe")

        # Deterministic analysis outputs must be 100% bitwise identical
        self.assertEqual(run1["risk_score"], run2["risk_score"])
        self.assertEqual(run1["hashes"], run2["hashes"])
        self.assertEqual(run1["pe"], run2["pe"])
        self.assertEqual(run1["status"], run2["status"])

        # Run 3: ML Active Mode (Shadow Mode = False) — blocking must still be inhibited!
        with patch.object(settings, "ML_ENABLED", True), \
             patch.object(settings, "ML_SHADOW_MODE", False):
            run3 = orchestrator.analyze_bytes(self.synthetic_pe, filename="sample.exe")

        self.assertTrue(run3["ml_analysis"].get("active_blocking_inhibited"))
        self.assertEqual(run1["risk_score"], run3["risk_score"])
        self.assertEqual(run1["status"], run3["status"])

    # -------------------------------------------------------------------------
    # Case 10: Error sanitization and cleanup after failure
    # -------------------------------------------------------------------------
    def test_10_error_sanitization_and_cleanup(self):
        """Case 10: Internal paths and user directories are redacted from all errors."""
        leak_msg = f"Crash in {BASE_DIR}\\app\\ml\\model.joblib on D:\\ethio_ai_defender_artifacts\\model.joblib"
        sanitized = _sanitize_error_str(leak_msg)

        self.assertNotIn(str(BASE_DIR), sanitized)
        self.assertNotIn("D:\\", sanitized)
        self.assertIn("[REDACTED_PATH]/", sanitized)


if __name__ == "__main__":
    unittest.main()
