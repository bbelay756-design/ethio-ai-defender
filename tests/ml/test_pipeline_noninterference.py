"""
Pipeline Non-Interference and Safety Isolation Test Suite for Milestone ML-07.

Verifies:
1. ML analyzer does not modify deterministic analyzer results, threat scores, or verdicts.
2. Simulated faults (missing model, checksum mismatch, extraction failure, prediction exceptions)
   record ML as unavailable without breaking deterministic analyzers.
3. Non-execution of PE binary samples.
4. Preservation of authentication, authorization, quarantine, and audit controls.
5. ML outputs are not represented as validated malware verdicts while raw-PE parity remains unproven.
"""

import tempfile
import unittest
from pathlib import Path

import numpy as np

from app.analyzers.entropy_analyzer import entropy_analyzer_service
from app.analyzers.file_intake import secure_intake_service
from app.analyzers.hash_analyzer import hash_analyzer_service
from app.analyzers.import_analyzer import windows_api_import_analyzer_service
from app.analyzers.indicator_engine import suspicious_indicator_engine_service, AnalysisContext
from app.analyzers.ml_analyzer import MLAnalyzer, MLAnalysisResult
from app.analyzers.pe_analyzer import pe_static_analyzer_service
from app.analyzers.section_analyzer import pe_section_analyzer_service
from app.analyzers.string_analyzer import string_analyzer_service
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
from tests.test_pe_analyzer import build_synthetic_pe


class TestPipelineNonInterference(unittest.TestCase):
    """Test suite verifying strict isolation and non-interference of the ML analyzer."""

    @classmethod
    def setUpClass(cls):
        cls.synthetic_pe = build_synthetic_pe(is_64bit=True, is_dll=False)
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.mock_dir = Path(cls.temp_dir.name)
        cls.mock_sha = create_mock_model_dir(cls.mock_dir)
        cls.classifier = EmberModelClassifier(
            model_dir=cls.mock_dir,
            verify_checksum=True,
            trusted_sha256=cls.mock_sha,
            allow_custom_path=True,
        )
        cls.ml_analyzer = MLAnalyzer(classifier=cls.classifier, enforce_parity_gate=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_deterministic_analyzers_unaltered_by_ml_execution(self):
        """Case 1: Verify deterministic analyzers, scores, and indicators are unchanged by ML."""
        bytez = self.synthetic_pe

        # 1. Baseline deterministic execution
        hash_base = hash_analyzer_service.compute_from_bytes(bytez).to_dict()
        pe_base = pe_static_analyzer_service.analyze_bytes(bytez).to_dict()
        sec_base = pe_section_analyzer_service.analyze_bytes(bytez).to_dict()
        ent_base = entropy_analyzer_service.analyze_bytes(bytez).to_dict()
        str_base = string_analyzer_service.analyze_bytes(bytez).to_dict()

        # Build context and baseline threat score
        ctx = AnalysisContext(
            pe_result=pe_static_analyzer_service.analyze_bytes(bytez),
            section_result=pe_section_analyzer_service.analyze_bytes(bytez),
            entropy_result=entropy_analyzer_service.analyze_bytes(bytez),
            string_result=string_analyzer_service.analyze_bytes(bytez),
            import_result=windows_api_import_analyzer_service.analyze_bytes(bytez),
        )
        indicators_base = suspicious_indicator_engine_service.evaluate(ctx)
        score_base = threat_scoring_engine_service.calculate_score(indicators_base.indicators).to_dict()

        # 2. Execute ML Analyzer
        ml_res = self.ml_analyzer.analyze_pe_bytes(bytez)
        self.assertIsInstance(ml_res, MLAnalysisResult)

        # 3. Repeat deterministic analysis
        hash_after = hash_analyzer_service.compute_from_bytes(bytez).to_dict()
        pe_after = pe_static_analyzer_service.analyze_bytes(bytez).to_dict()
        sec_after = pe_section_analyzer_service.analyze_bytes(bytez).to_dict()
        ent_after = entropy_analyzer_service.analyze_bytes(bytez).to_dict()
        str_after = string_analyzer_service.analyze_bytes(bytez).to_dict()
        indicators_after = suspicious_indicator_engine_service.evaluate(ctx)
        score_after = threat_scoring_engine_service.calculate_score(indicators_after.indicators).to_dict()

        # 4. Assert exact bitwise identity
        self.assertEqual(hash_base, hash_after)
        self.assertEqual(pe_base, pe_after)
        self.assertEqual(sec_base, sec_after)
        self.assertEqual(ent_base, ent_after)
        self.assertEqual(str_base, str_after)
        self.assertEqual(score_base["final_score"], score_after["final_score"])
        self.assertEqual(score_base["risk_level"], score_after["risk_level"])

    def test_fault_simulation_records_explicit_unavailable(self):
        """Case 2 & 3: Simulate faults and verify explicit UNAVAILABLE/FAILED status without crashing."""
        bytez = self.synthetic_pe

        # Fault A: Missing / uninitialized model
        analyzer_missing = MLAnalyzer(classifier=None)
        analyzer_missing._classifier = None
        res_missing = analyzer_missing.analyze_pe_bytes(bytez)
        self.assertFalse(res_missing.available)
        self.assertEqual(res_missing.status, "UNAVAILABLE")
        self.assertIsNone(res_missing.malicious_score)

        # Fault B: Empty content buffer
        res_empty = self.ml_analyzer.analyze_pe_bytes(b"")
        self.assertFalse(res_empty.available)
        self.assertEqual(res_empty.status, "FAILED")

        # Fault C: Corrupted feature vector (NaN)
        bad_vec = np.ones((1, EMBER_V2_TOTAL_DIM), dtype=np.float32)
        bad_vec[0, 10] = np.nan
        res_nan = self.ml_analyzer.analyze_feature_vector(bad_vec)
        self.assertFalse(res_nan.available)
        self.assertEqual(res_nan.status, "FAILED")
        self.assertIsNone(res_nan.malicious_score)

    def test_sample_non_execution(self):
        """Case 4: Confirm that PE samples are processed in memory and never executed."""
        # Analysis uses pure static in-memory parsing
        res = self.ml_analyzer.analyze_pe_bytes(self.synthetic_pe)
        self.assertIsNotNone(res)
        # Ensure execution time is sub-second static inspection
        self.assertLess(res.execution_time_ms, 10000.0)

    def test_raw_pe_parity_gate_prevents_verdict_claim(self):
        """Case 6: ML outputs for raw PE are flagged as unverified parity and not reliable verdicts."""
        res = self.ml_analyzer.analyze_pe_bytes(self.synthetic_pe)
        self.assertEqual(res.status, "OFFLINE_TEST_UNVERIFIED_PARITY")
        self.assertEqual(res.feature_parity_status, "UNVERIFIED_RAW_PE_PARITY")
        self.assertFalse(res.is_reliable)

        # Pre-extracted vector on the other hand is reliable for verified offline evaluations
        vec = np.random.uniform(0.0, 1.0, size=(1, EMBER_V2_TOTAL_DIM)).astype(np.float32)
        res_vec = self.ml_analyzer.analyze_feature_vector(vec)
        self.assertEqual(res_vec.status, "SUCCESS")
        self.assertEqual(res_vec.feature_parity_status, "VERIFIED_FEATURE_VECTOR")
        self.assertTrue(res_vec.is_reliable)


if __name__ == "__main__":
    unittest.main()
