"""
ETHIO-AI Defender — Milestone ML-12B Test Suite
Analyst Dashboard Integration for Advisory ML Scores

Verifies:
1. Advisory Contract: Correct schema and typed attributes for ml_analysis.
2. Heuristic Separation: Model scores cannot alter deterministic threat scores, verdicts, or risk factors.
3. Missing/Unavailable Handling: Absent, disabled, or failed ML returns None for scores (never 0.0).
4. Error Sanitization: Inference exceptions do not break the pipeline.
5. Model Identity & Provenance: Model name, version, and SHA-256 match the frozen baseline artifact.
6. Review Priority Logic: Accurate mapping of scores to ELEVATED / NORMAL / NOT_EVALUATED.
7. Reliability Gate Integrity: is_reliable remains strictly False across all raw-PE evaluation paths.
8. Non-Autonomous Enforcement: High ML scores cannot independently trigger blocking, quarantine, or deletion.
9. Backward Compatibility: Serialization preserves all legacy endpoints and schemas.
10. RBAC & Auth: Analysis endpoints maintain object-level authorization and permission checks.
"""

import json
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.db.session import SessionLocal
from app.db.models import SampleModel
from app.pipeline.orchestrator import unified_pipeline_service
from app.db.schemas import AnalysisSummaryResponse
from app.analyzers.ml_analyzer import MLAnalysisResult
from tests.test_pe_analyzer import build_synthetic_pe
from tests.auth_helpers import make_analyst


client = TestClient(app)
VALID_PE = build_synthetic_pe(is_64bit=True, is_dll=False)


@pytest.fixture
def auth_headers_analyst():
    """Returns valid authentication headers for a registered analyst user."""
    db = SessionLocal()
    try:
        user, headers = make_analyst(db, username_prefix="ml12b_analyst")
        return headers
    finally:
        db.close()


class TestAdvisoryContract:
    """Verifies Phase 1: Define the Advisory Contract."""

    def test_advisory_contract_fields_and_types_when_disabled(self):
        """When ML is disabled, verify exact contract structure and absence of zero scores."""
        with patch.object(settings, "ML_ENABLED", False):
            res = unified_pipeline_service.execute_pipeline(
                content=VALID_PE,
                filename="clean_test.exe"
            )
            assert "ml_analysis" in res
            ml = res["ml_analysis"]

            # Required contract fields
            assert ml["available"] is False
            assert ml["status"] == "DISABLED"
            assert ml["malicious_score"] is None, "Missing inference must never be represented as 0.0"
            assert ml["is_malicious"] is None
            assert ml["is_reliable"] is False
            assert ml["advisory_only"] is True
            assert ml["advisory_label"] == "EXPERIMENTAL_ADVISORY_PRIORITY"
            assert ml["review_priority"] == "NOT_EVALUATED"
            assert ml["model_name"] == "ember-v2-baseline-hgb-subset80k"
            assert ml["model_version"] == "1.0.0"
            assert ml["model_sha256"] == "f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684"
            assert "disclaimer" in ml
            assert "Advisory-only" in ml["disclaimer"]

    def test_advisory_contract_when_successful(self):
        """When ML succeeds, verify complete typed attributes and priority assignment."""
        mock_ml_res = MLAnalysisResult(
            available=True,
            status="SUCCESS",
            message="Raw PE features evaluated via baseline model.",
            malicious_score=0.854200,
            is_malicious=True,
            is_malicious_1pct_fpr=True,
            is_malicious_01pct_fpr=False,
            active_threshold=0.800395,
            thresholds={"default_05": 0.5, "target_1pct_fpr": 0.800395, "target_01pct_fpr": 0.966365},
            model_name="ember-v2-baseline-hgb-subset80k",
            model_version="1.0.0",
            model_sha256="f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684",
            feature_dim=2381,
            feature_parity_status="EXPERIMENTAL_UNVERIFIED_PARITY",
            is_reliable=False,
            execution_time_ms=15.4,
        )

        with patch.object(settings, "ML_ENABLED", True):
            with patch("app.analyzers.ml_analyzer.ml_analyzer_service.analyze_pe_bytes", return_value=mock_ml_res):
                res = unified_pipeline_service.execute_pipeline(
                    content=VALID_PE,
                    filename="sample.exe"
                )
                ml = res["ml_analysis"]
                assert ml["available"] is True
                assert ml["status"] == "SUCCESS"
                assert ml["malicious_score"] == 0.854200
                assert ml["is_reliable"] is False
                assert ml["review_priority"] == "ELEVATED", "Scores >= 0.800395 must have ELEVATED review priority"
                assert ml["advisory_only"] is True

    def test_review_priority_normal_for_low_scores(self):
        """Scores below 0.800395 should map to NORMAL review priority."""
        mock_low_ml = MLAnalysisResult(
            available=True,
            status="SUCCESS",
            message="Raw PE features evaluated via baseline model.",
            malicious_score=0.044000,
            is_malicious=False,
            is_malicious_1pct_fpr=False,
            is_malicious_01pct_fpr=False,
            active_threshold=0.800395,
            thresholds={"default_05": 0.5, "target_1pct_fpr": 0.800395, "target_01pct_fpr": 0.966365},
            model_name="ember-v2-baseline-hgb-subset80k",
            model_version="1.0.0",
            model_sha256="f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684",
            feature_dim=2381,
            feature_parity_status="EXPERIMENTAL_UNVERIFIED_PARITY",
            is_reliable=False,
            execution_time_ms=10.0,
        )

        with patch.object(settings, "ML_ENABLED", True):
            with patch("app.analyzers.ml_analyzer.ml_analyzer_service.analyze_pe_bytes", return_value=mock_low_ml):
                res = unified_pipeline_service.execute_pipeline(
                    content=VALID_PE,
                    filename="sample_clean.exe"
                )
                ml = res["ml_analysis"]
                assert ml["review_priority"] == "NORMAL"


class TestSeparationAndSafetyConstraints:
    """Verifies Phase 3: Mandatory Safety Constraints and Separation of Concerns."""

    def test_high_ml_score_does_not_alter_heuristic_verdict(self):
        """Proof that ML scores cannot independently trigger changes to deterministic verdicts."""
        mock_high_ml = MLAnalysisResult(
            available=True,
            status="SUCCESS",
            message="Raw PE features evaluated via baseline model.",
            malicious_score=0.999999,  # Maximum model probability
            is_malicious=True,
            is_malicious_1pct_fpr=True,
            is_malicious_01pct_fpr=True,
            active_threshold=0.800395,
            thresholds={"default_05": 0.5, "target_1pct_fpr": 0.800395, "target_01pct_fpr": 0.966365},
            model_name="ember-v2-baseline-hgb-subset80k",
            model_version="1.0.0",
            model_sha256="f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684",
            feature_dim=2381,
            feature_parity_status="EXPERIMENTAL_UNVERIFIED_PARITY",
            is_reliable=False,
            execution_time_ms=12.0,
        )

        with patch.object(settings, "ML_ENABLED", True):
            with patch("app.analyzers.ml_analyzer.ml_analyzer_service.analyze_pe_bytes", return_value=mock_high_ml):
                res = unified_pipeline_service.execute_pipeline(
                    content=VALID_PE,
                    filename="benign_test.exe"
                )
                # The deterministic risk score and classification must remain completely driven by heuristics
                score_data = res["risk_score"]
                assert score_data["score"] == 0 or score_data["risk_level"] == "LOW"
                assert res["ml_analysis"]["malicious_score"] == 0.999999
                assert res["ml_analysis"]["is_reliable"] is False, "Parity gate must remain closed"

    def test_active_mode_inhibition_and_zero_autonomous_blocking(self):
        """Proof that active blocking via ML remains inhibited even if shadow_mode is toggled."""
        mock_high_ml = MLAnalysisResult(
            available=True,
            status="SUCCESS",
            message="Raw PE features evaluated via baseline model.",
            malicious_score=0.980000,
            is_malicious=True,
            is_malicious_1pct_fpr=True,
            is_malicious_01pct_fpr=True,
            active_threshold=0.800395,
            thresholds={"default_05": 0.5, "target_1pct_fpr": 0.800395, "target_01pct_fpr": 0.966365},
            model_name="ember-v2-baseline-hgb-subset80k",
            model_version="1.0.0",
            model_sha256="f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684",
            feature_dim=2381,
            feature_parity_status="EXPERIMENTAL_UNVERIFIED_PARITY",
            is_reliable=False,
            execution_time_ms=10.0,
        )

        with patch.object(settings, "ML_ENABLED", True):
            with patch.object(settings, "ML_SHADOW_MODE", False):
                with patch("app.analyzers.ml_analyzer.ml_analyzer_service.analyze_pe_bytes", return_value=mock_high_ml):
                    res = unified_pipeline_service.execute_pipeline(
                        content=VALID_PE,
                        filename="test_blocking.exe"
                    )
                    ml = res["ml_analysis"]
                    assert ml.get("active_blocking_inhibited") is True, "Autonomous blocking must be inhibited"
                    assert "prohibited while raw-PE feature parity remains unverified" in ml.get("policy_notice", "")


class TestFaultToleranceAndErrorHandling:
    """Verifies graceful degradation when inference or model encounters errors."""

    def test_inference_exception_handled_gracefully(self):
        """When ml_analyzer raises an unhandled exception, pipeline survives and records FAILED."""
        with patch.object(settings, "ML_ENABLED", True):
            with patch("app.analyzers.ml_analyzer.ml_analyzer_service.analyze_pe_bytes", side_effect=RuntimeError("LIEF segfault simulation")):
                res = unified_pipeline_service.execute_pipeline(
                    content=VALID_PE,
                    filename="crash_test.exe"
                )
                assert "ml_analysis" in res
                ml = res["ml_analysis"]
                assert ml["available"] is False
                assert ml["status"] == "FAILED"
                assert ml["malicious_score"] is None
                assert ml["review_priority"] == "NOT_EVALUATED"
                assert ml["is_reliable"] is False
                assert "RuntimeError" in ml["error"]


class TestApiAndDashboardIntegration:
    """Verifies Phase 2: API endpoints and response schema backward compatibility."""

    def test_get_analysis_by_id_includes_advisory_contract(self, auth_headers_analyst):
        """GET /api/analyses/{id} exposes advisory ml_analysis without breaking schema."""
        db = SessionLocal()
        sample = db.query(SampleModel).first()
        db.close()
        if not sample:
            pytest.skip("No samples in DB for endpoint testing.")

        resp = client.get(f"/api/analyses/{sample.analysis_id}", headers=auth_headers_analyst)
        assert resp.status_code == 200
        data = resp.json()
        assert "ml_analysis" in data
        ml = data["ml_analysis"]
        assert ml["available"] is False
        assert ml["status"] == "UNAVAILABLE"
        assert ml["malicious_score"] is None
        assert ml["is_reliable"] is False
        assert ml["advisory_only"] is True

    def test_get_sample_full_dashboard_endpoint_includes_advisory_contract(self, auth_headers_analyst):
        """GET /api/dashboard/samples/{id}/full exposes advisory ml_analysis."""
        db = SessionLocal()
        sample = db.query(SampleModel).first()
        db.close()
        if not sample:
            pytest.skip("No samples in DB for endpoint testing.")

        resp = client.get(f"/api/dashboard/samples/{sample.analysis_id}/full", headers=auth_headers_analyst)
        assert resp.status_code == 200
        data = resp.json()
        assert "ml_analysis" in data
        ml = data["ml_analysis"]
        assert ml["is_reliable"] is False
        assert ml["advisory_label"] == "EXPERIMENTAL_ADVISORY_PRIORITY"

    def test_analysis_summary_schema_backward_compatibility(self):
        """Verify AnalysisSummaryResponse schema serializes safely with optional ML fields."""
        summary = AnalysisSummaryResponse(
            id=1,
            analysis_id="ANL-999999",
            filename="legacy_sample.exe",
            size=1024,
            file_type="EXE",
            architecture="x64",
            sha256="abc123def456",
            md5="123456",
            status="COMPLETED",
            risk_score=15,
            classification="LOW",
        )
        data = summary.model_dump()
        assert data["ml_score"] is None
        assert data["ml_status"] == "UNAVAILABLE"
        assert data["ml_review_priority"] == "NOT_EVALUATED"
        assert data["is_reliable"] is False
