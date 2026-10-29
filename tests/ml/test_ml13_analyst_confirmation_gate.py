"""
ETHIO-AI Defender — Milestone ML-13 Test Suite
Active Learning & Cascaded Rejection Gate (Analyst-Confirmation Gate)

Verifies:
1. High ML score without supporting deterministic evidence enters PENDING_REVIEW (Cascaded Rejection Gate).
2. Low ML score enters NORMAL_MONITORING without review requirement.
3. Deterministic YARA rules and heuristic scores take precedence over ML (DETERMINISTIC_ALERT).
4. Missing model, disabled inference, failure, and timeout result in NOT_EVALUATED gate state.
5. Role-Based Access Control: ANALYST and ADMIN can submit reviews; VIEWER receives 403; Unauthenticated receives 401.
6. State Transitions & Audit Logging: Decisions (CONFIRMED_MALWARE, REJECTED_FALSE_POSITIVE, BENIGN_UTILITY)
   log structured audit events without mutating deterministic evidence.
7. Duplicate reviews return 409 Conflict; input validation rejects empty rationale and invalid verdicts.
8. API Endpoints: GET /api/analyses/{id} and GET /api/analyses/{id}/reviews reflect review metadata.
9. Absolute Non-Authority of ML: Model scores cannot trigger quarantine, blocking, or verdict elevation.
"""

import json
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.db.session import SessionLocal
from app.db.models import SampleModel, AnalystReviewModel, AuditLogModel
from app.db.repository import SampleRepository
from app.db.schemas import SampleCreate
from app.pipeline.orchestrator import unified_pipeline_service
from app.analyzers.ml_analyzer import MLAnalysisResult
from tests.test_pe_analyzer import build_synthetic_pe
from tests.auth_helpers import make_analyst, make_admin, make_viewer


client = TestClient(app)
VALID_PE = build_synthetic_pe(is_64bit=True, is_dll=False)


@pytest.fixture
def auth_headers_analyst():
    db = SessionLocal()
    try:
        user, headers = make_analyst(db, username_prefix="ml13_analyst")
        return headers
    finally:
        db.close()


@pytest.fixture
def auth_headers_admin():
    db = SessionLocal()
    try:
        user, headers = make_admin(db, username_prefix="ml13_admin")
        return headers
    finally:
        db.close()


@pytest.fixture
def auth_headers_viewer():
    db = SessionLocal()
    try:
        user, headers = make_viewer(db, username_prefix="ml13_viewer")
        return headers
    finally:
        db.close()


class TestCascadedRejectionGatePipeline:
    """Verifies pipeline gate evaluation logic under different ML and deterministic conditions."""

    def test_high_ml_score_without_deterministic_evidence_enters_pending_review(self):
        """High ML score with 0 YARA and low heuristic score must trigger PENDING_REVIEW."""
        mock_ml = MLAnalysisResult(
            available=True,
            status="SUCCESS",
            message="Feature vector inference complete.",
            malicious_score=0.892400,
            is_malicious=True,
            active_threshold=0.800395,
            model_name="ember-v2-baseline-hgb-subset80k",
            model_version="1.0.0",
            model_sha256="f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684",
            feature_dim=2381,
            feature_parity_status="EXPERIMENTAL_UNVERIFIED_PARITY",
            is_reliable=False,
            execution_time_ms=18.5,
        )

        with patch.object(settings, "ML_ENABLED", True):
            with patch("app.analyzers.ml_analyzer.ml_analyzer_service.analyze_pe_bytes", return_value=mock_ml):
                res = unified_pipeline_service.execute_pipeline(
                    content=VALID_PE,
                    filename="suspicious_ml_only.exe"
                )

                assert "ml_analysis" in res
                ml = res["ml_analysis"]

                # Gate state assertions
                assert ml["rejection_gate_state"] == "PENDING_REVIEW"
                assert ml["review_status"] == "PENDING_REVIEW"
                assert ml["requires_analyst_review"] is True
                assert ml["review_priority"] == "ELEVATED"
                assert "LIM-01" in ml["rejection_gate_reason"] or "base-rate" in ml["rejection_gate_reason"]

                # Deterministic separation: Threat score and heuristic risk level remain low
                assert res["risk_score"]["score"] < 70
                assert res["risk_score"]["risk_level"] in ("LOW", "MODERATE")
                assert ml["is_reliable"] is False
                assert ml["active_blocking_inhibited"] is True

    def test_low_ml_score_enters_normal_monitoring(self):
        """Low ML score (< 0.800395) enters NORMAL_MONITORING without requiring review."""
        mock_ml = MLAnalysisResult(
            available=True,
            status="SUCCESS",
            message="Feature vector inference complete.",
            malicious_score=0.045100,
            is_malicious=False,
            active_threshold=0.800395,
            model_name="ember-v2-baseline-hgb-subset80k",
            model_version="1.0.0",
            model_sha256="f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684",
            feature_dim=2381,
            feature_parity_status="EXPERIMENTAL_UNVERIFIED_PARITY",
            is_reliable=False,
            execution_time_ms=12.1,
        )

        with patch.object(settings, "ML_ENABLED", True):
            with patch("app.analyzers.ml_analyzer.ml_analyzer_service.analyze_pe_bytes", return_value=mock_ml):
                res = unified_pipeline_service.execute_pipeline(
                    content=VALID_PE,
                    filename="benign_sample.exe"
                )

                ml = res["ml_analysis"]
                assert ml["rejection_gate_state"] == "NORMAL_MONITORING"
                assert ml["review_status"] == "NOT_REQUIRED"
                assert ml["requires_analyst_review"] is False
                assert ml["review_priority"] == "NORMAL"

    def test_deterministic_evidence_takes_precedence_over_ml(self):
        """When deterministic signatures exist, gate transitions to DETERMINISTIC_ALERT."""
        mock_ml = MLAnalysisResult(
            available=True,
            status="SUCCESS",
            message="Inference complete.",
            malicious_score=0.915000,
            is_malicious=True,
            active_threshold=0.800395,
            is_reliable=False,
        )

        from app.analyzers.yara_analyzer import YaraScanResult, YaraMatchItem
        mock_yara = YaraScanResult(
            available=True,
            total_matches=1,
            matches=[
                YaraMatchItem(
                    rule_name="Trojan_Dropper_Sample",
                    namespace="malware",
                    tags=["apt", "dropper"],
                    description="Detects dropper payload signature"
                )
            ]
        )

        with patch.object(settings, "ML_ENABLED", True):
            with patch("app.analyzers.ml_analyzer.ml_analyzer_service.analyze_pe_bytes", return_value=mock_ml):
                with patch("app.analyzers.yara_analyzer.yara_analyzer_service.scan_bytes_with_db_rules", return_value=mock_yara):
                    res = unified_pipeline_service.execute_pipeline(
                        content=VALID_PE,
                        filename="known_trojan.exe"
                    )

                    ml = res["ml_analysis"]
                    # Deterministic evidence governs
                    assert ml["rejection_gate_state"] == "DETERMINISTIC_ALERT"
                    assert ml["review_status"] == "NOT_REQUIRED"
                    assert ml["requires_analyst_review"] is False
                    assert "Trojan_Dropper_Sample" in str(res["yara_matches"])

    def test_missing_model_and_disabled_inference_yield_not_evaluated(self):
        """Disabled or unavailable ML yields NOT_EVALUATED and inactive gate."""
        with patch.object(settings, "ML_ENABLED", False):
            res = unified_pipeline_service.execute_pipeline(
                content=VALID_PE,
                filename="disabled_ml.exe"
            )
            ml = res["ml_analysis"]
            assert ml["rejection_gate_state"] == "NOT_EVALUATED"
            assert ml["review_status"] == "NOT_EVALUATED"
            assert ml["requires_analyst_review"] is False

    def test_inference_failure_or_timeout_yield_not_evaluated(self):
        """Inference error or timeout degrades safely to NOT_EVALUATED."""
        mock_ml = MLAnalysisResult(
            available=False,
            status="FAILED",
            message="Model timeout exceeded deadline.",
            malicious_score=None,
            is_reliable=False,
            error="TimeoutError",
        )

        with patch.object(settings, "ML_ENABLED", True):
            with patch("app.analyzers.ml_analyzer.ml_analyzer_service.analyze_pe_bytes", return_value=mock_ml):
                res = unified_pipeline_service.execute_pipeline(
                    content=VALID_PE,
                    filename="timeout_sample.exe"
                )
                ml = res["ml_analysis"]
                assert ml["rejection_gate_state"] == "NOT_EVALUATED"
                assert ml["review_status"] == "NOT_EVALUATED"
                assert ml["requires_analyst_review"] is False


class TestAnalystReviewApiAndRbac:
    """Verifies REST API endpoints, permissions, validations, and audit logs."""

    @pytest.fixture
    def sample_record(self):
        """Seeds a sample record in the isolated test database."""
        db = SessionLocal()
        try:
            import uuid
            analysis_id = f"ANL-TEST-{uuid.uuid4().hex[:8]}"
            sample = SampleRepository.create_sample(
                db=db,
                sample_in=SampleCreate(
                    analysis_id=analysis_id,
                    filename="test_target.exe",
                    size=1024,
                    file_type="EXE",
                    architecture="x64",
                    md5="0123456789abcdef0123456789abcdef",
                    sha1="0123456789abcdef0123456789abcdef01234567",
                    sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    status="COMPLETED",
                    risk_score=25,
                    classification="MODERATE",
                )
            )
            return sample.analysis_id
        finally:
            db.close()

    def test_viewer_role_cannot_submit_review(self, sample_record, auth_headers_viewer):
        """VIEWER role receives HTTP 403 Forbidden when attempting to submit a review."""
        payload = {
            "verdict": "CONFIRMED_MALWARE",
            "rationale": "Viewer attempting unauthorized confirmation."
        }
        resp = client.post(
            f"/api/analyses/{sample_record}/reviews",
            headers=auth_headers_viewer,
            json=payload
        )
        assert resp.status_code == 403
        assert "permission" in resp.text.lower() or "forbidden" in resp.text.lower()

    def test_unauthenticated_request_rejected(self, sample_record):
        """Unauthenticated review request receives HTTP 401 Unauthorized."""
        payload = {
            "verdict": "REJECTED_FALSE_POSITIVE",
            "rationale": "Unauthenticated submission."
        }
        resp = client.post(
            f"/api/analyses/{sample_record}/reviews",
            json=payload
        )
        assert resp.status_code == 401

    def test_analyst_can_confirm_threat_with_audit_trail(self, sample_record, auth_headers_analyst):
        """ANALYST role can submit CONFIRMED_MALWARE and generates structured audit entry."""
        payload = {
            "verdict": "CONFIRMED_MALWARE",
            "rationale": "Manual disassembly reveals unpacked malicious shellcode staging."
        }
        resp = client.post(
            f"/api/analyses/{sample_record}/reviews",
            headers=auth_headers_analyst,
            json=payload
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["analysis_id"] == sample_record
        assert data["verdict"] == "CONFIRMED_MALWARE"
        assert data["review_state"] == "ANALYST_CONFIRMED"
        assert data["previous_state"] == "PENDING_REVIEW"
        assert "unpacked malicious shellcode" in data["rationale"]

        # Verify audit log persistence
        db = SessionLocal()
        try:
            audit_entry = db.query(AuditLogModel).filter(
                AuditLogModel.analysis_id == sample_record,
                AuditLogModel.event == "analyst review"
            ).first()
            assert audit_entry is not None
            assert audit_entry.result == "SUCCESS"
            assert "CONFIRMED_MALWARE" in (audit_entry.details_json or "")
        finally:
            db.close()

    def test_duplicate_review_request_returns_409_conflict(self, sample_record, auth_headers_analyst):
        """Submitting a second review on the same analysis returns HTTP 409 Conflict."""
        payload = {
            "verdict": "REJECTED_FALSE_POSITIVE",
            "rationale": "Internal diagnostic tool verified against vendor manifest."
        }
        # First submission
        resp1 = client.post(
            f"/api/analyses/{sample_record}/reviews",
            headers=auth_headers_analyst,
            json=payload
        )
        assert resp1.status_code == 201

        # Second submission
        resp2 = client.post(
            f"/api/analyses/{sample_record}/reviews",
            headers=auth_headers_analyst,
            json=payload
        )
        assert resp2.status_code == 409
        assert "already been reviewed" in resp2.json()["detail"]

    def test_empty_rationale_rejected_with_400(self, sample_record, auth_headers_analyst):
        """Review submission with whitespace-only rationale is rejected with HTTP 400."""
        payload = {
            "verdict": "CONFIRMED_MALWARE",
            "rationale": "    "
        }
        resp = client.post(
            f"/api/analyses/{sample_record}/reviews",
            headers=auth_headers_analyst,
            json=payload
        )
        assert resp.status_code == 400
        assert "rationale cannot be empty" in resp.json()["detail"].lower()

    def test_invalid_verdict_rejected_with_400(self, sample_record, auth_headers_analyst):
        """Unrecognized verdict string returns HTTP 400."""
        payload = {
            "verdict": "MAYBE_MALWARE_NOT_SURE",
            "rationale": "Uncertain finding."
        }
        resp = client.post(
            f"/api/analyses/{sample_record}/reviews",
            headers=auth_headers_analyst,
            json=payload
        )
        assert resp.status_code == 400
        assert "invalid verdict" in resp.json()["detail"].lower()

    def test_get_analysis_by_id_and_review_history(self, sample_record, auth_headers_admin):
        """GET /api/analyses/{id} and /reviews expose populated review metadata."""
        # Submit a benign utility confirmation
        payload = {
            "verdict": "BENIGN_UTILITY",
            "rationale": "Commercial administration utility signed by known vendor."
        }
        submit_resp = client.post(
            f"/api/analyses/{sample_record}/reviews",
            headers=auth_headers_admin,
            json=payload
        )
        assert submit_resp.status_code == 201

        # Fetch analysis detail
        get_resp = client.get(
            f"/api/analyses/{sample_record}",
            headers=auth_headers_admin
        )
        assert get_resp.status_code == 200
        analysis_data = get_resp.json()

        assert "reviews" in analysis_data
        assert len(analysis_data["reviews"]) == 1
        rev = analysis_data["reviews"][0]
        assert rev["verdict"] == "BENIGN_UTILITY"
        assert rev["review_state"] == "BENIGN_CONFIRMED"

        ml_section = analysis_data["ml_analysis"]
        assert ml_section["review_status"] == "BENIGN_CONFIRMED"
        assert ml_section["rejection_gate_state"] == "BENIGN_CONFIRMED"
        assert ml_section["reviewed_by"] is not None

        # Fetch dedicated reviews endpoint
        hist_resp = client.get(
            f"/api/analyses/{sample_record}/reviews",
            headers=auth_headers_admin
        )
        assert hist_resp.status_code == 200
        hist_data = hist_resp.json()
        assert len(hist_data) == 1
        assert hist_data[0]["verdict"] == "BENIGN_UTILITY"

    def test_analyst_rejection_does_not_mutate_deterministic_evidence(self, sample_record, auth_headers_analyst):
        """Rejecting an ML alert must never alter heuristic threat scores or sample classification."""
        db = SessionLocal()
        try:
            s_before = SampleRepository.get_by_analysis_id(db, sample_record)
            original_score = s_before.risk_score
            original_classification = s_before.classification
        finally:
            db.close()

        payload = {
            "verdict": "REJECTED_FALSE_POSITIVE",
            "rationale": "False alarm caused by temporal concept drift."
        }
        client.post(
            f"/api/analyses/{sample_record}/reviews",
            headers=auth_headers_analyst,
            json=payload
        )

        db = SessionLocal()
        try:
            s_after = SampleRepository.get_by_analysis_id(db, sample_record)
            assert s_after.risk_score == original_score, "Heuristic risk score must remain untouched"
            assert s_after.classification == original_classification, "Deterministic classification must not be erased"
        finally:
            db.close()
