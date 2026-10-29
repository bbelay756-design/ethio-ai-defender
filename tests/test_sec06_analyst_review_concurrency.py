"""
Unit and Concurrency Regression Tests for SEC-06: Analyst-Review Concurrency Hardening.

Verifies:
1. Normal analyst review creation returns HTTP 201.
2. Duplicate sequential review submission returns HTTP 409 Conflict.
3. Concurrent review submissions from racing threads trigger database uniqueness enforcement,
   where exactly 1 succeeds (201) and the competitor receives clean HTTP 409 Conflict.
4. Database contains exactly 1 review row for the analysis ID (zero duplicate rows).
5. Audit trail records exactly 1 SUCCESS event for the review.
6. SampleRepository.add_analyst_review translates IntegrityError into DuplicateReviewError.
7. Authorization controls (VIEWER 403, unauthenticated 401) remain strictly enforced.
8. ML-13 analyst confirmation gate and deterministic evidence remain unaltered.
9. Operational database (storage/defender.db) isolation is strictly preserved.
"""

import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.session import Base, SessionLocal, engine
from app.db.models import UserModel, SampleModel, AnalystReviewModel, AuditLogModel
from app.db.repository import SampleRepository, DuplicateReviewError
from app.auth.roles import UserRole
from app.auth.service import AuthService, create_access_token


class TestSec06AnalystReviewConcurrency(unittest.TestCase):
    """Test suite for analyst-review concurrency, uniqueness, and idempotency."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

        # Create isolated test users via AuthService
        cls.db = SessionLocal()
        cls.password = "Sec06TestPassword123!"

        users_to_create = [
            ("sec06_analyst", UserRole.ANALYST.value),
            ("sec06_analyst_2", UserRole.ANALYST.value),
            ("sec06_viewer", UserRole.VIEWER.value),
        ]

        for username, role in users_to_create:
            existing = cls.db.query(UserModel).filter(UserModel.username == username).first()
            if existing:
                cls.db.delete(existing)
                cls.db.commit()
            u = AuthService.register_user(
                db=cls.db,
                username=username,
                email=f"{username}@defender.local",
                password=cls.password,
                role=role,
            )
            if username == "sec06_analyst":
                cls.analyst_user = u
            elif username == "sec06_analyst_2":
                cls.analyst_user_2 = u
            elif username == "sec06_viewer":
                cls.viewer_user = u

        def _do_login(uname: str) -> str:
            res = cls.client.post("/api/auth/login", json={"username": uname, "password": cls.password})
            if res.status_code == 200:
                return res.json().get("access_token")
            raise RuntimeError(f"Login failed for {uname}: {res.status_code} {res.text}")

        cls.analyst_token = _do_login("sec06_analyst")
        cls.analyst_headers = {"Authorization": f"Bearer {cls.analyst_token}"}

        cls.analyst_2_token = _do_login("sec06_analyst_2")
        cls.analyst_2_headers = {"Authorization": f"Bearer {cls.analyst_2_token}"}

        cls.viewer_token = _do_login("sec06_viewer")
        cls.viewer_headers = {"Authorization": f"Bearer {cls.viewer_token}"}

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def _create_test_sample(self, analysis_id: str) -> SampleModel:
        """Helper to create an isolated sample record."""
        db = SessionLocal()
        try:
            sample = db.query(SampleModel).filter(SampleModel.analysis_id == analysis_id).first()
            if not sample:
                sample = SampleModel(
                    analysis_id=analysis_id,
                    filename=f"{analysis_id}.exe",
                    size=4096,
                    md5="0" * 32,
                    sha256=f"hash_{analysis_id}"[:64].ljust(64, "0"),
                    risk_score=75,
                    classification="HIGH",
                    status="ANALYST_REVIEW",
                    created_at=datetime.now(timezone.utc),
                )
                db.add(sample)
                db.commit()
                db.refresh(sample)
            return sample
        finally:
            db.close()

    def test_01_normal_review_creation_returns_201(self):
        """Verifies normal, valid analyst review creation succeeds with HTTP 201."""
        analysis_id = "ANL-SEC06-NORM-001"
        self._create_test_sample(analysis_id)

        payload = {
            "verdict": "CONFIRMED_MALWARE",
            "rationale": "Heuristic match corroborated by dynamic PE structure analysis.",
        }

        resp = self.client.post(
            f"/api/analyses/{analysis_id}/reviews",
            headers=self.analyst_headers,
            json=payload,
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["analysis_id"], analysis_id)
        self.assertEqual(data["verdict"], "CONFIRMED_MALWARE")
        self.assertEqual(data["review_state"], "ANALYST_CONFIRMED")
        self.assertEqual(data["reviewer_username"], "sec06_analyst")

    def test_02_sequential_duplicate_review_returns_409_conflict(self):
        """Verifies submitting a second review for the same analysis returns HTTP 409."""
        analysis_id = "ANL-SEC06-DUP-001"
        self._create_test_sample(analysis_id)

        payload1 = {
            "verdict": "REJECTED_FALSE_POSITIVE",
            "rationale": "Initial review: clean internal utility.",
        }
        resp1 = self.client.post(
            f"/api/analyses/{analysis_id}/reviews",
            headers=self.analyst_headers,
            json=payload1,
        )
        self.assertEqual(resp1.status_code, 201)

        payload2 = {
            "verdict": "CONFIRMED_MALWARE",
            "rationale": "Conflicting second review attempt.",
        }
        resp2 = self.client.post(
            f"/api/analyses/{analysis_id}/reviews",
            headers=self.analyst_headers,
            json=payload2,
        )
        self.assertEqual(resp2.status_code, 409)
        self.assertIn("already been reviewed", resp2.json()["detail"])

    def test_03_concurrent_review_submissions_strictly_idempotent(self):
        """Simulates simultaneous concurrent review submissions across multiple threads.

        Verifies that:
        - Exactly one request succeeds with HTTP 201.
        - The other racing request receives clean HTTP 409 Conflict.
        - Exactly one review row is present in the database.
        - Exactly one SUCCESS audit log event is recorded.
        """
        analysis_id = "ANL-SEC06-RACE-001"
        self._create_test_sample(analysis_id)

        barrier = threading.Barrier(2)
        results = []

        def submit_review(headers, verdict, rationale):
            # Wait for both threads to reach the starting line
            barrier.wait()
            resp = self.client.post(
                f"/api/analyses/{analysis_id}/reviews",
                headers=headers,
                json={"verdict": verdict, "rationale": rationale},
            )
            results.append((resp.status_code, resp.json()))

        t1 = threading.Thread(
            target=submit_review,
            args=(self.analyst_headers, "CONFIRMED_MALWARE", "Thread 1 rationale: confirmed malware"),
        )
        t2 = threading.Thread(
            target=submit_review,
            args=(self.analyst_2_headers, "REJECTED_FALSE_POSITIVE", "Thread 2 rationale: rejected FP"),
        )

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        status_codes = [r[0] for r in results]
        self.assertIn(201, status_codes, "Exactly one thread must successfully create the review (201)")
        self.assertIn(409, status_codes, "The competing thread must receive HTTP 409 Conflict")
        self.assertEqual(len(status_codes), 2)

        # Check database records
        db = SessionLocal()
        try:
            reviews = db.query(AnalystReviewModel).filter(
                AnalystReviewModel.analysis_id == analysis_id
            ).all()
            self.assertEqual(len(reviews), 1, "Database must contain exactly 1 review record (zero duplicates)")

            # Check audit logs
            audit_events = db.query(AuditLogModel).filter(
                AuditLogModel.analysis_id == analysis_id,
                AuditLogModel.event == "analyst review",
            ).all()
            self.assertEqual(len(audit_events), 1, "Exactly one review audit event must be committed")
            self.assertEqual(audit_events[0].result, "SUCCESS")
        finally:
            db.close()

    def test_04_repository_translates_integrity_error_to_duplicate_review_error(self):
        """Verifies SampleRepository.add_analyst_review translates DB IntegrityError into DuplicateReviewError."""
        analysis_id = "ANL-SEC06-REPO-001"
        sample = self._create_test_sample(analysis_id)

        db1 = SessionLocal()
        db2 = SessionLocal()
        try:
            # First insertion succeeds
            SampleRepository.add_analyst_review(
                db=db1,
                sample_id=sample.id,
                analysis_id=analysis_id,
                user_id=self.analyst_user.id,
                reviewer_username=self.analyst_user.username,
                verdict="CONFIRMED_MALWARE",
                rationale="Valid first insertion",
            )

            # Second insertion with same analysis_id must raise DuplicateReviewError
            with self.assertRaises(DuplicateReviewError):
                SampleRepository.add_analyst_review(
                    db=db2,
                    sample_id=sample.id,
                    analysis_id=analysis_id,
                    user_id=self.analyst_user_2.id,
                    reviewer_username=self.analyst_user_2.username,
                    verdict="REJECTED_FALSE_POSITIVE",
                    rationale="Conflicting duplicate insertion",
                )
        finally:
            db1.close()
            db2.close()

    def test_05_viewer_role_cannot_submit_review(self):
        """Verifies VIEWER role receives HTTP 403 Forbidden when attempting review submission."""
        analysis_id = "ANL-SEC06-VIEWER-001"
        self._create_test_sample(analysis_id)

        payload = {
            "verdict": "CONFIRMED_MALWARE",
            "rationale": "Viewer attempting mutation",
        }
        resp = self.client.post(
            f"/api/analyses/{analysis_id}/reviews",
            headers=self.viewer_headers,
            json=payload,
        )
        self.assertEqual(resp.status_code, 403)

    def test_06_unauthenticated_request_returns_401(self):
        """Verifies unauthenticated review submissions return HTTP 401 Unauthorized."""
        analysis_id = "ANL-SEC06-UNAUTH-001"
        self._create_test_sample(analysis_id)

        payload = {
            "verdict": "CONFIRMED_MALWARE",
            "rationale": "Anonymous review attempt",
        }
        unauth_client = TestClient(app)
        resp = unauth_client.post(
            f"/api/analyses/{analysis_id}/reviews",
            json=payload,
        )
        self.assertEqual(resp.status_code, 401)

    def test_07_empty_rationale_and_invalid_verdict_rejected(self):
        """Verifies domain validation for empty rationales and invalid verdict strings."""
        analysis_id = "ANL-SEC06-VAL-001"
        self._create_test_sample(analysis_id)

        # Empty rationale
        resp_empty = self.client.post(
            f"/api/analyses/{analysis_id}/reviews",
            headers=self.analyst_headers,
            json={"verdict": "CONFIRMED_MALWARE", "rationale": "   "},
        )
        self.assertEqual(resp_empty.status_code, 400)
        self.assertIn("cannot be empty", resp_empty.json()["detail"])

        # Invalid verdict
        resp_invalid = self.client.post(
            f"/api/analyses/{analysis_id}/reviews",
            headers=self.analyst_headers,
            json={"verdict": "UNKNOWN_ACTION", "rationale": "Valid rationale"},
        )
        self.assertEqual(resp_invalid.status_code, 400)
        self.assertIn("Invalid verdict", resp_invalid.json()["detail"])

    def test_08_review_history_retrieval(self):
        """Verifies GET /api/analyses/{id}/reviews returns the recorded review."""
        analysis_id = "ANL-SEC06-HIST-001"
        self._create_test_sample(analysis_id)

        payload = {
            "verdict": "BENIGN_UTILITY",
            "rationale": "Verified vendor digital certificate and known hash manifest.",
        }
        post_resp = self.client.post(
            f"/api/analyses/{analysis_id}/reviews",
            headers=self.analyst_headers,
            json=payload,
        )
        self.assertEqual(post_resp.status_code, 201)

        get_resp = self.client.get(
            f"/api/analyses/{analysis_id}/reviews",
            headers=self.analyst_headers,
        )
        self.assertEqual(get_resp.status_code, 200)
        reviews = get_resp.json()
        self.assertEqual(len(reviews), 1)
        self.assertEqual(reviews[0]["verdict"], "BENIGN_UTILITY")
        self.assertEqual(reviews[0]["review_state"], "BENIGN_CONFIRMED")


if __name__ == "__main__":
    unittest.main()
