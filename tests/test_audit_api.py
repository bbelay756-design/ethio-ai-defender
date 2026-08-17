"""
API and RBAC Integration Tests for Module 17: Administrator Audit Viewer.
Tests:
- GET /api/audit/logs (Admin authorized, non-admin 403 Forbidden)
- Filtering by event, result, user_id, search, date
- GET /api/audit/stats
- GET /api/audit/export/csv
"""

import unittest
import uuid
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import init_db, SessionLocal
from app.auth.service import AuthService
from app.auth.roles import UserRole
from app.audit.logger import audit_logger
from app.audit.events import AuditEventType, AuditResult


class TestAuditApiAndAccessControl(unittest.TestCase):
    """Test suite for Audit API endpoints and RBAC security."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        # Create distinct test users
        uid = str(uuid.uuid4())[:8]
        cls.admin_username = f"admin_audit_{uid}"
        cls.analyst_username = f"analyst_audit_{uid}"
        cls.student_username = f"student_audit_{uid}"

        cls.admin = AuthService.register_user(
            cls.db, cls.admin_username, f"{cls.admin_username}@soc.et", "AdminSecretPass2026!", role="ADMIN"
        )
        cls.analyst = AuthService.register_user(
            cls.db, cls.analyst_username, f"{cls.analyst_username}@soc.et", "AnalystSecretPass2026!", role="ANALYST"
        )
        cls.student = AuthService.register_user(
            cls.db, cls.student_username, f"{cls.student_username}@soc.et", "StudentSecretPass2026!", role="STUDENT"
        )

        cls.admin_token = AuthService.create_token_for_user(cls.admin)["access_token"]
        cls.analyst_token = AuthService.create_token_for_user(cls.analyst)["access_token"]
        cls.student_token = AuthService.create_token_for_user(cls.student)["access_token"]

        # Seed test audit records
        audit_logger.log_login(AuditResult.SUCCESS, cls.admin_username, user_id=cls.admin.id, db=cls.db)
        audit_logger.log_upload(
            AuditResult.SUCCESS,
            "banking_agent.exe",
            user_id=cls.analyst.id,
            analysis_id="ANL-AUDIT-001",
            size=20480,
            db=cls.db
        )
        audit_logger.log_analysis_completion(
            analysis_id="ANL-AUDIT-001",
            filename="banking_agent.exe",
            risk_level="HIGH",
            threat_score=75,
            db=cls.db
        )
        audit_logger.log_security_alert(
            alert_type="UNAUTHORIZED_ACCESS",
            description="Student attempted to read admin records",
            user_id=cls.student.id,
            db=cls.db
        )

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_admin_can_access_audit_logs(self):
        """Admin is authorized to query audit logs."""
        response = self.client.get(
            "/api/audit/logs",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("items", data)
        self.assertIn("total", data)
        self.assertGreaterEqual(data["total"], 4)

    def test_analyst_and_student_forbidden_from_audit_logs(self):
        """Analyst and Student are strictly forbidden with 403 from viewing audit logs."""
        # Analyst
        res_analyst = self.client.get(
            "/api/audit/logs",
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(res_analyst.status_code, 403)

        # Student
        res_student = self.client.get(
            "/api/audit/logs",
            headers={"Authorization": f"Bearer {self.student_token}"}
        )
        self.assertEqual(res_student.status_code, 403)

        # Unauthenticated
        res_unauth = self.client.get("/api/audit/logs")
        self.assertEqual(res_unauth.status_code, 401)

    def test_audit_logs_filtering(self):
        """Test filtering audit logs by event type and result."""
        # Filter by event=upload
        res = self.client.get(
            "/api/audit/logs?event=upload",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        for item in data["items"]:
            self.assertEqual(item["event"], "upload")

        # Filter by result=DENIED
        res_denied = self.client.get(
            "/api/audit/logs?result=DENIED",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_denied.status_code, 200)
        data_denied = res_denied.json()
        for item in data_denied["items"]:
            self.assertEqual(item["result"], "DENIED")

    def test_audit_statistics_endpoint(self):
        """Admin can fetch aggregate audit statistics."""
        response = self.client.get(
            "/api/audit/stats",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(response.status_code, 200)
        stats = response.json()
        self.assertIn("total_events", stats)
        self.assertIn("success_count", stats)
        self.assertIn("event_distribution", stats)
        self.assertIn("recent_alerts", stats)
        self.assertGreaterEqual(stats["total_events"], 1)

    def test_audit_csv_export(self):
        """Admin can export sanitized audit logs as CSV."""
        response = self.client.get(
            "/api/audit/export/csv",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.headers.get("content-type", ""))
        self.assertIn("Timestamp", response.text)
        self.assertIn("Event", response.text)


if __name__ == "__main__":
    unittest.main()
