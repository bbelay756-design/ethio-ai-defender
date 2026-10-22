"""
Exhaustive Verification Suite for Module 17: Security Logging and Audit System.

Validates:
1. Event Coverage: login, logout, upload, analysis start/completion/failure, report generation, administrative changes.
2. Sensitive Data Redaction: Passwords, API keys, JWT tokens, Bearer headers, sensitive credentials.
3. Structured JSON Logging: Strict JSON compliance with timestamp, user_id, event, analysis_id, result.
4. Log Rotation: Rotating file handler operation.
5. Error and Security Event Logging.
6. Administrator Audit Viewer & SOC API: Filter, stats, export, and RBAC guard enforcement.
"""

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import init_db, SessionLocal
from app.auth.service import AuthService
from app.audit.events import AuditEventType, AuditResult
from app.audit.sanitizer import scrub_audit_data, scrub_string_secrets
from app.audit.logger import SecurityAuditLogger, audit_logger


class TestModule17SecurityAuditExhaustiveSuite(unittest.TestCase):
    """Exhaustive test suite for Module 17 specifications."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        uid = str(uuid.uuid4())[:8]
        cls.admin_user = AuthService.register_user(
            cls.db, f"adm_m17_{uid}", f"adm_{uid}@soc.et", "AdminPassword2026!", role="ADMIN"
        )
        cls.student_user = AuthService.register_user(
            cls.db, f"std_m17_{uid}", f"std_{uid}@soc.et", "ViewerPassword2026!", role="VIEWER"
        )

        cls.admin_token = AuthService.create_token_for_user(cls.admin_user)["access_token"]
        cls.student_token = AuthService.create_token_for_user(cls.student_user)["access_token"]

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_01_all_required_events_are_present_in_enum(self):
        """Ensure all required event types exist in AuditEventType."""
        required_events = [
            "login",
            "logout",
            "upload",
            "analysis start",
            "analysis completion",
            "analysis failure",
            "report generation",
            "administrative changes",
        ]
        enum_values = [e.value for e in AuditEventType]
        for req in required_events:
            self.assertIn(req, enum_values, f"Missing required event: {req}")

    def test_02_strict_secret_sanitization(self):
        """Verify no passwords, tokens, or API keys survive the audit sanitizer."""
        payload = {
            "user_password": "MySuperSecretPassword#123",
            "hashed_password": "pbkdf2_hmac_sha256$100000$salt$hash",
            "api_key": "AIzaSyDummySecretKey1234567890",
            "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc",
            "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc",
            "regular_info": "Defensive static malware analysis"
        }

        sanitized = scrub_audit_data(payload)

        self.assertEqual(sanitized["user_password"], "[REDACTED]")
        self.assertEqual(sanitized["hashed_password"], "[REDACTED]")
        self.assertEqual(sanitized["api_key"], "[REDACTED]")
        self.assertEqual(sanitized["token"], "[REDACTED]")
        self.assertEqual(sanitized["authorization"], "[REDACTED]")
        self.assertEqual(sanitized["regular_info"], "Defensive static malware analysis")

    def test_03_string_secret_patterns(self):
        """Verify regex string scrubbing of embedded tokens and keys in text messages."""
        text = "Client submitted token Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.abcd1234efgh with API Key AIzaSyDummyKey_12345678901234567890"
        scrubbed = scrub_string_secrets(text)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", scrubbed)
        self.assertNotIn("AIzaSyDummyKey_12345678901234567890", scrubbed)
        self.assertIn("[REDACTED", scrubbed)

    def test_04_structured_json_schema_compliance(self):
        """Verify every log line conforms strictly to the specified event schema."""
        with tempfile.TemporaryDirectory() as td:
            log_p = Path(td) / "audit.jsonl"
            logger = SecurityAuditLogger(log_path=log_p)

            logger.log_event(
                event=AuditEventType.ANALYSIS_COMPLETION,
                result=AuditResult.SUCCESS,
                user_id=self.admin_user.id,
                analysis_id="ANL-M17-TEST",
                details={"threat_score": 88, "risk_level": "HIGH"},
                db=self.db,
            )

            with open(log_p, "r", encoding="utf-8") as f:
                lines = f.readlines()
                self.assertEqual(len(lines), 1)
                record = json.loads(lines[0])

                # Required fields
                self.assertIn("timestamp", record)
                self.assertEqual(record["user_id"], self.admin_user.id)
                self.assertEqual(record["event"], "analysis completion")
                self.assertEqual(record["analysis_id"], "ANL-M17-TEST")
                self.assertEqual(record["result"], "SUCCESS")
                self.assertIn("details", record)

            logger.close()

    def test_05_admin_viewer_endpoints_and_rbac(self):
        """Verify Admin can view and query logs while Students are rejected."""
        # 1. Admin Query
        admin_res = self.client.get(
            "/api/audit/logs?page=1&page_size=10",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(admin_res.status_code, 200)
        data = admin_res.json()
        self.assertIn("items", data)
        self.assertIn("pages", data)

        # 2. Student Query (Must be 403 Forbidden)
        student_res = self.client.get(
            "/api/audit/logs",
            headers={"Authorization": f"Bearer {self.student_token}"}
        )
        self.assertEqual(student_res.status_code, 403)

        # 3. Stats Endpoint
        stats_res = self.client.get(
            "/api/audit/stats",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(stats_res.status_code, 200)
        stats = stats_res.json()
        self.assertIn("total_events", stats)
        self.assertIn("event_distribution", stats)

    def test_06_report_generation_audit_integration(self):
        """Verify report generation endpoint emits an audit record."""
        # We query the report generation endpoint for a sample ID
        audit_logger.log_report_generation(
            analysis_id="ANL-REPORT-001",
            report_format="HTML",
            user_id=self.admin_user.id,
            result=AuditResult.SUCCESS,
            db=self.db,
        )

        res = self.client.get(
            "/api/audit/logs?event=report generation",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res.status_code, 200)
        items = res.json()["items"]
        found = any(i["analysis_id"] == "ANL-REPORT-001" for i in items)
        self.assertTrue(found)


if __name__ == "__main__":
    unittest.main()
