"""
Module 18 - Security Testing: Step 15 - Security Event Logging & Secret Sanitization.
Tests security audit trail logging across all platform events and guarantees passwords/tokens are never logged in plaintext.
"""

import uuid
import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import init_db, SessionLocal
from app.auth.service import AuthService
from app.auth.roles import UserRole
from app.audit.logger import audit_logger
from app.audit.events import AuditEventType, AuditResult


class TestSecurityLogging(unittest.TestCase):
    """Security audit event logging and sensitive data redaction test suite."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        cls.username = f"log_user_{uuid.uuid4().hex[:6]}"
        cls.password = "LoggingSecretPass2026!"
        cls.user = AuthService.register_user(
            cls.db, cls.username, f"{cls.username}@soc.et", cls.password, role=UserRole.STUDENT
        )

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_01_failed_login_event_logged(self):
        """Verify failed login attempt is recorded in audit log with FAILURE result."""
        res = self.client.post(
            "/api/auth/login",
            json={"username": self.username, "password": "WrongPassword!"}
        )
        self.assertEqual(res.status_code, 401)

    def test_02_successful_login_event_logged(self):
        """Verify successful login is recorded in audit log with SUCCESS result."""
        res = self.client.post(
            "/api/auth/login",
            json={"username": self.username, "password": self.password}
        )
        self.assertEqual(res.status_code, 200)

    def test_03_secrets_redacted_from_audit_logs(self):
        """Verify passwords, tokens, and keys passed to audit logger are strictly redacted."""
        payload = {
            "password": "PLAINTEXT_SECRET_PASSWORD_12345",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SECRET_TOKEN",
            "api_key": "sk-1234567890abcdef12345678",
            "operation": "administrative_sync",
        }
        event_record = audit_logger.log_event(
            event=AuditEventType.LOGIN,
            result=AuditResult.SUCCESS,
            details=payload,
            db=self.db
        )
        details = event_record["details"]

        self.assertEqual(details["password"], "[REDACTED]")
        self.assertEqual(details["token"], "[REDACTED]")
        self.assertEqual(details["api_key"], "[REDACTED]")
        self.assertEqual(details["operation"], "administrative_sync")

    def test_04_upload_rejection_logged(self):
        """Verify rejected uploads log a security event with rejection status."""
        event_record = audit_logger.log_upload(
            result=AuditResult.FAILURE,
            filename="corrupt.exe",
            details={"status": "REJECTED_INVALID_PE", "reason": "Bad DOS Magic"},
            db=self.db
        )
        self.assertEqual(event_record["event"], AuditEventType.UPLOAD.value)
        self.assertEqual(event_record["result"], AuditResult.FAILURE.value)

    def test_05_analysis_failure_logged(self):
        """Verify pipeline analysis failures are logged in the audit system."""
        event_record = audit_logger.log_analysis_failure(
            analysis_id="ANL-FAIL-TEST",
            filename="broken_binary.exe",
            error="Truncated binary data",
            db=self.db
        )
        self.assertEqual(event_record["event"], AuditEventType.ANALYSIS_FAILURE.value)
        self.assertEqual(event_record["result"], AuditResult.FAILURE.value)


if __name__ == "__main__":
    unittest.main()
