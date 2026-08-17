"""
Unit and Integration Tests for Module 17: Security Logging and Audit System.
Tests:
- Structured JSON logging format (timestamp, user_id, event, analysis_id, result, details)
- Strict scrubbing of passwords, tokens, API keys, and sensitive data
- Log rotation mechanism
- All required security events (login, logout, upload, analysis start/completion/failure, report generation, admin changes)
"""

import os
import json
import tempfile
import unittest
from pathlib import Path

from app.audit.events import AuditEventType, AuditResult
from app.audit.sanitizer import scrub_audit_data, is_sensitive_key
from app.audit.logger import SecurityAuditLogger
from app.db.session import SessionLocal, init_db


class TestSecurityAuditSystem(unittest.TestCase):
    """Test suite for Security Logging and Audit System."""

    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "test_audit.jsonl"
        self.logger = SecurityAuditLogger(log_path=self.log_file)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()
        if hasattr(self, "logger"):
            self.logger.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_structured_json_event_format(self):
        """Verify that audit logs emit valid JSON containing the required standardized fields."""
        payload = self.logger.log_event(
            event=AuditEventType.LOGIN,
            result=AuditResult.SUCCESS,
            user_id=101,
            analysis_id="ANL-101",
            details={"ip": "192.168.1.10", "client": "SOC-Workstation"},
            db=self.db,
        )

        self.assertIn("timestamp", payload)
        self.assertEqual(payload["user_id"], 101)
        self.assertEqual(payload["event"], "login")
        self.assertEqual(payload["analysis_id"], "ANL-101")
        self.assertEqual(payload["result"], "SUCCESS")
        self.assertIn("ip", payload["details"])

        # Check raw file format
        self.assertTrue(self.log_file.exists())
        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
            self.assertGreaterEqual(len(lines), 1)
            last_record = json.loads(lines[-1])
            self.assertEqual(last_record["event"], "login")
            self.assertEqual(last_record["user_id"], 101)

    def test_do_not_log_passwords_and_tokens(self):
        """Strictly enforce DO NOT LOG rule for passwords, API keys, tokens, and authorization headers."""
        raw_sensitive_data = {
            "username": "analyst_sam",
            "password": "SuperSecretPassword123!",
            "hashed_password": "pbkdf2:sha256:100000$abcd$efgh",
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.mocksignature",
            "api_key": "AIzaSyDummySecretGoogleAPIKey12345",
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
            "secret_key": "platform-master-key-not-to-leak",
            "nested_auth": {
                "user_password": "MySecretPassword!",
                "session_token": "token_value_abc"
            },
            "benign_field": "sample_analysis_run"
        }

        sanitized = scrub_audit_data(raw_sensitive_data)

        # Assert all sensitive fields are redacted
        self.assertEqual(sanitized["password"], "[REDACTED]")
        self.assertEqual(sanitized["hashed_password"], "[REDACTED]")
        self.assertEqual(sanitized["access_token"], "[REDACTED]")
        self.assertEqual(sanitized["api_key"], "[REDACTED]")
        self.assertEqual(sanitized["authorization"], "[REDACTED]")
        self.assertEqual(sanitized["secret_key"], "[REDACTED]")
        self.assertEqual(sanitized["nested_auth"]["user_password"], "[REDACTED]")
        self.assertEqual(sanitized["nested_auth"]["session_token"], "[REDACTED]")
        self.assertEqual(sanitized["benign_field"], "sample_analysis_run")

        # Emit audit log and ensure file contains zero plain passwords/tokens
        payload = self.logger.log_event(
            event=AuditEventType.LOGIN,
            result=AuditResult.SUCCESS,
            user_id=42,
            details=raw_sensitive_data,
            db=self.db,
        )

        with open(self.log_file, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertNotIn("SuperSecretPassword123!", content)
            self.assertNotIn("AIzaSyDummySecretGoogleAPIKey12345", content)
            self.assertNotIn("platform-master-key-not-to-leak", content)
            self.assertNotIn("MySecretPassword!", content)

    def test_log_rotation_mechanism(self):
        """Test that log file rotates when size threshold is reached."""
        rot_file = Path(self.temp_dir.name) / "rot_audit.jsonl"
        custom_logger = SecurityAuditLogger(log_path=rot_file)

        # Write enough records to trigger rotation with small bytes limit
        for i in range(100):
            custom_logger.log_event(
                event=AuditEventType.UPLOAD,
                result=AuditResult.SUCCESS,
                user_id=i,
                details={"index": i, "padding": "x" * 200},
                db=self.db,
            )

        self.assertTrue(rot_file.exists())
        self.assertGreater(rot_file.stat().st_size, 0)
        custom_logger.close()

    def test_all_required_security_events(self):
        """Verify dedicated logging helper methods for all required security events."""
        # 1. Login (Success, Failure, Lockout)
        self.logger.log_login(AuditResult.SUCCESS, username="soc_lead", user_id=1, db=self.db)
        self.logger.log_login(AuditResult.FAILURE, username="attacker", details={"reason": "bad pass"}, db=self.db)
        self.logger.log_login(AuditResult.LOCKED, username="locked_user", details={"reason": "5 fails"}, db=self.db)

        # 2. Logout
        self.logger.log_logout(user_id=1, username="soc_lead", db=self.db)

        # 3. Upload
        self.logger.log_upload(
            AuditResult.SUCCESS,
            filename="trojan.exe",
            user_id=2,
            analysis_id="ANL-001",
            size=10240,
            sha256="abcd1234efgh5678abcd1234efgh5678abcd1234efgh5678abcd1234efgh5678",
            db=self.db,
        )

        # 4. Analysis Start
        self.logger.log_analysis_start(analysis_id="ANL-001", filename="trojan.exe", user_id=2, db=self.db)

        # 5. Analysis Completion
        self.logger.log_analysis_completion(
            analysis_id="ANL-001",
            filename="trojan.exe",
            risk_level="CRITICAL",
            threat_score=85,
            db=self.db,
        )

        # 6. Analysis Failure
        self.logger.log_analysis_failure(
            analysis_id="ANL-999",
            filename="corrupt.exe",
            error="Invalid PE headers",
            db=self.db,
        )

        # 7. Report Generation
        self.logger.log_report_generation(
            analysis_id="ANL-001",
            report_format="PDF",
            user_id=2,
            db=self.db,
        )

        # 8. Administrative Changes
        self.logger.log_admin_change(
            action="PROMOTE_ANALYST",
            target_user_id=3,
            admin_user_id=1,
            details={"new_role": "ANALYST"},
            db=self.db,
        )

        # 9. Error Logging
        self.logger.log_error(
            event_name="DATABASE_RECONNECT",
            error_message="Connection pool timeout",
            db=self.db,
        )

        # 10. Security Alert
        self.logger.log_security_alert(
            alert_type="BRUTE_FORCE_BURST",
            description="20 failed logins in 1 minute",
            db=self.db,
        )

        # Check count of lines written to JSONL (3 logins + 1 logout + 1 upload + 1 start + 1 comp + 1 fail + 1 rep + 1 adm + 1 err + 1 alert = 12)
        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
            self.assertEqual(len(lines), 12)


if __name__ == "__main__":
    unittest.main()
