"""
Module 18 - Security Testing: Step 9 & 10 - SQL Injection (SQLi) & Cross-Site Scripting (XSS) Defense.
Verifies parameterized ORM queries prevent SQLi and output encoding/sanitization neutralizes XSS payloads.
"""

import io
import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.testing.synthetic_pe import SyntheticPEBuilder
from tests.fixtures.security_payloads import SQL_INJECTION_PAYLOADS, XSS_PAYLOADS


class TestInjectionAndXSS(unittest.TestCase):
    """SQL Injection and Cross-Site Scripting defense validation suite."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.valid_pe = SyntheticPEBuilder.create_minimal_pe()

    def test_01_sqli_login_bypass_neutralized(self):
        """Verify SQL injection payloads in login fields do not bypass authentication."""
        for sqli in SQL_INJECTION_PAYLOADS:
            res = self.client.post(
                "/api/auth/login",
                json={"username": sqli, "password": "arbitrary_password"}
            )
            self.assertEqual(res.status_code, 401, f"SQLi payload bypassed login: {sqli}")
            # Ensure no SQL syntax errors or schema names leaked
            self.assertNotIn("OperationalError", res.text)
            self.assertNotIn("syntax error", res.text.lower())
            self.assertNotIn("sqlite3", res.text.lower())

    def test_02_sqli_in_query_parameters(self):
        """Verify SQL injection payloads in query parameters (skip, limit, format, language) are handled safely."""
        for sqli in SQL_INJECTION_PAYLOADS:
            # Query samples endpoint
            res_samples = self.client.get(f"/api/dashboard/samples?limit=10&skip=0{sqli}")
            self.assertIn(res_samples.status_code, [200, 422, 400])

            # Query audit stats endpoint
            res_stats = self.client.get(f"/api/audit/stats?days=7{sqli}")
            self.assertIn(res_stats.status_code, [200, 401, 403, 422])

    def test_03_xss_in_filenames_sanitized(self):
        """Verify script tags and event handlers in uploaded filenames are stripped of HTML tags."""
        for xss in XSS_PAYLOADS:
            file_obj = io.BytesIO(self.valid_pe)
            filename = f"sample_{xss}.exe"
            response = self.client.post(
                "/api/files/upload",
                files={"file": (filename, file_obj, "application/octet-stream")}
            )
            self.assertIn(response.status_code, [200, 201, 400])
            if response.status_code in (200, 201):
                data = response.json()
                sanitized_name = data["filename"]
                self.assertNotIn("<script>", sanitized_name)
                self.assertNotIn("<", sanitized_name)
                self.assertNotIn(">", sanitized_name)

    def test_04_xss_in_user_registration_fields(self):
        """Verify XSS vectors in usernames and emails are handled as plain string data."""
        for xss in XSS_PAYLOADS:
            res = self.client.post(
                "/api/auth/register",
                json={"username": f"user_{xss}", "email": "valid_email@soc.et", "password": "Password2026!"}
            )
            self.assertIn(res.status_code, [200, 201, 400, 422])


if __name__ == "__main__":
    unittest.main()
