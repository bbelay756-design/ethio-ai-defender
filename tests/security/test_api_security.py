"""
Module 18 - Security Testing: Step 5 - API Security & Error Sanitization.
Tests input validation boundaries, malformed JSON handling, and strict prevention of stack trace leakage.
"""

import unittest
from fastapi.testclient import TestClient

from app.main import app
from tests.fixtures.security_payloads import MALFORMED_JSON_PAYLOADS, INVALID_AUTH_HEADERS
from tests.security.test_helpers import reset_failed_login_attempts


class TestAPISecurity(unittest.TestCase):
    """API boundary robustness and error sanitization test suite."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        from tests.security.test_helpers import reset_failed_login_attempts
        reset_failed_login_attempts()

    def test_01_malformed_json_returns_422(self):
        """Verify malformed JSON requests produce controlled 422 Unprocessable Entity responses."""
        for mal_json in MALFORMED_JSON_PAYLOADS:
            response = self.client.post(
                "/api/auth/login",
                content=mal_json,
                headers={"Content-Type": "application/json"}
            )
            self.assertIn(response.status_code, [400, 422])
            text = response.text
            # Must not expose Python stack traces or file paths
            self.assertNotIn("Traceback (most recent call last)", text)
            self.assertNotIn("C:\\Users\\", text)
            self.assertNotIn("/home/", text)

    def test_02_invalid_analysis_id_returns_404(self):
        """Verify querying non-existent or malformed analysis IDs returns controlled 404."""
        invalid_ids = [
            "ANL-NONEXISTENT-999999",
            "../../../etc/passwd",
            "ANL-SQLI' OR '1'='1",
            "ANL-" + ("X" * 200),
        ]
        for aid in invalid_ids:
            response = self.client.get(f"/api/dashboard/samples/{aid}/full")
            self.assertIn(response.status_code, [404, 422, 400])
            self.assertNotIn("Traceback", response.text)

    def test_03_missing_and_invalid_type_fields(self):
        """Verify missing required fields and type mismatches return controlled validation errors."""
        # Missing password field
        res_missing = self.client.post(
            "/api/auth/login",
            json={"username": "test_user"}
        )
        self.assertEqual(res_missing.status_code, 422)

        # Integer provided for string username
        res_type = self.client.post(
            "/api/auth/login",
            json={"username": 12345, "password": "Password123!"}
        )
        self.assertIn(res_type.status_code, [401, 422])

    def test_04_oversized_string_input_boundary(self):
        """Verify oversized string inputs (100KB buffer) do not cause buffer overflow or crash."""
        oversized_str = "A" * 100_000
        response = self.client.post(
            "/api/auth/login",
            json={"username": oversized_str, "password": "Password123!"}
        )
        self.assertIn(response.status_code, [400, 401, 422])

    def test_05_unauthorized_and_invalid_auth_requests(self):
        """Verify invalid authentication headers return 401 Unauthorized."""
        for auth_header in INVALID_AUTH_HEADERS:
            response = self.client.get("/api/auth/me", headers=auth_header)
            self.assertEqual(response.status_code, 401)
            self.assertIn("detail", response.json())


if __name__ == "__main__":
    unittest.main()