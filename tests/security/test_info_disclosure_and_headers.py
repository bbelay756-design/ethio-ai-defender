"""
Module 18 - Security Testing: Step 12 & 13 - Information Disclosure & Security Headers.
Verifies error responses do not leak secrets or internal paths, and verifies standard defensive HTTP security headers.
"""

import unittest
from fastapi.testclient import TestClient

from app.main import app


class TestInfoDisclosureAndHeaders(unittest.TestCase):
    """Information leakage prevention and HTTP security headers verification suite."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_security_headers_present_on_root_endpoint(self):
        """Verify standard security headers are attached to root endpoint responses."""
        response = self.client.get("/")
        headers = response.headers

        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("X-XSS-Protection"), "1; mode=block")
        self.assertEqual(headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

    def test_02_security_headers_present_on_api_endpoints(self):
        """Verify standard security headers are attached to API responses."""
        response = self.client.get("/api/dashboard/samples")
        headers = response.headers

        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")

    def test_03_no_internal_paths_or_stack_traces_in_404(self):
        """Verify 404 responses do not leak server paths or traceback data."""
        response = self.client.get("/non_existent_route_12345")
        self.assertEqual(response.status_code, 404)
        body = response.text

        self.assertNotIn("Traceback", body)
        self.assertNotIn("C:\\Users\\", body)
        self.assertNotIn("D:\\", body)
        self.assertNotIn("/var/www", body)
        self.assertNotIn(".env", body)

    def test_04_no_secrets_in_error_responses(self):
        """Verify authentication error responses do not leak server secrets or internal salts."""
        response = self.client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "WrongPassword!"}
        )
        body = response.text

        self.assertNotIn("SECRET_KEY", body)
        self.assertNotIn("hash_password", body)
        self.assertNotIn("salt", body)
        self.assertNotIn("pbkdf2", body)


if __name__ == "__main__":
    unittest.main()
