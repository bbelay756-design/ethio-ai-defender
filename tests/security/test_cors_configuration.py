"""
P1 / SEC-04 regression tests: configurable, non-wildcard CORS.

Verifies:
  - wildcard origins ('*' and wildcard patterns) are rejected by
    Settings.validate_cors();
  - credentials cannot be enabled without an explicit origin allowlist;
  - an explicit origin allowlist validates cleanly;
  - the default configuration exposes no CORS allowance (same-origin);
  - the body-size middleware is registered on the application.
"""

import unittest

from fastapi.testclient import TestClient

from app.core.config import Settings, settings
from app.main import app


class TestCorsValidation(unittest.TestCase):
    """Unit tests for Settings.validate_cors()."""

    def test_wildcard_origin_rejected(self):
        candidate = Settings()
        candidate.CORS_ORIGINS = {"*"}
        with self.assertRaises(RuntimeError):
            candidate.validate_cors()

    def test_wildcard_subdomain_pattern_rejected(self):
        candidate = Settings()
        candidate.CORS_ORIGINS = {"https://*.example.com"}
        with self.assertRaises(RuntimeError):
            candidate.validate_cors()

    def test_credentials_without_origins_rejected(self):
        candidate = Settings()
        candidate.CORS_ORIGINS = set()
        candidate.CORS_ALLOW_CREDENTIALS = True
        with self.assertRaises(RuntimeError):
            candidate.validate_cors()

    def test_explicit_origin_accepted(self):
        candidate = Settings()
        candidate.CORS_ORIGINS = {"https://soc.ethio.example"}
        candidate.CORS_ALLOW_CREDENTIALS = True
        # Must not raise.
        candidate.validate_cors()

    def test_empty_default_origins_accepted(self):
        candidate = Settings()
        candidate.CORS_ORIGINS = set()
        candidate.CORS_ALLOW_CREDENTIALS = False
        candidate.validate_cors()


class TestCorsRuntime(unittest.TestCase):
    """Integration checks against the assembled application."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_no_wildcard_allow_origin_header(self):
        """With the default (empty) allowlist, no CORS permission is granted."""
        if settings.CORS_ORIGINS:
            self.skipTest("CORS_ORIGINS configured in environment; skipping default check.")
        response = self.client.get("/", headers={"Origin": "https://evil.example"})
        self.assertNotEqual(response.headers.get("access-control-allow-origin"), "*")
        self.assertNotIn("access-control-allow-origin", {k.lower() for k in response.headers.keys()})

    def test_body_size_middleware_registered(self):
        """SEC-05 body limiter must be part of the middleware stack."""
        names = {getattr(entry.cls, "__name__", "") for entry in app.user_middleware}
        self.assertIn("BodySizeLimitMiddleware", names)


if __name__ == "__main__":
    unittest.main()
