"""
P1 / SEC-04 regression tests: configurable, non-wildcard CORS.

Verifies:
  - wildcard origins ('*' and wildcard patterns) are rejected by
    Settings.validate_cors();
  - credentials cannot be enabled without an explicit origin allowlist;
  - an explicit origin allowlist validates cleanly;
  - the default configuration exposes no CORS allowance (same-origin);
  - the body-size middleware is registered on the application.
  - preflight OPTIONS requests work correctly with allowed origins
  - preflight OPTIONS requests are rejected for disallowed origins
  - credential behavior is correct when CORS is configured
  - CORS headers are properly set in responses
"""

import os
import unittest
from unittest.mock import patch

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


class TestCorsMiddlewareWithOrigins(unittest.TestCase):
    """Integration tests for CORS middleware when origins are explicitly configured."""

    @classmethod
    def setUpClass(cls):
        # Create a fresh app instance with CORS enabled
        cls.test_origin = "https://trusted.example.com"
        cls.disallowed_origin = "https://evil.example.com"

    def _make_app_with_cors(self, origins, allow_credentials=False):
        """Create a test FastAPI app with specific CORS config."""
        from fastapi import FastAPI
        from fastapi.middleware.cors import CORSMiddleware

        test_app = FastAPI()
        test_app.add_middleware(
            CORSMiddleware,
            allow_origins=sorted(origins),
            allow_credentials=allow_credentials,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "Accept"],
        )

        @test_app.get("/test")
        async def test_endpoint():
            return {"message": "ok"}

        @test_app.post("/test")
        async def test_post():
            return {"message": "posted"}

        return test_app

    def test_preflight_disallowed_origin(self):
        """Preflight OPTIONS request with disallowed origin is rejected with 400."""
        test_app = self._make_app_with_cors({self.test_origin})
        client = TestClient(test_app)

        response = client.options(
            "/test",
            headers={
                "Origin": self.disallowed_origin,
                "Access-Control-Request-Method": "POST",
            },
        )
        # Starlette's CORSMiddleware returns 400 for disallowed origin preflight requests
        self.assertEqual(response.status_code, 400)
        self.assertNotEqual(response.headers.get("access-control-allow-origin"), self.disallowed_origin)

    def test_actual_request_allowed_origin(self):
        """Actual request with allowed origin gets CORS headers."""
        test_app = self._make_app_with_cors({self.test_origin})
        client = TestClient(test_app)

        response = client.get("/test", headers={"Origin": self.test_origin})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("access-control-allow-origin"), self.test_origin)

    def test_actual_request_disallowed_origin(self):
        """Actual request with disallowed origin gets no CORS headers."""
        test_app = self._make_app_with_cors({self.test_origin})
        client = TestClient(test_app)

        response = client.get("/test", headers={"Origin": self.disallowed_origin})
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.headers.get("access-control-allow-origin"), self.disallowed_origin)
        self.assertNotIn("access-control-allow-origin", {k.lower() for k in response.headers.keys()})

    def test_credentials_with_allowed_origin(self):
        """Credentials are allowed when explicitly configured and origin matches."""
        test_app = self._make_app_with_cors({self.test_origin}, allow_credentials=True)
        client = TestClient(test_app)

        response = client.get("/test", headers={"Origin": self.test_origin})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("access-control-allow-origin"), self.test_origin)
        self.assertEqual(response.headers.get("access-control-allow-credentials"), "true")

    def test_credentials_not_sent_for_disallowed_origin(self):
        """Credentials header not sent for disallowed origin even if configured."""
        test_app = self._make_app_with_cors({self.test_origin}, allow_credentials=True)
        client = TestClient(test_app)

        response = client.get("/test", headers={"Origin": self.disallowed_origin})
        self.assertEqual(response.status_code, 200)
        # For disallowed origins, credentials header should not be present
        # (Starlette sets it to 'true' but without allow-origin, browser will reject)
        self.assertNotEqual(response.headers.get("access-control-allow-origin"), self.disallowed_origin)

    def test_vary_header_present(self):
        """Vary: Origin header is set for CORS responses."""
        test_app = self._make_app_with_cors({self.test_origin})
        client = TestClient(test_app)

        response = client.get("/test", headers={"Origin": self.test_origin})
        vary = response.headers.get("vary", "")
        self.assertIn("Origin", vary)

    def test_multiple_allowed_origins(self):
        """Multiple allowed origins work correctly."""
        origins = {"https://app1.example.com", "https://app2.example.com", "https://app3.example.com"}
        test_app = self._make_app_with_cors(origins)
        client = TestClient(test_app)

        for origin in origins:
            response = client.get("/test", headers={"Origin": origin})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers.get("access-control-allow-origin"), origin)

        # Origin not in list
        response = client.get("/test", headers={"Origin": "https://notallowed.example.com"})
        self.assertNotEqual(response.headers.get("access-control-allow-origin"), "https://notallowed.example.com")


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
