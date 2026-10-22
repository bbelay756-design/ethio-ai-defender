"""
P1 / SEC-05 regression tests: authentication + authorization on upload endpoints.

Verifies that every production upload endpoint enforces the UPLOAD_FILES
permission (ADMIN / ANALYST), rejecting:
  - unauthenticated requests with 401
  - authenticated VIEWER requests with 403
while continuing to allow ADMIN and ANALYST identities.
"""

import io
import unittest

from fastapi.testclient import TestClient

from app.main import app
from app.db.session import init_db, SessionLocal
from app.testing.synthetic_pe import SyntheticPEBuilder
from tests.auth_helpers import make_admin, make_analyst, make_viewer


UPLOAD_ENDPOINTS = (
    "/api/files/upload",
    "/api/analyses",
    "/api/dashboard/analyze",
)


class TestUploadAuthorization(unittest.TestCase):
    """Upload endpoints must require the UPLOAD_FILES permission."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.db = SessionLocal()
        _, cls.admin_hdr = make_admin(cls.db)
        _, cls.analyst_hdr = make_analyst(cls.db)
        _, cls.viewer_hdr = make_viewer(cls.db)
        cls.pe = SyntheticPEBuilder.create_minimal_pe()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def _upload(self, endpoint, headers):
        return self.client.post(
            endpoint,
            files={"file": ("authz_sample.exe", io.BytesIO(self.pe), "application/octet-stream")},
            headers=headers,
        )

    def test_anonymous_upload_rejected_401(self):
        """No Authorization header -> 401 Unauthorized on every upload endpoint."""
        for endpoint in UPLOAD_ENDPOINTS:
            with self.subTest(endpoint=endpoint):
                response = self._upload(endpoint, None)
                self.assertEqual(response.status_code, 401, endpoint)

    def test_viewer_upload_forbidden_403(self):
        """Authenticated VIEWER (lacks UPLOAD_FILES) -> 403 Forbidden."""
        for endpoint in UPLOAD_ENDPOINTS:
            with self.subTest(endpoint=endpoint):
                response = self._upload(endpoint, self.viewer_hdr)
                self.assertEqual(response.status_code, 403, endpoint)

    def test_analyst_upload_allowed(self):
        """ANALYST holds UPLOAD_FILES -> upload accepted (200/201)."""
        for endpoint in UPLOAD_ENDPOINTS:
            with self.subTest(endpoint=endpoint):
                response = self._upload(endpoint, self.analyst_hdr)
                self.assertIn(response.status_code, (200, 201), endpoint)

    def test_admin_upload_allowed(self):
        """ADMIN holds UPLOAD_FILES -> upload accepted (200/201)."""
        for endpoint in UPLOAD_ENDPOINTS:
            with self.subTest(endpoint=endpoint):
                response = self._upload(endpoint, self.admin_hdr)
                self.assertIn(response.status_code, (200, 201), endpoint)

    def test_authorization_precedes_body_validation(self):
        """A rejected (VIEWER) upload returns 403 even for an invalid payload.

        Confirms authorization is enforced by the dependency rather than after
        parses/validates the file body.
        """
        response = self.client.post(
            "/api/files/upload",
            files={"file": ("not_a_pe.txt", io.BytesIO(b"plain text"), "application/octet-stream")},
            headers=self.viewer_hdr,
        )
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
