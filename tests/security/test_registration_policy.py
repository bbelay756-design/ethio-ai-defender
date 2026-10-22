"""
SEC-01: Public self-registration role policy.

Anonymous clients must never be able to obtain a privileged role
(ADMIN / ANALYST) through POST /api/auth/register.
"""

import secrets
import unittest

from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.db.session import init_db


OMITTED = object()


class TestRegistrationPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    def setUp(self):
        self.prefix = f"regpol_{secrets.token_hex(4)}"

    def _unique(self, tag):
        return f"{self.prefix}_{tag}_{secrets.token_hex(3)}"

    def _register(self, username, role=OMITTED, password="RegPolicyPass2026!"):
        payload = {
            "username": username,
            "email": f"{username}@university.edu.et",
            "password": password,
        }
        if role is not OMITTED:
            payload["role"] = role
        return self.client.post("/api/auth/register", json=payload)

    def test_public_registration_defaults_to_viewer(self):
        res = self._register(self._unique("no_role"))
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["role"], "VIEWER")

    def test_public_registration_null_role_yields_viewer(self):
        res = self._register(self._unique("null_role"), role=None)
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["role"], "VIEWER")

    def test_public_registration_rejects_admin(self):
        for variant in ["ADMIN", "admin", "Admin", " ADMIN ", "ADMIN\t", "aDmIn"]:
            with self.subTest(role=variant):
                res = self._register(self._unique("adm"), role=variant)
                self.assertEqual(res.status_code, 400)
                self.assertEqual(res.json()["role"] if res.status_code == 201 else None, None)

    def test_public_registration_rejects_analyst(self):
        for variant in ["ANALYST", "analyst", " Analyst ", "AnAlYsT"]:
            with self.subTest(role=variant):
                res = self._register(self._unique("anl"), role=variant)
                self.assertEqual(res.status_code, 400)

    def test_rejected_escalation_creates_no_user(self):
        username = self._unique("ghost")
        res = self._register(username, role="ADMIN")
        self.assertEqual(res.status_code, 400)
        login = self.client.post("/api/auth/login", json={
            "username": username,
            "password": "RegPolicyPass2026!",
        })
        self.assertEqual(login.status_code, 401)

    def test_admin_provisioning_requires_authentication(self):
        res = self.client.post("/api/auth/users", json={
            "username": self._unique("probe"),
            "email": f"{self._unique('probe')}@insa.gov.et",
            "password": "RegPolicyPass2026!",
            "role": "ADMIN",
        })
        self.assertIn(res.status_code, (401, 403))

    def test_allowlist_never_contains_admin(self):
        self.assertNotIn("ADMIN", settings.SELF_REGISTRATION_ROLES)
        self.assertIn("VIEWER", settings.SELF_REGISTRATION_ROLES)


if __name__ == "__main__":
    unittest.main()
