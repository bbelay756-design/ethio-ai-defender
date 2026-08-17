"""
Module 18 - Security Testing: Step 6 & 7 - Authentication & Role-Based Access Control (RBAC).
Tests authentication lifecycles, token revocations, and strict role boundary enforcement.
"""

import uuid
import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import init_db, SessionLocal
from app.auth.service import AuthService
from app.auth.roles import UserRole


class TestAuthAndRBAC(unittest.TestCase):
    """Authentication lifecycle and multi-role authorization boundary test suite."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        uid = uuid.uuid4().hex[:6]
        # Create users for all three roles
        cls.admin_username = f"sec_admin_{uid}"
        cls.analyst_username = f"sec_analyst_{uid}"
        cls.student_username = f"sec_student_{uid}"
        cls.password = "SecTestPass2026!"

        cls.admin_user = AuthService.register_user(
            cls.db, cls.admin_username, f"{cls.admin_username}@soc.et", cls.password, role=UserRole.ADMIN
        )
        cls.analyst_user = AuthService.register_user(
            cls.db, cls.analyst_username, f"{cls.analyst_username}@soc.et", cls.password, role=UserRole.ANALYST
        )
        cls.student_user = AuthService.register_user(
            cls.db, cls.student_username, f"{cls.student_username}@soc.et", cls.password, role=UserRole.STUDENT
        )

        cls.admin_token = AuthService.create_token_for_user(cls.admin_user)["access_token"]
        cls.analyst_token = AuthService.create_token_for_user(cls.analyst_user)["access_token"]
        cls.student_token = AuthService.create_token_for_user(cls.student_user)["access_token"]

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_01_valid_login_returns_jwt(self):
        """Verify valid credentials return signed JWT bearer token and role."""
        res = self.client.post(
            "/api/auth/login",
            json={"username": self.admin_username, "password": self.password}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["role"], UserRole.ADMIN.value)

    def test_02_invalid_password_rejected(self):
        """Verify invalid password returns 401 Unauthorized."""
        res = self.client.post(
            "/api/auth/login",
            json={"username": self.admin_username, "password": "WrongPassword2026!"}
        )
        self.assertEqual(res.status_code, 401)

    def test_03_unknown_user_rejected(self):
        """Verify non-existent user returns 401 Unauthorized."""
        res = self.client.post(
            "/api/auth/login",
            json={"username": "completely_unknown_user_9999", "password": self.password}
        )
        self.assertEqual(res.status_code, 401)

    def test_04_token_revocation_on_logout(self):
        """Verify logging out blacklists the JWT JTI and revokes subsequent requests."""
        # Authenticate new session
        login_res = self.client.post(
            "/api/auth/login",
            json={"username": self.student_username, "password": self.password}
        )
        token = login_res.json()["access_token"]
        auth_hdr = {"Authorization": f"Bearer {token}"}

        # Verify access before logout
        res_me1 = self.client.get("/api/auth/me", headers=auth_hdr)
        self.assertEqual(res_me1.status_code, 200)

        # Logout
        res_logout = self.client.post("/api/auth/logout", headers=auth_hdr)
        self.assertEqual(res_logout.status_code, 200)

        # Verify token is now revoked
        res_me2 = self.client.get("/api/auth/me", headers=auth_hdr)
        self.assertEqual(res_me2.status_code, 401)

    def test_05_student_role_boundary_enforcement(self):
        """Verify STUDENT role cannot access user administration or security audit logs."""
        std_hdr = {"Authorization": f"Bearer {self.student_token}"}

        # Cannot list users
        res_users = self.client.get("/api/auth/users", headers=std_hdr)
        self.assertEqual(res_users.status_code, 403)

        # Cannot access audit logs
        res_audit = self.client.get("/api/audit/logs", headers=std_hdr)
        self.assertEqual(res_audit.status_code, 403)

    def test_06_analyst_role_boundary_enforcement(self):
        """Verify ANALYST role cannot access administrative audit logs."""
        anl_hdr = {"Authorization": f"Bearer {self.analyst_token}"}

        res_audit = self.client.get("/api/audit/logs", headers=anl_hdr)
        self.assertEqual(res_audit.status_code, 403)

    def test_07_admin_role_access_permitted(self):
        """Verify ADMIN role has permitted access to audit logs and platform user management."""
        adm_hdr = {"Authorization": f"Bearer {self.admin_token}"}

        res_users = self.client.get("/api/auth/users", headers=adm_hdr)
        self.assertEqual(res_users.status_code, 200)

        res_audit = self.client.get("/api/audit/logs", headers=adm_hdr)
        self.assertEqual(res_audit.status_code, 200)


if __name__ == "__main__":
    unittest.main()
