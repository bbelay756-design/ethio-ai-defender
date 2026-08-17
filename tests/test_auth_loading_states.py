"""
Tests for Authentication Loading States, Endpoint Reachability, and Public Layout Guard.

Verifies:
1. Test 1: Unauthenticated request to /api/auth/me returns 401 Unauthorized.
2. Test 2: Admin session returns 200 with role ADMIN and /admin/dashboard.
3. Test 3: Analyst session returns 200 with role ANALYST and /analyst/dashboard.
4. Test 4: Student session returns 200 with role STUDENT and /student/dashboard.
5. Test 5: Revoked/invalid token returns 401 Unauthorized.
6. Test 6: HTML index contains decoupled public layout (#public-layout) and hidden loading overlay (#auth-loading-overlay).
"""

import unittest
import uuid
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal, init_db
from app.auth.service import AuthService


class TestAuthLoadingStates(unittest.TestCase):
    """
    Test suite verifying authentication loading state resolution,
    endpoints, and unauthenticated behavior.
    """

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

        cls.uid = uuid.uuid4().hex[:8]
        with SessionLocal() as db:
            cls.admin = AuthService.register_user(
                db=db,
                username=f"adm_load_{cls.uid}",
                email=f"adm_load_{cls.uid}@defensive.local",
                password="AdminPassword123!",
                role="ADMIN"
            )
            cls.analyst = AuthService.register_user(
                db=db,
                username=f"ana_load_{cls.uid}",
                email=f"ana_load_{cls.uid}@defensive.local",
                password="AnalystPassword123!",
                role="ANALYST"
            )
            cls.student = AuthService.register_user(
                db=db,
                username=f"stu_load_{cls.uid}",
                email=f"stu_load_{cls.uid}@defensive.local",
                password="StudentPassword123!",
                role="STUDENT"
            )

    @classmethod
    def tearDownClass(cls):
        pass

    def test_01_unauthenticated_returns_401_no_hang(self):
        """Test 1: Backend running + unauthenticated returns clear 401 without hanging."""
        res = self.client.get("/api/auth/me")
        self.assertEqual(res.status_code, 401)
        self.assertIn("detail", res.json())

    def test_02_admin_session_resolution(self):
        """Test 2: Backend running + valid admin session resolves to Admin Dashboard."""
        login = self.client.post("/api/auth/login", json={
            "username": f"adm_load_{self.uid}",
            "password": "AdminPassword123!"
        })
        self.assertEqual(login.status_code, 200)
        token = login.json()["access_token"]

        me_res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_res.status_code, 200)
        data = me_res.json()
        self.assertEqual(data["role"], "ADMIN")
        self.assertEqual(data["dashboard_url"], "/admin/dashboard")

    def test_03_analyst_session_resolution(self):
        """Test 3: Backend running + valid analyst session resolves to Analyst Dashboard."""
        login = self.client.post("/api/auth/login", json={
            "username": f"ana_load_{self.uid}",
            "password": "AnalystPassword123!"
        })
        self.assertEqual(login.status_code, 200)
        token = login.json()["access_token"]

        me_res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_res.status_code, 200)
        data = me_res.json()
        self.assertEqual(data["role"], "ANALYST")
        self.assertEqual(data["dashboard_url"], "/analyst/dashboard")

    def test_04_student_session_resolution(self):
        """Test 4: Backend running + valid student session resolves to Student Dashboard."""
        login = self.client.post("/api/auth/login", json={
            "username": f"stu_load_{self.uid}",
            "password": "StudentPassword123!"
        })
        self.assertEqual(login.status_code, 200)
        token = login.json()["access_token"]

        me_res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_res.status_code, 200)
        data = me_res.json()
        self.assertEqual(data["role"], "STUDENT")
        self.assertEqual(data["dashboard_url"], "/student/dashboard")

    def test_05_revoked_token_returns_401(self):
        """Test 5: Revoked token returns 401."""
        login = self.client.post("/api/auth/login", json={
            "username": f"adm_load_{self.uid}",
            "password": "AdminPassword123!"
        })
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Logout
        self.client.post("/api/auth/logout", headers=headers)

        # /api/auth/me with revoked token
        res = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(res.status_code, 401)

    def test_06_frontend_markup_includes_public_layout_and_managed_overlay(self):
        """Test 6: Frontend index serves public layout and connection banner without blocking."""
        res = self.client.get("/login", headers={"Accept": "text/html"})
        self.assertEqual(res.status_code, 200)
        html = res.text
        self.assertIn('id="public-layout"', html)
        self.assertIn('id="auth-loading-overlay"', html)
        self.assertIn('id="auth-connection-banner"', html)
        self.assertIn('id="auth-login-form"', html)
        self.assertIn('id="btn-submit-login"', html)


if __name__ == "__main__":
    unittest.main()
