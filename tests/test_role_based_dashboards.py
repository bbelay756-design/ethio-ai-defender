"""
Tests for Role-Based Dashboard Routing and Authorization (Step 7 Verification)

Covers:
1. Admin login -> /admin/dashboard
2. Analyst login -> /analyst/dashboard
3. Viewer login -> /viewer/dashboard
4. Invalid credentials -> rejected (401)
5. Viewer requests admin API -> 403 Forbidden
6. Analyst requests admin API -> 403 Forbidden
7. Admin requests admin API -> allowed (200 OK)
8. Logout -> token revoked, protected routes unavailable
9. Missing / invalid role registration -> safe failure (400)
10. Web dashboard routes (/admin/dashboard, /analyst/dashboard, /viewer/dashboard, /unauthorized) -> 200 OK HTML
"""

import unittest
import uuid
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal, init_db
from app.db.models import UserModel
from app.auth.service import AuthService
from app.auth.roles import UserRole


class TestRoleBasedDashboards(unittest.TestCase):
    """
    Test suite verifying role-based dashboard URLs, responses, and authorization boundaries.
    """

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

        # Seed test users for each role
        cls.uid = uuid.uuid4().hex[:8]
        with SessionLocal() as db:
            cls.admin_user = AuthService.register_user(
                db=db,
                username=f"admin_{cls.uid}",
                email=f"admin_{cls.uid}@defensive.local",
                password="AdminSecretPassword123!",
                role="ADMIN"
            )
            cls.analyst_user = AuthService.register_user(
                db=db,
                username=f"analyst_{cls.uid}",
                email=f"analyst_{cls.uid}@defensive.local",
                password="AnalystSecretPassword123!",
                role="ANALYST"
            )
            cls.viewer_user = AuthService.register_user(
                db=db,
                username=f"viewer_{cls.uid}",
                email=f"viewer_{cls.uid}@defensive.local",
                password="ViewerSecretPassword123!",
                role="VIEWER"
            )

    @classmethod
    def tearDownClass(cls):
        pass

    def test_01_admin_login_routing(self):
        """1. Admin login returns admin role and /admin/dashboard URL."""
        res = self.client.post("/api/auth/login", json={
            "username": f"admin_{self.uid}",
            "password": "AdminSecretPassword123!"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["role"], "ADMIN")
        self.assertEqual(data["dashboard_url"], "/admin/dashboard")
        self.assertEqual(data["user_id"], self.admin_user.id)
        self.assertEqual(data["username"], f"admin_{self.uid}")
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")

    def test_02_analyst_login_routing(self):
        """2. Analyst login returns analyst role and /analyst/dashboard URL."""
        res = self.client.post("/api/auth/login", json={
            "username": f"analyst_{self.uid}",
            "password": "AnalystSecretPassword123!"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["role"], "ANALYST")
        self.assertEqual(data["dashboard_url"], "/analyst/dashboard")
        self.assertEqual(data["user_id"], self.analyst_user.id)
        self.assertEqual(data["username"], f"analyst_{self.uid}")

    def test_03_viewer_login_routing(self):
        """3. Viewer login returns viewer role and /viewer/dashboard URL."""
        res = self.client.post("/api/auth/login", json={
            "username": f"viewer_{self.uid}",
            "password": "ViewerSecretPassword123!"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["role"], "VIEWER")
        self.assertEqual(data["dashboard_url"], "/viewer/dashboard")
        self.assertEqual(data["user_id"], self.viewer_user.id)
        self.assertEqual(data["username"], f"viewer_{self.uid}")

    def test_04_invalid_credentials_rejected(self):
        """4. Invalid credentials rejected with 401 Unauthorized."""
        res = self.client.post("/api/auth/login", json={
            "username": f"admin_{self.uid}",
            "password": "WrongPassword123!"
        })
        self.assertEqual(res.status_code, 401)
        self.assertTrue("invalid" in res.json().get("detail", "").lower())

    def test_05_viewer_requests_admin_api_forbidden(self):
        """5. Viewer requesting admin API (/api/auth/users, /api/audit/logs) returns 403 Forbidden."""
        login_res = self.client.post("/api/auth/login", json={
            "username": f"viewer_{self.uid}",
            "password": "ViewerSecretPassword123!"
        })
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Viewer calls /api/auth/users
        res_users = self.client.get("/api/auth/users", headers=headers)
        self.assertEqual(res_users.status_code, 403)

        # Viewer calls /api/audit/logs
        res_logs = self.client.get("/api/audit/logs", headers=headers)
        self.assertEqual(res_logs.status_code, 403)

    def test_06_analyst_requests_admin_api_forbidden(self):
        """6. Analyst requesting admin API returns 403 Forbidden."""
        login_res = self.client.post("/api/auth/login", json={
            "username": f"analyst_{self.uid}",
            "password": "AnalystSecretPassword123!"
        })
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        res_users = self.client.get("/api/auth/users", headers=headers)
        self.assertEqual(res_users.status_code, 403)

        res_logs = self.client.get("/api/audit/logs", headers=headers)
        self.assertEqual(res_logs.status_code, 403)

    def test_07_admin_requests_admin_api_allowed(self):
        """7. Admin requesting admin API is allowed (200 OK)."""
        login_res = self.client.post("/api/auth/login", json={
            "username": f"admin_{self.uid}",
            "password": "AdminSecretPassword123!"
        })
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        res_users = self.client.get("/api/auth/users", headers=headers)
        self.assertEqual(res_users.status_code, 200)
        self.assertIsInstance(res_users.json(), list)

        res_logs = self.client.get("/api/audit/logs", headers=headers)
        self.assertEqual(res_logs.status_code, 200)
        self.assertIn("items", res_logs.json())

    def test_08_logout_invalidates_token(self):
        """8. Logout revokes token and blocks subsequent access to protected routes."""
        login_res = self.client.post("/api/auth/login", json={
            "username": f"admin_{self.uid}",
            "password": "AdminSecretPassword123!"
        })
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Verify access before logout
        res_before = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(res_before.status_code, 200)

        # Perform logout
        res_logout = self.client.post("/api/auth/logout", headers=headers)
        self.assertEqual(res_logout.status_code, 200)

        # Attempt access after logout -> 401
        res_after = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(res_after.status_code, 401)
        self.assertIn("revoked", res_after.json().get("detail", "").lower())

    def test_09_invalid_role_registration_fails(self):
        """9. Registration with an invalid role returns a safe 400 Bad Request."""
        res = self.client.post("/api/auth/register", json={
            "username": f"invalid_role_{uuid.uuid4().hex[:6]}",
            "email": f"badrole_{uuid.uuid4().hex[:6]}@defensive.local",
            "password": "ValidPassword123!",
            "role": "SUPER_HACKER_ROOT"
        })
        self.assertEqual(res.status_code, 400)
        self.assertTrue("invalid" in res.json().get("detail", "").lower())

    def test_10_web_dashboard_html_routes(self):
        """10. Role-specific dashboard web routes serve HTML."""
        routes = [
            "/admin/dashboard",
            "/analyst/dashboard",
            "/viewer/dashboard",
            "/unauthorized",
            "/dashboard",
            "/",
            "/login",
            "/about",
            "/analysis",
            "/pe-analysis",
            "/imports",
            "/strings",
            "/indicators",
            "/ai-analysis",
            "/reports",
            "/settings",
            "/admin/users",
            "/admin/audit",
            "/analyst/new-analysis",
            "/analyst/history",
            "/viewer/reports",
            "/viewer/analyses",
        ]
        for route in routes:
            res = self.client.get(route, headers={"Accept": "text/html"})
            self.assertEqual(res.status_code, 200, f"Route {route} failed")
            self.assertIn("text/html", res.headers.get("content-type", ""))
            self.assertIn("ETHIO-AI Defender", res.text)

    def test_11_unauthenticated_api_request_rejected(self):
        """11. Unauthenticated requests to protected endpoints return 401 Unauthorized."""
        endpoints = [
            "/api/auth/me",
            "/api/auth/users",
            "/api/audit/logs",
            "/api/audit/stats",
        ]
        for ep in endpoints:
            res = self.client.get(ep)
            self.assertEqual(res.status_code, 401, f"Expected 401 for unauthenticated {ep}, got {res.status_code}")

    def test_12_token_persistence_refresh_flow(self):
        """12. Session persistence: /api/auth/me validates stored token on refresh."""
        login_res = self.client.post("/api/auth/login", json={
            "username": f"viewer_{self.uid}",
            "password": "ViewerSecretPassword123!"
        })
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["access_token"]

        # Simulate page refresh / initial load with stored token
        refresh_res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(refresh_res.status_code, 200)
        user_data = refresh_res.json()
        self.assertEqual(user_data["username"], f"viewer_{self.uid}")
        self.assertEqual(user_data["role"], "VIEWER")
        self.assertEqual(user_data["dashboard_url"], "/viewer/dashboard")

    def test_13_client_cannot_escalate_via_tampered_role(self):
        """13. Zero-trust: Backend authorization always reads DB identity, ignoring any client role spoofing."""
        login_res = self.client.post("/api/auth/login", json={
            "username": f"viewer_{self.uid}",
            "password": "ViewerSecretPassword123!"
        })
        token = login_res.json()["access_token"]

        # Viewer attempts to call admin endpoint with query params or custom headers pretending to be admin
        res = self.client.get("/api/auth/users?role=ADMIN", headers={
            "Authorization": f"Bearer {token}",
            "X-User-Role": "ADMIN",
            "Role": "ADMIN"
        })
        self.assertEqual(res.status_code, 403, "Tampered client role must be ignored by backend RBAC")


if __name__ == "__main__":
    unittest.main()
