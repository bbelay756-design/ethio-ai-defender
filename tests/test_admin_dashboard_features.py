"""
Unit and Integration Tests for Refined Admin Dashboard Features:
1. Admin Overview API (/api/auth/overview)
2. Direct User Provisioning (/api/auth/users - POST)
3. User Status Toggle (/api/auth/users/{id}/status - PUT)
4. User Deletion (/api/auth/users/{id} - DELETE)
5. Non-Admin RBAC Denial (403 Forbidden)
6. Self-Deactivation / Self-Deletion Safeguards (400 Bad Request)
"""

import os
import sys
import unittest
import uuid

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath("."))

from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal, init_db
from app.auth.service import AuthService


class TestAdminDashboardFeatures(unittest.TestCase):
    """
    Test suite verifying enhanced Administrator Control Center endpoints and operations.
    """

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

        cls.uid = uuid.uuid4().hex[:8]
        with SessionLocal() as db:
            cls.admin = AuthService.register_user(
                db=db,
                username=f"adm_feat_{cls.uid}",
                email=f"adm_feat_{cls.uid}@defensive.local",
                password="AdminPassword123!",
                role="ADMIN"
            )
            cls.analyst = AuthService.register_user(
                db=db,
                username=f"ana_feat_{cls.uid}",
                email=f"ana_feat_{cls.uid}@defensive.local",
                password="AnalystPassword123!",
                role="ANALYST"
            )
            cls.student = AuthService.register_user(
                db=db,
                username=f"stu_feat_{cls.uid}",
                email=f"stu_feat_{cls.uid}@defensive.local",
                password="StudentPassword123!",
                role="STUDENT"
            )

        # Login admin to get token
        admin_login = cls.client.post("/api/auth/login", json={
            "username": f"adm_feat_{cls.uid}",
            "password": "AdminPassword123!"
        })
        cls.admin_token = admin_login.json()["access_token"]
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}

        # Login student to get token
        student_login = cls.client.post("/api/auth/login", json={
            "username": f"stu_feat_{cls.uid}",
            "password": "StudentPassword123!"
        })
        cls.student_token = student_login.json()["access_token"]
        cls.student_headers = {"Authorization": f"Bearer {cls.student_token}"}

    def test_01_admin_overview_stats_success(self):
        """1. Admin can retrieve aggregated system stats via /api/auth/overview."""
        res = self.client.get("/api/auth/overview", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total_users", data)
        self.assertIn("admin_count", data)
        self.assertIn("analyst_count", data)
        self.assertIn("student_count", data)
        self.assertIn("system_health", data)
        self.assertTrue(data["zero_execution_guarantee"])
        self.assertIsInstance(data["recent_users"], list)

    def test_02_student_cannot_access_admin_overview(self):
        """2. Non-admin user gets 403 Forbidden when calling /api/auth/overview."""
        res = self.client.get("/api/auth/overview", headers=self.student_headers)
        self.assertEqual(res.status_code, 403)

    def test_03_admin_can_provision_new_user(self):
        """3. Admin can provision a new analyst directly via POST /api/auth/users."""
        new_username = f"prov_user_{uuid.uuid4().hex[:6]}"
        res = self.client.post("/api/auth/users", headers=self.admin_headers, json={
            "username": new_username,
            "email": f"{new_username}@defensive.local",
            "password": "ProvPassword123!",
            "role": "ANALYST"
        })
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["username"], new_username)
        self.assertEqual(data["role"], "ANALYST")
        self.assertEqual(data["dashboard_url"], "/analyst/dashboard")

    def test_04_admin_can_toggle_user_active_status(self):
        """4. Admin can deactivate and reactivate a user account."""
        # Provision temporary student
        tmp_username = f"tmp_deact_{uuid.uuid4().hex[:6]}"
        prov_res = self.client.post("/api/auth/users", headers=self.admin_headers, json={
            "username": tmp_username,
            "email": f"{tmp_username}@defensive.local",
            "password": "TmpPassword123!",
            "role": "STUDENT"
        })
        tmp_user_id = prov_res.json()["id"]

        # Deactivate user
        deact_res = self.client.put(f"/api/auth/users/{tmp_user_id}/status", headers=self.admin_headers)
        self.assertEqual(deact_res.status_code, 200)
        self.assertFalse(deact_res.json()["is_active"])

        # Deactivated user cannot log in
        bad_login = self.client.post("/api/auth/login", json={
            "username": tmp_username,
            "password": "TmpPassword123!"
        })
        self.assertEqual(bad_login.status_code, 401)
        self.assertIn("inactive", bad_login.json().get("detail", "").lower())

        # Reactivate user
        react_res = self.client.put(f"/api/auth/users/{tmp_user_id}/status", headers=self.admin_headers)
        self.assertEqual(react_res.status_code, 200)
        self.assertTrue(react_res.json()["is_active"])

        # Reactivated user can now log in
        good_login = self.client.post("/api/auth/login", json={
            "username": tmp_username,
            "password": "TmpPassword123!"
        })
        self.assertEqual(good_login.status_code, 200)

    def test_05_admin_cannot_deactivate_self(self):
        """5. Safeguard: Admin cannot deactivate their own account."""
        res = self.client.put(f"/api/auth/users/{self.admin.id}/status", headers=self.admin_headers)
        self.assertEqual(res.status_code, 400)
        self.assertIn("cannot deactivate", res.json().get("detail", "").lower())

    def test_06_admin_can_delete_user(self):
        """6. Admin can permanently delete a user account."""
        del_username = f"del_user_{uuid.uuid4().hex[:6]}"
        prov_res = self.client.post("/api/auth/users", headers=self.admin_headers, json={
            "username": del_username,
            "email": f"{del_username}@defensive.local",
            "password": "DelPassword123!",
            "role": "STUDENT"
        })
        del_user_id = prov_res.json()["id"]

        del_res = self.client.delete(f"/api/auth/users/{del_user_id}", headers=self.admin_headers)
        self.assertEqual(del_res.status_code, 200)
        self.assertIn("permanently deleted", del_res.json().get("message", "").lower())

        # Deleted user cannot log in
        login_res = self.client.post("/api/auth/login", json={
            "username": del_username,
            "password": "DelPassword123!"
        })
        self.assertEqual(login_res.status_code, 401)

    def test_07_admin_cannot_delete_self(self):
        """7. Safeguard: Admin cannot delete their own account."""
        res = self.client.delete(f"/api/auth/users/{self.admin.id}", headers=self.admin_headers)
        self.assertEqual(res.status_code, 400)
        self.assertIn("cannot delete", res.json().get("detail", "").lower())

    def test_08_admin_can_update_user_role(self):
        """8. Admin can modify a user's role and capability permissions."""
        res = self.client.put(f"/api/auth/users/{self.student.id}/role", headers=self.admin_headers, json={
            "role": "ANALYST"
        })
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["role"], "ANALYST")

    def test_09_admin_can_unlock_user(self):
        """9. Admin can unlock a user account."""
        res = self.client.post(f"/api/auth/users/{self.student.id}/unlock", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        self.assertIn("unlocked", res.json().get("message", "").lower())

    def test_10_admin_can_reset_password(self):
        """10. Admin can directly reset a user's password."""
        res = self.client.post(f"/api/auth/users/{self.student.id}/reset-password", headers=self.admin_headers, json={
            "password": "NewSecurePassword999!"
        })
        self.assertEqual(res.status_code, 200)
        self.assertIn("successfully reset", res.json().get("message", "").lower())

        # Verify login with new password
        login_res = self.client.post("/api/auth/login", json={
            "username": self.student.username,
            "password": "NewSecurePassword999!"
        })
        self.assertEqual(login_res.status_code, 200)

    def test_11_admin_can_get_rbac_matrix(self):
        """11. Admin can retrieve the granular RBAC permissions matrix."""
        res = self.client.get("/api/auth/rbac/matrix", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("matrix", data)
        self.assertIn("ADMIN", data["matrix"])
        self.assertIn("ANALYST", data["matrix"])
        self.assertIn("STUDENT", data["matrix"])
        self.assertIn("permissions", data)
        self.assertIn("roles", data)

    def test_12_admin_can_get_system_status_and_purge(self):
        """12. Admin can check system health metrics and purge quarantine buffer."""
        status_res = self.client.get("/api/auth/system/status", headers=self.admin_headers)
        self.assertEqual(status_res.status_code, 200)
        s_data = status_res.json()
        self.assertEqual(s_data["status"], "HEALTHY")
        self.assertEqual(s_data["zero_execution_sandbox"], "ENFORCED")
        self.assertIn("quarantine_count", s_data)
        self.assertIn("database_samples_count", s_data)

        purge_res = self.client.post("/api/auth/system/quarantine/cleanup", headers=self.admin_headers)
        self.assertEqual(purge_res.status_code, 200)
        self.assertIn("cleaned_count", purge_res.json())


if __name__ == "__main__":
    unittest.main(verbosity=2)
