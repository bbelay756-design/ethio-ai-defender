"""
Module 18 - Security Testing: Step 8 - Object-Level Authorization (IDOR Protection).
Tests object ownership boundaries and prevents unauthorized access or deletion of other users' samples.
"""

import io
import uuid
import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import init_db, SessionLocal
from app.auth.service import AuthService
from app.auth.roles import UserRole
from app.testing.synthetic_pe import SyntheticPEBuilder


class TestObjectAuthorization(unittest.TestCase):
    """Object-level authorization and Insecure Direct Object Reference (IDOR) prevention suite."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()
        cls.synthetic_pe = SyntheticPEBuilder.create_minimal_pe()

        uid = uuid.uuid4().hex[:6]
        # 1. Create User A (Analyst)
        cls.user_a_name = f"user_a_{uid}"
        cls.user_a = AuthService.register_user(
            cls.db, cls.user_a_name, f"{cls.user_a_name}@soc.et", "PasswordA2026!", role=UserRole.ANALYST
        )
        cls.token_a = AuthService.create_token_for_user(cls.user_a)["access_token"]
        cls.hdr_a = {"Authorization": f"Bearer {cls.token_a}"}

        # 2. Create User B (Analyst)
        cls.user_b_name = f"user_b_{uid}"
        cls.user_b = AuthService.register_user(
            cls.db, cls.user_b_name, f"{cls.user_b_name}@soc.et", "PasswordB2026!", role=UserRole.ANALYST
        )
        cls.token_b = AuthService.create_token_for_user(cls.user_b)["access_token"]
        cls.hdr_b = {"Authorization": f"Bearer {cls.token_b}"}

        # 3. Create Admin User
        cls.admin_name = f"admin_{uid}"
        cls.admin = AuthService.register_user(
            cls.db, cls.admin_name, f"{cls.admin_name}@soc.et", "AdminPass2026!", role=UserRole.ADMIN
        )
        cls.token_admin = AuthService.create_token_for_user(cls.admin)["access_token"]
        cls.hdr_admin = {"Authorization": f"Bearer {cls.token_admin}"}

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_01_user_a_creates_sample_and_user_b_idor_prevented(self):
        """User A creates an analysis sample; User B is forbidden from reading User A's private sample."""
        # User A analyzes a sample
        upload_res = self.client.post(
            "/api/dashboard/analyze",
            files={"file": ("user_a_binary.exe", io.BytesIO(self.synthetic_pe), "application/octet-stream")},
            headers=self.hdr_a
        )
        self.assertEqual(upload_res.status_code, 200)
        analysis_id = upload_res.json()["analysis_id"]

        # User A can read their own sample
        res_a = self.client.get(f"/api/dashboard/samples/{analysis_id}/full", headers=self.hdr_a)
        self.assertEqual(res_a.status_code, 200)

        # User B attempts to access User A's sample -> Must be 403 Forbidden (IDOR Prevented)
        res_b = self.client.get(f"/api/dashboard/samples/{analysis_id}/full", headers=self.hdr_b)
        self.assertEqual(res_b.status_code, 403)

        # Admin can access User A's sample
        res_admin = self.client.get(f"/api/dashboard/samples/{analysis_id}/full", headers=self.hdr_admin)
        self.assertEqual(res_admin.status_code, 200)

    def test_02_unauthorized_deletion_idor_prevented(self):
        """User B cannot delete User A's sample; only Owner or Admin can delete."""
        # User A analyzes a sample
        upload_res = self.client.post(
            "/api/dashboard/analyze",
            files={"file": ("user_a_del_test.exe", io.BytesIO(self.synthetic_pe), "application/octet-stream")},
            headers=self.hdr_a
        )
        analysis_id = upload_res.json()["analysis_id"]

        # User B attempts to delete User A's sample -> 403 Forbidden
        del_b = self.client.delete(f"/api/dashboard/samples/{analysis_id}", headers=self.hdr_b)
        self.assertEqual(del_b.status_code, 403)

        # User A can delete their own sample -> 200 OK
        del_a = self.client.delete(f"/api/dashboard/samples/{analysis_id}", headers=self.hdr_a)
        self.assertEqual(del_a.status_code, 200)


if __name__ == "__main__":
    unittest.main()
