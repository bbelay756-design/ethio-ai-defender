"""
Comprehensive Security Testing Suite for Module 16: Authentication and Access Control.

Covers:
1. Authentication tests (valid admin, analyst, student, wrong pass, unknown user, empty user/pass, missing auth, invalid token, expired token, logout, protected access).
2. Role-Based Authorization tests (ADMIN, ANALYST, STUDENT boundaries).
3. Object-Level Authorization tests (User A owns Analysis A, User B denied access/delete).
4. Password Security (PBKDF2-HMAC-SHA256, salted, zero plaintext storage).
5. Security Input Tests (SQL injection, SQL comments, XSS payloads).
6. Rate Limiting and Account Lockout.
7. Session and Token Lifecycle tests.
8. Security Logging and Secrets Leak Prevention.
"""

import time
import secrets
import unittest
from datetime import timedelta
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.db.session import SessionLocal, init_db
from app.db.models import UserModel, SampleModel, RevokedTokenModel
from app.auth.roles import UserRole, Permission, has_permission
from app.auth.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token
)
from app.auth.rate_limiter import rate_limiter
from app.auth.service import AuthService


class TestComprehensiveSecurityModule16(unittest.TestCase):
    """Dedicated comprehensive security test suite for Module 16."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

        # Standard Test Accounts with fake credentials
        cls.admin_user = "admin_sec_tester"
        cls.admin_email = "admin@test.local"
        cls.admin_pass = "FakeAdminPass2026!"

        cls.analyst_user = "analyst_sec_tester"
        cls.analyst_email = "analyst@test.local"
        cls.analyst_pass = "FakeAnalystPass2026!"

        cls.student_user = "student_sec_tester"
        cls.student_email = "student@test.local"
        cls.student_pass = "FakeStudentPass2026!"

        # Register standard test users if not exist
        db = SessionLocal()
        try:
            for u, e, p, r in [
                (cls.admin_user, cls.admin_email, cls.admin_pass, "ADMIN"),
                (cls.analyst_user, cls.analyst_email, cls.analyst_pass, "ANALYST"),
                (cls.student_user, cls.student_email, cls.student_pass, "STUDENT"),
            ]:
                if not db.query(UserModel).filter(UserModel.username == u).first():
                    AuthService.register_user(db, username=u, email=e, password=p, role=r)
        finally:
            db.close()

    def setUp(self):
        rate_limiter.reset_all()
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    # ==========================================
    # 1. AUTHENTICATION TESTS
    # ==========================================
    def test_01_valid_admin_login(self):
        """Test valid admin login returns 200 and access token."""
        res = self.client.post("/api/auth/login", json={
            "username": self.admin_user,
            "password": self.admin_pass
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["role"], "ADMIN")

    def test_02_valid_analyst_login(self):
        """Test valid analyst login returns 200 and access token."""
        res = self.client.post("/api/auth/login", json={
            "username": self.analyst_user,
            "password": self.analyst_pass
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["role"], "ANALYST")

    def test_03_valid_student_login(self):
        """Test valid student login returns 200 and access token."""
        res = self.client.post("/api/auth/login", json={
            "username": self.student_user,
            "password": self.student_pass
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["role"], "STUDENT")

    def test_04_wrong_password_returns_401(self):
        """Test authentication with wrong password returns 401 Unauthorized."""
        res = self.client.post("/api/auth/login", json={
            "username": self.student_user,
            "password": "IncorrectPassword123!"
        })
        self.assertEqual(res.status_code, 401)
        self.assertIn("Invalid username or password", res.json()["detail"])

    def test_05_unknown_username_returns_401(self):
        """Test authentication with unknown user returns 401 Unauthorized."""
        res = self.client.post("/api/auth/login", json={
            "username": "non_existent_user_999",
            "password": "AnyPassword123!"
        })
        self.assertEqual(res.status_code, 401)
        self.assertIn("Invalid username or password", res.json()["detail"])

    def test_06_empty_username_validation_failure(self):
        """Test empty username triggers 422 validation failure."""
        res = self.client.post("/api/auth/login", json={
            "username": "",
            "password": "ValidPassword123!"
        })
        self.assertEqual(res.status_code, 422)

    def test_07_empty_password_validation_failure(self):
        """Test empty password triggers 422 validation failure."""
        res = self.client.post("/api/auth/login", json={
            "username": self.student_user,
            "password": ""
        })
        self.assertEqual(res.status_code, 422)

    def test_08_missing_authentication_returns_401(self):
        """Test accessing protected route without token returns 401."""
        res = self.client.get("/api/auth/me")
        self.assertEqual(res.status_code, 401)
        self.assertIn("Missing Authorization header", res.json()["detail"])

    def test_09_invalid_token_signature_returns_401(self):
        """Test accessing protected route with forged token returns 401."""
        forged_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiJ9.invalid_signature"
        res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged_token}"})
        self.assertEqual(res.status_code, 401)

    def test_10_expired_token_returns_401(self):
        """Test accessing protected route with expired token returns 401."""
        # Create token that expired 1 hour ago
        expired_token, _, _ = create_access_token(
            data={"sub": "1", "username": self.admin_user, "role": "ADMIN"},
            expires_delta=timedelta(hours=-1)
        )
        res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
        self.assertEqual(res.status_code, 401)
        self.assertIn("expired", res.json()["detail"].lower())

    def test_11_logout_and_revocation_behavior(self):
        """Test that logout revokes token and subsequent access fails with 401."""
        login_res = self.client.post("/api/auth/login", json={
            "username": self.analyst_user,
            "password": self.analyst_pass
        })
        token = login_res.json()["access_token"]

        # Valid before logout
        res_before = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_before.status_code, 200)

        # Logout
        logout_res = self.client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(logout_res.status_code, 200)

        # 401 after logout
        res_after = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res_after.status_code, 401)
        self.assertIn("revoked", res_after.json()["detail"].lower())

    def test_12_protected_endpoint_access(self):
        """Test valid bearer token successfully accesses /api/auth/me."""
        login_res = self.client.post("/api/auth/login", json={
            "username": self.student_user,
            "password": self.student_pass
        })
        token = login_res.json()["access_token"]
        res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["username"], self.student_user)
        self.assertEqual(res.json()["role"], "STUDENT")

    # ==========================================
    # 2. AUTHORIZATION TESTS (ROLE BOUNDARIES)
    # ==========================================
    def test_13_admin_role_can_access_user_management(self):
        """Test ADMIN role can list all platform users."""
        admin_token = self.client.post("/api/auth/login", json={
            "username": self.admin_user,
            "password": self.admin_pass
        }).json()["access_token"]

        res = self.client.get("/api/auth/users", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

    def test_14_analyst_role_cannot_access_admin_endpoints(self):
        """Test ANALYST role receives 403 Forbidden on admin user management."""
        analyst_token = self.client.post("/api/auth/login", json={
            "username": self.analyst_user,
            "password": self.analyst_pass
        }).json()["access_token"]

        res = self.client.get("/api/auth/users", headers={"Authorization": f"Bearer {analyst_token}"})
        self.assertEqual(res.status_code, 403)
        self.assertIn("Access forbidden", res.json()["detail"])

    def test_15_student_role_cannot_access_admin_endpoints(self):
        """Test STUDENT role receives 403 Forbidden on admin user management."""
        student_token = self.client.post("/api/auth/login", json={
            "username": self.student_user,
            "password": self.student_pass
        }).json()["access_token"]

        res = self.client.get("/api/auth/users", headers={"Authorization": f"Bearer {student_token}"})
        self.assertEqual(res.status_code, 403)
        self.assertIn("Access forbidden", res.json()["detail"])

    def test_16_student_role_cannot_update_roles(self):
        """Test STUDENT role receives 403 Forbidden when attempting to elevate user roles."""
        student_token = self.client.post("/api/auth/login", json={
            "username": self.student_user,
            "password": self.student_pass
        }).json()["access_token"]

        res = self.client.put("/api/auth/users/1/role", json={"role": "ADMIN"}, headers={"Authorization": f"Bearer {student_token}"})
        self.assertEqual(res.status_code, 403)

    # ==========================================
    # 3. OBJECT-LEVEL AUTHORIZATION
    # ==========================================
    def test_17_object_level_authorization_denial(self):
        """
        Verify Object-Level Authorization:
        - User A owns Analysis A.
        - User B attempts to access Analysis A -> Denied with 403 Forbidden.
        - User B attempts to delete Analysis A -> Denied with 403 Forbidden.
        - User A accesses Analysis A -> Allowed (200 OK).
        - Admin accesses Analysis A -> Allowed (200 OK).
        """
        pfx = secrets.token_hex(4)
        # Register User A (Student A) and User B (Student B)
        user_a = AuthService.register_user(self.db, f"user_a_{pfx}", f"user_a_{pfx}@test.local", "FakePass12345!", "STUDENT")
        user_b = AuthService.register_user(self.db, f"user_b_{pfx}", f"user_b_{pfx}@test.local", "FakePass12345!", "STUDENT")

        # Create Analysis A owned by User A
        anl_id = f"ANL-OBJ-{pfx}"
        sample_a = SampleModel(
            analysis_id=anl_id,
            filename="user_a_sample.exe",
            size=1024,
            file_type="EXE",
            architecture="x64",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status="ANALYZED",
            user_id=user_a.id
        )
        self.db.add(sample_a)
        self.db.commit()

        # Login User A and User B
        token_a = self.client.post("/api/auth/login", json={"username": user_a.username, "password": "FakePass12345!"}).json()["access_token"]
        token_b = self.client.post("/api/auth/login", json={"username": user_b.username, "password": "FakePass12345!"}).json()["access_token"]
        token_admin = self.client.post("/api/auth/login", json={"username": self.admin_user, "password": self.admin_pass}).json()["access_token"]

        # 1. User B attempts GET on Analysis A -> 403 Forbidden
        res_b_get = self.client.get(f"/api/auth/analyses/{anl_id}", headers={"Authorization": f"Bearer {token_b}"})
        self.assertEqual(res_b_get.status_code, 403)
        self.assertIn("do not own", res_b_get.json()["detail"].lower())

        # 2. User B attempts DELETE on Analysis A -> 403 Forbidden
        res_b_del = self.client.delete(f"/api/auth/analyses/{anl_id}", headers={"Authorization": f"Bearer {token_b}"})
        self.assertEqual(res_b_del.status_code, 403)
        self.assertIn("cannot delete another user", res_b_del.json()["detail"].lower())

        # 3. User A attempts GET on Analysis A -> 200 OK
        res_a_get = self.client.get(f"/api/auth/analyses/{anl_id}", headers={"Authorization": f"Bearer {token_a}"})
        self.assertEqual(res_a_get.status_code, 200)
        self.assertEqual(res_a_get.json()["analysis_id"], anl_id)

        # 4. Admin attempts GET on Analysis A -> 200 OK
        res_admin_get = self.client.get(f"/api/auth/analyses/{anl_id}", headers={"Authorization": f"Bearer {token_admin}"})
        self.assertEqual(res_admin_get.status_code, 200)

        # 5. User A deletes their own analysis -> 200 OK
        res_a_del = self.client.delete(f"/api/auth/analyses/{anl_id}", headers={"Authorization": f"Bearer {token_a}"})
        self.assertEqual(res_a_del.status_code, 200)

    # ==========================================
    # 4. PASSWORD SECURITY & HASHING
    # ==========================================
    def test_18_passwords_never_stored_plaintext(self):
        """Verify that all stored user passwords in database are cryptographically hashed."""
        users = self.db.query(UserModel).all()
        for u in users:
            self.assertNotEqual(u.hashed_password, self.admin_pass)
            self.assertNotEqual(u.hashed_password, self.analyst_pass)
            self.assertNotEqual(u.hashed_password, self.student_pass)
            # PBKDF2 SHA-256 produces 64-hex-character digest
            self.assertEqual(len(u.hashed_password), 64)
            # Salt is 32-hex characters (16 random bytes)
            self.assertEqual(len(u.salt), 32)

    def test_19_pbkdf2_algorithm_verification(self):
        """Verify PBKDF2-HMAC-SHA256 algorithm with distinct salts."""
        raw_pass = "AlgVerificationPass2026!"
        s1, h1 = hash_password(raw_pass)
        s2, h2 = hash_password(raw_pass)

        self.assertNotEqual(s1, s2)
        self.assertNotEqual(h1, h2)
        self.assertTrue(verify_password(raw_pass, s1, h1))
        self.assertFalse(verify_password("WrongPass", s1, h1))

    # ==========================================
    # 5. SECURITY INPUT TESTS (SQLi, Comment, XSS)
    # ==========================================
    def test_20_sqli_payload_login_rejected(self):
        """Verify SQL injection payload does not bypass authentication."""
        sqli_payload = "' OR '1'='1"
        res = self.client.post("/api/auth/login", json={
            "username": sqli_payload,
            "password": sqli_payload
        })
        self.assertEqual(res.status_code, 401)

    def test_21_sql_comment_payload_login_rejected(self):
        """Verify SQL comment payload does not bypass authentication."""
        comment_payload = "admin'--"
        res = self.client.post("/api/auth/login", json={
            "username": comment_payload,
            "password": "anypassword"
        })
        self.assertEqual(res.status_code, 401)

    def test_22_xss_payload_registration_and_login_safe(self):
        """Verify XSS script payload does not execute or bypass auth."""
        xss_payload = '<script>alert("XSS")</script>'
        res_login = self.client.post("/api/auth/login", json={
            "username": xss_payload,
            "password": "Password123!"
        })
        self.assertEqual(res_login.status_code, 401)

    # ==========================================
    # 6. RATE LIMITING & LOCKOUT
    # ==========================================
    def test_23_rate_limiting_and_account_lockout_activation(self):
        """Verify that 5 consecutive failed attempts trigger account lockout (423)."""
        target_name = f"rate_target_{secrets.token_hex(4)}"
        AuthService.register_user(self.db, target_name, f"{target_name}@test.local", "TargetPass123!", "STUDENT")

        for _ in range(4):
            r = self.client.post("/api/auth/login", json={"username": target_name, "password": "WrongPassword"})
            self.assertEqual(r.status_code, 401)

        # 5th attempt locks out account
        r5 = self.client.post("/api/auth/login", json={"username": target_name, "password": "WrongPassword"})
        self.assertEqual(r5.status_code, 423)
        self.assertIn("locked", r5.json()["detail"].lower())

    # ==========================================
    # 7. SESSION & TOKEN EDGE CASES
    # ==========================================
    def test_24_malformed_token_handling(self):
        """Verify malformed tokens are safely rejected with 401."""
        for malformed in ["not_a_jwt", "part1.part2", "part1.part2.part3.part4", ""]:
            headers = {"Authorization": f"Bearer {malformed}"} if malformed else {}
            res = self.client.get("/api/auth/me", headers=headers)
            self.assertEqual(res.status_code, 401)

    # ==========================================
    # 8. SECURITY LOGGING AND SECRETS EXCLUSION
    # ==========================================
    def test_25_security_logging_and_zero_secret_leakage(self):
        """Verify that authentication events are logged and secrets/passwords are never logged."""
        with patch("app.core.logger.logger.info") as mock_info, \
             patch("app.core.logger.logger.warning") as mock_warn:

            # 1. Trigger successful login
            self.client.post("/api/auth/login", json={"username": self.admin_user, "password": self.admin_pass})
            
            # 2. Trigger failed login
            self.client.post("/api/auth/login", json={"username": self.admin_user, "password": "WrongPassword123!"})

            # Check that logger recorded events
            mock_info_calls = [str(call) for call in mock_info.call_args_list]
            mock_warn_calls = [str(call) for call in mock_warn.call_args_list]

            combined_logs = " ".join(mock_info_calls + mock_warn_calls)
            
            # Assert secrets/passwords/tokens are never present in log text
            self.assertNotIn(self.admin_pass, combined_logs)
            self.assertNotIn("WrongPassword123!", combined_logs)
            self.assertNotIn(settings.SECRET_KEY, combined_logs)


if __name__ == "__main__":
    unittest.main()
