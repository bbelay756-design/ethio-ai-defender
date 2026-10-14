"""
Security and Unit tests for Module 16: Authentication and Access Control.

Tests:
1. PBKDF2-HMAC-SHA256 password hashing with unique random salts.
2. User registration and role assignment (ADMIN, ANALYST, STUDENT).
3. JWT-like HMAC-SHA256 signed access token generation, decoding, and verification.
4. Token logout and revocation blacklist.
5. Role-Based Access Control (RBAC): Admin permissions granted, Student access forbidden (403).
6. Brute-force rate limiting and consecutive failed attempt account lockout.
7. Verification that plaintext passwords and secrets are never returned or logged.
"""

import time
import secrets
import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal, init_db
from app.db.models import UserModel
from app.auth.roles import UserRole, Permission, has_permission
from app.auth.security import hash_password, verify_password, create_access_token, decode_access_token
from app.auth.rate_limiter import rate_limiter
from app.auth.service import AuthService


class TestAuthenticationAndAccessControl(unittest.TestCase):
    """Unit and security test suite for Module 16."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    def setUp(self):
        rate_limiter.reset_all()
        self.db = SessionLocal()
        self.prefix = f"t_{secrets.token_hex(4)}"

    def tearDown(self):
        self.db.close()

    def test_password_hashing_and_verification(self):
        """Verify PBKDF2-HMAC-SHA256 hashing produces unique salts and verifies correctly."""
        password = "DefensiveMalwareLab2026!"
        salt1, hash1 = hash_password(password)
        salt2, hash2 = hash_password(password)

        # Unique salts guarantee different hashes for identical passwords
        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(hash1, hash2)

        # Verification succeeds with correct password
        self.assertTrue(verify_password(password, salt1, hash1))
        self.assertTrue(verify_password(password, salt2, hash2))

        # Verification fails with wrong password
        self.assertFalse(verify_password("WrongPassword123", salt1, hash1))

    def test_user_registration_and_roles(self):
        """SEC-01: public self-registration assigns STUDENT and rejects privileged roles."""
        # 1. Register Student (allowed)
        student_res = self.client.post("/api/auth/register", json={
            "username": f"{self.prefix}_student",
            "email": f"{self.prefix}_student@university.edu.et",
            "password": "StudentSecurePass2026!",
            "role": "STUDENT"
        })
        self.assertEqual(student_res.status_code, 201)
        data = student_res.json()
        self.assertEqual(data["username"], f"{self.prefix}_student")
        self.assertEqual(data["role"], "STUDENT")
        self.assertIn("use_learning_mode", data["permissions"])
        self.assertNotIn("manage_users", data["permissions"])

        # 2. Omitting the role still yields STUDENT (server-decided)
        default_res = self.client.post("/api/auth/register", json={
            "username": f"{self.prefix}_default",
            "email": f"{self.prefix}_default@university.edu.et",
            "password": "DefaultSecurePass2026!"
        })
        self.assertEqual(default_res.status_code, 201)
        self.assertEqual(default_res.json()["role"], "STUDENT")

        # 3. Self-registering as ANALYST is rejected
        analyst_res = self.client.post("/api/auth/register", json={
            "username": f"{self.prefix}_analyst",
            "email": f"{self.prefix}_analyst@soc.gov.et",
            "password": "AnalystSecurePass2026!",
            "role": "ANALYST"
        })
        self.assertEqual(analyst_res.status_code, 400)

        # 4. Self-registering as ADMIN is rejected (privilege escalation blocked)
        admin_res = self.client.post("/api/auth/register", json={
            "username": f"{self.prefix}_admin",
            "email": f"{self.prefix}_admin@insa.gov.et",
            "password": "AdminMasterPass2026!",
            "role": "ADMIN"
        })
        self.assertEqual(admin_res.status_code, 400)

    def test_duplicate_user_registration_rejected(self):
        """Verify registration rejects duplicate username or email."""
        uname = f"{self.prefix}_dup"
        self.client.post("/api/auth/register", json={
            "username": uname,
            "email": f"{uname}@university.edu.et",
            "password": "Password12345!"
        })

        # Attempt to register same username
        res = self.client.post("/api/auth/register", json={
            "username": uname,
            "email": f"{uname}_different@university.edu.et",
            "password": "Password12345!"
        })
        self.assertEqual(res.status_code, 400)
        self.assertIn("already registered", res.json()["detail"])

    def test_authentication_and_token_generation(self):
        """Verify login returns valid signed access token and user info."""
        uname = f"{self.prefix}_login"
        self.client.post("/api/auth/register", json={
            "username": uname,
            "email": f"{uname}@university.edu.et",
            "password": "LoginSecurePass2026!",
            "role": "STUDENT"
        })

        login_res = self.client.post("/api/auth/login", json={
            "username": uname,
            "password": "LoginSecurePass2026!"
        })
        self.assertEqual(login_res.status_code, 200)
        data = login_res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["role"], "STUDENT")

        # Use token on /api/auth/me
        token = data["access_token"]
        me_res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_res.status_code, 200)
        self.assertEqual(me_res.json()["username"], uname)

    def test_token_logout_and_revocation(self):
        """Verify logout revokes token and prevents subsequent access."""
        uname = f"{self.prefix}_logout"
        self.client.post("/api/auth/register", json={
            "username": uname,
            "email": f"{uname}@soc.gov.et",
            "password": "LogoutSecurePass2026!",
            "role": "ANALYST"
        })

        # Login
        login_res = self.client.post("/api/auth/login", json={
            "username": uname,
            "password": "LogoutSecurePass2026!"
        })
        token = login_res.json()["access_token"]

        # Access before logout
        me_before = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_before.status_code, 200)

        # Logout
        logout_res = self.client.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(logout_res.status_code, 200)

        # Access after logout must be rejected (401)
        me_after = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_after.status_code, 401)
        self.assertIn("revoked", me_after.json()["detail"].lower())

    def test_rbac_students_cannot_access_admin_functions(self):
        """Verify students are strictly forbidden (403) from accessing administrator endpoints."""
        student_uname = f"{self.prefix}_rbac_std"
        admin_uname = f"{self.prefix}_rbac_adm"

        self.client.post("/api/auth/register", json={
            "username": student_uname,
            "email": f"{student_uname}@university.edu.et",
            "password": "StudentPass2026!",
            "role": "STUDENT"
        })
        # SEC-01: ADMIN cannot be self-registered; provision directly via the service layer.
        AuthService.register_user(
            db=self.db,
            username=admin_uname,
            email=f"{admin_uname}@insa.gov.et",
            password="AdminPass2026!",
            role="ADMIN"
        )

        # Student login
        student_token = self.client.post("/api/auth/login", json={
            "username": student_uname,
            "password": "StudentPass2026!"
        }).json()["access_token"]

        # Student attempts to list all users (Admin only)
        forbidden_res = self.client.get("/api/auth/users", headers={"Authorization": f"Bearer {student_token}"})
        self.assertEqual(forbidden_res.status_code, 403)
        self.assertIn("Access forbidden", forbidden_res.json()["detail"])

        # Admin login
        admin_token = self.client.post("/api/auth/login", json={
            "username": admin_uname,
            "password": "AdminPass2026!"
        }).json()["access_token"]

        # Admin succeeds
        admin_list_res = self.client.get("/api/auth/users", headers={"Authorization": f"Bearer {admin_token}"})
        self.assertEqual(admin_list_res.status_code, 200)
        self.assertIsInstance(admin_list_res.json(), list)

    def test_brute_force_account_lockout(self):
        """Verify 5 consecutive failed logins trigger account lockout."""
        target_uname = f"{self.prefix}_target"
        self.client.post("/api/auth/register", json={
            "username": target_uname,
            "email": f"{target_uname}@insa.gov.et",
            "password": "TargetPass2026!"
        })

        # 4 failed attempts: returns 401
        for _ in range(4):
            res = self.client.post("/api/auth/login", json={
                "username": target_uname,
                "password": "WrongPassword!"
            })
            self.assertEqual(res.status_code, 401)

        # 5th failed attempt: triggers Account Lockout (HTTP 423 Locked)
        lockout_res = self.client.post("/api/auth/login", json={
            "username": target_uname,
            "password": "WrongPassword!"
        })
        self.assertEqual(lockout_res.status_code, 423)
        self.assertIn("locked", lockout_res.json()["detail"].lower())

    def test_zero_plaintext_password_stored(self):
        """Verify that database never contains plaintext passwords."""
        secret_uname = f"{self.prefix}_secret"
        self.client.post("/api/auth/register", json={
            "username": secret_uname,
            "email": f"{secret_uname}@insa.gov.et",
            "password": "SuperSecretPass2026!",
            "role": "ANALYST"
        })
        user = self.db.query(UserModel).filter(UserModel.username == secret_uname).first()
        self.assertIsNotNone(user)
        self.assertNotEqual(user.hashed_password, "SuperSecretPass2026!")
        self.assertTrue(len(user.hashed_password) >= 64)
        self.assertTrue(len(user.salt) >= 32)


if __name__ == "__main__":
    unittest.main()
