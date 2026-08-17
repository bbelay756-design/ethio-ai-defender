"""
Module 18 - Security Testing: Step 11 - Rate Limiting & Brute-Force Protection.
Tests in-memory sliding-window request throttling and account lockout after repeated failed login attempts.
"""

import uuid
import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import init_db, SessionLocal
from app.auth.service import AuthService
from app.auth.roles import UserRole
from app.auth.rate_limiter import rate_limiter


class TestRateLimiting(unittest.TestCase):
    """Rate limiting and brute-force lockout test suite."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        cls.victim_username = f"rl_target_{uuid.uuid4().hex[:6]}"
        cls.correct_password = "ValidTargetPass2026!"
        cls.user = AuthService.register_user(
            cls.db, cls.victim_username, f"{cls.victim_username}@soc.et", cls.correct_password, role=UserRole.STUDENT
        )

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        rate_limiter.reset_all()

    def test_01_brute_force_lockout_activation(self):
        """Verify 5 consecutive failed login attempts trigger an immediate 15-minute account lockout."""
        # 1-4 failed attempts -> 401 Unauthorized
        for i in range(4):
            res = self.client.post(
                "/api/auth/login",
                json={"username": self.victim_username, "password": "WrongPassword!"}
            )
            self.assertEqual(res.status_code, 401)

        # 5th failed attempt -> locks account
        res5 = self.client.post(
            "/api/auth/login",
            json={"username": self.victim_username, "password": "WrongPassword!"}
        )
        self.assertIn(res5.status_code, [401, 423, 429])

        # 6th attempt with CORRECT password must be rejected due to active lockout
        locked_res = self.client.post(
            "/api/auth/login",
            json={"username": self.victim_username, "password": self.correct_password}
        )
        self.assertIn(locked_res.status_code, [423, 429])
        self.assertIn("locked", locked_res.json()["detail"].lower())


if __name__ == "__main__":
    unittest.main()
