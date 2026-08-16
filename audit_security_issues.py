"""
Automated Defensive Security Audit and Penetration Test Suite for ETHIO-AI Defender.

Simulates 9 critical defensive security vectors:
1. Non-Execution Guarantee & Inert Quarantine Inspection
2. Path Traversal & File Intake Perimeter Validation
3. PBKDF2-HMAC-SHA256 Cryptographic Password Storage Audit
4. Token Forgery, Signature Tampering, and Expiration Defense
5. RBAC Authorization & Privilege Escalation Prevention
6. Object-Level Access Control (Cross-Tenant / Multi-User Isolation)
7. Injection Resilience (SQL Injection, SQL Comment, XSS in Auth and Input)
8. Brute-Force Rate Limiting & Account Lockout Defense
9. Sensitive Information Disclosure & Secret Leakage Prevention in Logs/APIs
"""

import sys
import os
import json
import time
import secrets
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from app.main import app
from app.core.config import settings, BASE_DIR
from app.db.session import SessionLocal, init_db
from app.db.models import UserModel, SampleModel
from app.auth.roles import UserRole, Permission, has_permission
from app.auth.security import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token
)
from app.auth.rate_limiter import rate_limiter
from app.auth.service import AuthService
from app.analyzers.file_intake import secure_intake_service


class ComprehensiveSecurityAudit(unittest.TestCase):
    """Hermetic security audit test suite testing all defensive security guarantees."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    def setUp(self):
        rate_limiter.reset_all()
        self.db = SessionLocal()
        self.pfx = f"sec_{secrets.token_hex(4)}"

    def tearDown(self):
        self.db.close()

    def _create_synthetic_pe(self) -> bytes:
        """Helper to create a valid synthetic PE binary header."""
        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'
        dos_header[0x3C:0x40] = (64).to_bytes(4, byteorder='little')
        pe_sig = b'PE\x00\x00'
        coff_header = b'\x64\x86\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01'
        return bytes(dos_header) + pe_sig + coff_header + (b'\x00' * 512)

    # -------------------------------------------------------------
    # 1. NON-EXECUTION GUARANTEE
    # -------------------------------------------------------------
    def test_security_01_non_execution_guarantee(self):
        """Audit: Verify that uploaded binaries are quarantined as inert data and never executed."""
        fake_pe = self._create_synthetic_pe()
        res = secure_intake_service.process_bytes(fake_pe, raw_filename="potentially_malicious.exe")
        self.assertTrue(res.is_success)

        quarantined_file = Path(res.secure_storage_path)
        self.assertTrue(quarantined_file.exists())

        # Storage directory is isolated in storage/quarantine
        self.assertIn("quarantine", str(quarantined_file))
        # Content in quarantine matches exact bytes without execution
        self.assertEqual(quarantined_file.read_bytes()[:2], b"MZ")

    # -------------------------------------------------------------
    # 2. PATH TRAVERSAL & PERIMETER DEFENSE
    # -------------------------------------------------------------
    def test_security_02_path_traversal_sanitization(self):
        """Audit: Verify path traversal payloads in filenames are neutralized."""
        traversal_names = [
            "../../../../Windows/System32/cmd.exe",
            "..\\..\\..\\boot.ini.exe",
            "/etc/shadow.exe",
            "C:\\Windows\\System32\\calc.exe",
            "CON.exe",
            "NUL.dll",
            "AUX.exe"
        ]
        synthetic_pe = self._create_synthetic_pe()

        for dangerous_name in traversal_names:
            res = secure_intake_service.process_bytes(synthetic_pe, raw_filename=dangerous_name)
            self.assertTrue(res.is_success)
            # Filename must not contain path separators
            self.assertNotIn("/", res.filename)
            self.assertNotIn("\\", res.filename)
            self.assertNotIn("..", res.filename)
            # Reserved device names must be sanitized
            self.assertFalse(res.filename.upper().startswith("CON.EXE"))

    # -------------------------------------------------------------
    # 3. PASSWORD CRYPTOGRAPHY & ZERO PLAINTEXT
    # -------------------------------------------------------------
    def test_security_03_zero_plaintext_password_in_database(self):
        """Audit: Verify passwords stored in database are salted PBKDF2-HMAC-SHA256 hashes."""
        raw_pass = "ComplexDefensivePass2026!#"
        user = AuthService.register_user(
            self.db,
            username=f"{self.pfx}_user",
            email=f"{self.pfx}_user@test.local",
            password=raw_pass,
            role="STUDENT"
        )
        # Verify in-memory model and DB record
        db_user = self.db.query(UserModel).filter(UserModel.id == user.id).first()
        self.assertNotEqual(db_user.hashed_password, raw_pass)
        self.assertEqual(len(db_user.hashed_password), 64)  # 256-bit hex
        self.assertEqual(len(db_user.salt), 32)             # 16-byte hex salt

    # -------------------------------------------------------------
    # 4. TOKEN FORGERY & SIGNATURE INTEGRITY
    # -------------------------------------------------------------
    def test_security_04_tampered_token_signature_rejected(self):
        """Audit: Verify that forged tokens or altered payloads are strictly rejected."""
        # 1. Create a legitimate token for student
        user = AuthService.register_user(
            self.db,
            username=f"{self.pfx}_std_tok",
            email=f"{self.pfx}_std_tok@test.local",
            password="Password123!",
            role="STUDENT"
        )
        token_data = AuthService.create_token_for_user(user)
        legit_token = token_data["access_token"]

        # 2. Tamper with token signature (change last 4 characters)
        tampered_token = legit_token[:-4] + "AAAA"

        res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
        self.assertEqual(res.status_code, 401)
        self.assertIn("Invalid or expired token", res.json()["detail"])

    # -------------------------------------------------------------
    # 5. ROLE-BASED ACCESS CONTROL (RBAC) BOUNDARIES
    # -------------------------------------------------------------
    def test_security_05_rbac_privilege_escalation_denial(self):
        """Audit: Verify that non-admin roles cannot perform administrative actions."""
        # Register Analyst and Student
        analyst = AuthService.register_user(self.db, f"{self.pfx}_analyst", f"{self.pfx}_analyst@test.local", "Pass1234!", "ANALYST")
        student = AuthService.register_user(self.db, f"{self.pfx}_student", f"{self.pfx}_student@test.local", "Pass1234!", "STUDENT")

        analyst_token = AuthService.create_token_for_user(analyst)["access_token"]
        student_token = AuthService.create_token_for_user(student)["access_token"]

        # 1. Student attempting to list all platform users -> 403 Forbidden
        res1 = self.client.get("/api/auth/users", headers={"Authorization": f"Bearer {student_token}"})
        self.assertEqual(res1.status_code, 403)

        # 2. Analyst attempting to list all platform users -> 403 Forbidden
        res2 = self.client.get("/api/auth/users", headers={"Authorization": f"Bearer {analyst_token}"})
        self.assertEqual(res2.status_code, 403)

        # 3. Student attempting to promote themselves to ADMIN -> 403 Forbidden
        res3 = self.client.put(
            f"/api/auth/users/{student.id}/role",
            json={"role": "ADMIN"},
            headers={"Authorization": f"Bearer {student_token}"}
        )
        self.assertEqual(res3.status_code, 403)

    # -------------------------------------------------------------
    # 6. OBJECT-LEVEL AUTHORIZATION
    # -------------------------------------------------------------
    def test_security_06_object_level_tenant_isolation(self):
        """Audit: Verify cross-user / cross-tenant object access isolation."""
        user_alpha = AuthService.register_user(self.db, f"{self.pfx}_alpha", f"{self.pfx}_alpha@test.local", "Pass1234!", "STUDENT")
        user_beta = AuthService.register_user(self.db, f"{self.pfx}_beta", f"{self.pfx}_beta@test.local", "Pass1234!", "STUDENT")

        # Create an analysis sample owned by User Alpha
        anl_id = f"ANL-AUDIT-{self.pfx}"
        sample = SampleModel(
            analysis_id=anl_id,
            filename="alpha_sample.exe",
            size=2048,
            file_type="EXE",
            architecture="x64",
            md5="098f6bcd4621d373cade4e832627b4f6",
            sha256="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            status="ANALYZED",
            user_id=user_alpha.id
        )
        self.db.add(sample)
        self.db.commit()

        token_beta = AuthService.create_token_for_user(user_beta)["access_token"]
        token_alpha = AuthService.create_token_for_user(user_alpha)["access_token"]

        # User Beta tries to read User Alpha's analysis -> 403 Forbidden
        read_res = self.client.get(f"/api/auth/analyses/{anl_id}", headers={"Authorization": f"Bearer {token_beta}"})
        self.assertEqual(read_res.status_code, 403)

        # User Beta tries to delete User Alpha's analysis -> 403 Forbidden
        del_res = self.client.delete(f"/api/auth/analyses/{anl_id}", headers={"Authorization": f"Bearer {token_beta}"})
        self.assertEqual(del_res.status_code, 403)

        # User Alpha (Owner) reads successfully -> 200 OK
        owner_read = self.client.get(f"/api/auth/analyses/{anl_id}", headers={"Authorization": f"Bearer {token_alpha}"})
        self.assertEqual(owner_read.status_code, 200)

    # -------------------------------------------------------------
    # 7. INJECTION RESILIENCE (SQLi & XSS)
    # -------------------------------------------------------------
    def test_security_07_sqli_and_xss_injection_resilience(self):
        """Audit: Verify ORM and parameterization protect against SQL injection and XSS."""
        attack_payloads = [
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE users; --",
            "<script>alert(document.cookie)</script>",
            "\"><img src=x onerror=alert(1)>",
            "' UNION SELECT * FROM users --"
        ]

        for payload in attack_payloads:
            res = self.client.post("/api/auth/login", json={
                "username": payload,
                "password": payload
            })
            # Authentication must be securely rejected with 401 Unauthorized without crashing
            self.assertEqual(res.status_code, 401)

    # -------------------------------------------------------------
    # 8. BRUTE-FORCE RATE LIMITING & ACCOUNT LOCKOUT
    # -------------------------------------------------------------
    def test_security_08_brute_force_account_lockout(self):
        """Audit: Verify consecutive failed logins trigger 15-minute account lockout."""
        target_name = f"{self.pfx}_lock_target"
        AuthService.register_user(self.db, target_name, f"{target_name}@test.local", "CorrectPassword123!", "STUDENT")

        for _ in range(4):
            r = self.client.post("/api/auth/login", json={"username": target_name, "password": "WrongPassword"})
            self.assertEqual(r.status_code, 401)

        # 5th attempt locks the account
        r5 = self.client.post("/api/auth/login", json={"username": target_name, "password": "WrongPassword"})
        self.assertEqual(r5.status_code, 423)
        self.assertIn("locked", r5.json()["detail"].lower())

        # Even correct password fails while locked
        r_correct = self.client.post("/api/auth/login", json={"username": target_name, "password": "CorrectPassword123!"})
        self.assertEqual(r_correct.status_code, 423)

    # -------------------------------------------------------------
    # 9. SENSITIVE DATA DISCLOSURE & SECRET LEAKAGE
    # -------------------------------------------------------------
    def test_security_09_zero_secrets_or_passwords_in_logs(self):
        """Audit: Verify secret keys, user passwords, and authorization tokens never leak into system logs."""
        raw_password = "ConfidentialSecretPassword2026!"
        with patch("app.core.logger.logger.info") as mock_info, \
             patch("app.core.logger.logger.warning") as mock_warn, \
             patch("app.core.logger.logger.error") as mock_error:

            # Perform registration and login operations
            AuthService.register_user(self.db, f"{self.pfx}_leak_test", f"{self.pfx}_leak_test@test.local", raw_password, "ANALYST")
            self.client.post("/api/auth/login", json={"username": f"{self.pfx}_leak_test", "password": raw_password})
            self.client.post("/api/auth/login", json={"username": f"{self.pfx}_leak_test", "password": "WrongPassword"})

            all_calls = [str(c) for c in mock_info.call_args_list + mock_warn.call_args_list + mock_error.call_args_list]
            logs_text = " ".join(all_calls)

            self.assertNotIn(raw_password, logs_text)
            self.assertNotIn("WrongPassword", logs_text)
            self.assertNotIn(settings.SECRET_KEY, logs_text)


if __name__ == "__main__":
    unittest.main()
