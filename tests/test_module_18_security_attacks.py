"""
Module 18: Comprehensive Security Attack & Robustness Verification Suite.

Tests:
1. Path Traversal & Directory Traversal
2. Oversized Uploads
3. Malformed PE Binaries
4. Invalid & Corrupt Headers
5. Duplicate File Processing
6. Unauthorized API Access & RBAC Enforcement
7. Invalid Authentication & Token Forgery
8. SQL Injection Attacks (Login, Register, Queries)
9. Cross-Site Scripting (XSS) in Uploads & Parameters
10. Rate Limiting & Account Lockout
11. Dangerous Filenames (Null bytes, reserved names, shell characters)
12. Malformed API Requests & Invalid JSON
"""

import io
import unittest
import uuid
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import init_db, SessionLocal
from app.auth.service import AuthService
from app.testing.synthetic_pe import SyntheticPEBuilder
from app.testing.attack_payloads import (
    PATH_TRAVERSAL_FILENAMES,
    DANGEROUS_FILENAMES,
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    INVALID_AUTH_HEADERS,
    MALFORMED_JSON_PAYLOADS,
)


class TestModule18SecurityAttackVectors(unittest.TestCase):
    """Exhaustive security attack validation suite."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        uid = str(uuid.uuid4())[:8]
        cls.admin_username = f"admin_atk_{uid}"
        cls.analyst_username = f"analyst_atk_{uid}"
        cls.student_username = f"viewer_atk_{uid}"

        cls.admin = AuthService.register_user(
            cls.db, cls.admin_username, f"{cls.admin_username}@soc.et", "AdminSecretPass2026!", role="ADMIN"
        )
        cls.analyst = AuthService.register_user(
            cls.db, cls.analyst_username, f"{cls.analyst_username}@soc.et", "AnalystSecretPass2026!", role="ANALYST"
        )
        cls.student = AuthService.register_user(
            cls.db, cls.student_username, f"{cls.student_username}@soc.et", "ViewerSecretPass2026!", role="VIEWER"
        )

        cls.admin_token = AuthService.create_token_for_user(cls.admin)["access_token"]
        cls.analyst_token = AuthService.create_token_for_user(cls.analyst)["access_token"]
        cls.student_token = AuthService.create_token_for_user(cls.student)["access_token"]

        cls.valid_pe = SyntheticPEBuilder.create_minimal_pe()

        # SEC-05: upload endpoints require an authenticated ANALYST identity.
        cls.auth_headers = {"Authorization": f"Bearer {cls.analyst_token}"}

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    # 1. Path Traversal & Directory Traversal Attacks
    def test_01_path_traversal_attacks(self):
        """Ensure all directory traversal payloads are neutralized without escaping the quarantine root."""
        for path_payload in PATH_TRAVERSAL_FILENAMES:
            file_obj = io.BytesIO(self.valid_pe)
            response = self.client.post(
                "/api/files/upload",
                files={"file": (path_payload, file_obj, "application/octet-stream")},
                headers=self.auth_headers
            )
            self.assertIn(response.status_code, [200, 201, 400], f"Failed on path payload: {path_payload}")
            if response.status_code in (200, 201):
                data = response.json()
                # Stored safe filename must never contain ../ or ..\
                self.assertNotIn("../", data["filename"])
                self.assertNotIn("..\\", data["filename"])
                self.assertNotIn("/", data["filename"])
                self.assertNotIn("\\", data["filename"])

    # 2. Oversized Upload Attack
    def test_02_oversized_upload_attack(self):
        """Ensure uploads exceeding the maximum configured threshold (50MB) are immediately rejected."""
        # 55MB mock payload
        oversized_bytes = b"M" * (55 * 1024 * 1024)
        file_obj = io.BytesIO(oversized_bytes)
        response = self.client.post(
            "/api/files/upload",
            files={"file": ("oversized_payload.exe", file_obj, "application/octet-stream")},
            headers=self.auth_headers
        )
        self.assertIn(response.status_code, [400, 413])

    # 3. Malformed PE Binaries
    def test_03_malformed_pe_variants(self):
        """Ensure malformed binary structures are handled safely without crashing the service."""
        malformed_variants = [
            "bad_dos_magic",
            "truncated_dos",
            "invalid_pe_offset",
            "bad_pe_magic",
            "zero_sections",
            "excessive_sections",
            "corrupt_optional_magic",
            "all_zero_bytes",
            "random_garbage",
        ]
        for variant in malformed_variants:
            mal_bytes = SyntheticPEBuilder.create_malformed_pe(variant)
            file_obj = io.BytesIO(mal_bytes)
            response = self.client.post(
                "/api/files/upload",
                files={"file": (f"mal_{variant}.exe", file_obj, "application/octet-stream")},
                headers=self.auth_headers
            )
            # Must be handled without unhandled 500 server crash
            self.assertIn(response.status_code, [200, 201, 400, 422], f"Variant '{variant}' returned unexpected status")

    # 4. Invalid & Corrupt Headers
    def test_04_invalid_authentication_headers(self):
        """Ensure invalid, forged, or corrupt Authorization headers return 401 Unauthorized."""
        for auth_header in INVALID_AUTH_HEADERS:
            response = self.client.get("/api/auth/me", headers=auth_header)
            self.assertEqual(response.status_code, 401, f"Failed on header: {auth_header}")

    # 5. Duplicate File Processing
    def test_05_duplicate_file_processing(self):
        """Ensure duplicate uploads calculate identical SHA-256 hashes without database corruption."""
        file_obj1 = io.BytesIO(self.valid_pe)
        res1 = self.client.post(
            "/api/files/upload",
            files={"file": ("dup_sample.exe", file_obj1, "application/octet-stream")},
            headers=self.auth_headers
        )
        self.assertIn(res1.status_code, [200, 201])
        data1 = res1.json()

        file_obj2 = io.BytesIO(self.valid_pe)
        res2 = self.client.post(
            "/api/files/upload",
            files={"file": ("dup_sample.exe", file_obj2, "application/octet-stream")},
            headers=self.auth_headers
        )
        self.assertIn(res2.status_code, [200, 201])
        data2 = res2.json()

        self.assertEqual(data1["sha256"], data2["sha256"])

    # 6. Unauthorized API Access & RBAC Enforcement
    def test_06_unauthorized_api_access(self):
        """Ensure role boundaries are strictly enforced across sensitive admin routes."""
        # Student cannot access /api/auth/users
        res_std = self.client.get(
            "/api/auth/users",
            headers={"Authorization": f"Bearer {self.student_token}"}
        )
        self.assertEqual(res_std.status_code, 403)

        # Analyst cannot access /api/audit/logs
        res_anl = self.client.get(
            "/api/audit/logs",
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(res_anl.status_code, 403)

        # Admin can access /api/audit/logs
        res_adm = self.client.get(
            "/api/audit/logs",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_adm.status_code, 200)

    # 7. Invalid Authentication & Token Forgery
    def test_07_invalid_credentials_and_forgery(self):
        """Test rejection of incorrect passwords and forged signatures."""
        res = self.client.post(
            "/api/auth/login",
            json={"username": self.student_username, "password": "WrongPassword123!"}
        )
        self.assertEqual(res.status_code, 401)

        # Forged signature token
        fake_token = self.student_token[:-10] + "0123456789"
        res_forged = self.client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {fake_token}"}
        )
        self.assertEqual(res_forged.status_code, 401)

    # 8. SQL Injection Attacks
    def test_08_sql_injection_attacks(self):
        """Verify parameterized queries prevent all SQL injection login and search bypasses."""
        for sqli in SQL_INJECTION_PAYLOADS:
            # Login attempt with SQL injection
            res = self.client.post(
                "/api/auth/login",
                json={"username": sqli, "password": "arbitrary_password"}
            )
            self.assertEqual(res.status_code, 401, f"SQLi payload bypassed login: {sqli}")

            # Registration attempt with SQL injection username
            res_reg = self.client.post(
                "/api/auth/register",
                json={"username": sqli, "email": "sqli@soc.et", "password": "Password2026!"}
            )
            # Parameterized ORM handles injection safely without SQL error
            self.assertIn(res_reg.status_code, [200, 201, 400, 422])

    # 9. Cross-Site Scripting (XSS) Attacks
    def test_09_xss_attacks_sanitization(self):
        """Verify XSS vectors in filenames and usernames are stripped or escaped safely."""
        for xss in XSS_PAYLOADS:
            file_obj = io.BytesIO(self.valid_pe)
            filename = f"sample_{xss}.exe"
            response = self.client.post(
                "/api/files/upload",
                files={"file": (filename, file_obj, "application/octet-stream")},
                headers=self.auth_headers
            )
            self.assertIn(response.status_code, [200, 201, 400])
            if response.status_code in (200, 201):
                data = response.json()
                # Stored safe filename must never contain raw HTML tags or executable script tags
                self.assertNotIn("<script>", data["filename"])
                self.assertNotIn("<", data["filename"])
                self.assertNotIn(">", data["filename"])

    # 10. Rate Limiting & Account Lockout
    def test_10_rate_limiting_and_account_lockout(self):
        """Verify 5 consecutive failed logins trigger a 15-minute account lockout."""
        victim_user = f"rate_victim_{uuid.uuid4().hex[:6]}"
        AuthService.register_user(
            self.db, victim_user, f"{victim_user}@soc.et", "ValidPassword2026!", role="VIEWER"
        )

        for i in range(5):
            res = self.client.post(
                "/api/auth/login",
                json={"username": victim_user, "password": "WrongPassword!"}
            )
            self.assertIn(res.status_code, [401, 423, 429])

        # 6th attempt must be 423 or 429 (Account Locked)
        locked_res = self.client.post(
            "/api/auth/login",
            json={"username": victim_user, "password": "ValidPassword2026!"}
        )
        self.assertIn(locked_res.status_code, [423, 429])
        self.assertIn("locked", locked_res.json()["detail"].lower())

    # 11. Dangerous Filenames & Null Byte Attacks
    def test_11_dangerous_filenames_sanitization(self):
        """Verify null bytes, control characters, and reserved Windows device names are sanitized."""
        for dangerous_name in DANGEROUS_FILENAMES:
            file_obj = io.BytesIO(self.valid_pe)
            response = self.client.post(
                "/api/files/upload",
                files={"file": (dangerous_name, file_obj, "application/octet-stream")},
                headers=self.auth_headers
            )
            self.assertIn(response.status_code, [200, 201, 400], f"Failed on filename: {dangerous_name}")
            if response.status_code in (200, 201):
                data = response.json()
                # Null bytes must be stripped
                self.assertNotIn("\x00", data["filename"])
                # Reserved devices must be safely prefixed or sanitized
                self.assertNotEqual(data["filename"], "CON.exe")
                self.assertNotEqual(data["filename"], "PRN.dll")
                self.assertNotEqual(data["filename"], "AUX.sys")
                self.assertNotEqual(data["filename"], "NUL.exe")

    # 12. Malformed API Requests & Corrupt JSON
    def test_12_malformed_api_requests(self):
        """Ensure invalid or malformed JSON payloads return 422 Unprocessable Entity gracefully."""
        for mal_json in MALFORMED_JSON_PAYLOADS:
            response = self.client.post(
                "/api/auth/login",
                content=mal_json,
                headers={"Content-Type": "application/json"}
            )
            self.assertIn(response.status_code, [400, 422])


if __name__ == "__main__":
    unittest.main()
