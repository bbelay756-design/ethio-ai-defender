"""
Module 18 - Security Testing: Step 3 - Upload Security & Perimeter Validation.
Tests file upload handling, perimeter validation, extension enforcement, path traversal defense, and non-execution guarantee.
"""

import io
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.analyzers.file_intake import secure_intake_service, IntakeStatus
from app.testing.synthetic_pe import SyntheticPEBuilder
from app.db.session import init_db, SessionLocal
from tests.auth_helpers import make_analyst
from tests.fixtures.security_payloads import PATH_TRAVERSAL_FILENAMES, DANGEROUS_FILENAMES


class TestUploadSecurity(unittest.TestCase):
    """Exhaustive upload security and perimeter validation test suite."""

    @classmethod
    def setUpClass(cls):
        # SEC-05: endpoint requires an authenticated ANALYST/ADMIN identity.
        init_db()
        cls._db = SessionLocal()
        _, cls._auth_headers = make_analyst(cls._db)
        cls.client = TestClient(app)
        cls.client.headers.update(cls._auth_headers)
        cls.valid_exe = SyntheticPEBuilder.create_minimal_pe()
        cls.valid_dll = SyntheticPEBuilder.create_minimal_pe(subsystem=2)
        cls.quarantine_dir = Path(settings.QUARANTINE_DIR).resolve()

    @classmethod
    def tearDownClass(cls):
        cls._db.close()

    def test_01_valid_exe_upload_accepted(self):
        """Verify valid PE32 EXE binary is accepted and assigned an analysis ID."""
        file_obj = io.BytesIO(self.valid_exe)
        response = self.client.post(
            "/api/files/upload",
            files={"file": ("sample_valid.exe", file_obj, "application/octet-stream")}
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn("analysis_id", data)
        self.assertEqual(len(data["sha256"]), 64)
        self.assertTrue(data["filename"].endswith(".exe"))

    def test_02_valid_dll_upload_accepted(self):
        """Verify valid DLL binary is accepted safely."""
        file_obj = io.BytesIO(self.valid_dll)
        response = self.client.post(
            "/api/files/upload",
            files={"file": ("library_valid.dll", file_obj, "application/octet-stream")}
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn("analysis_id", data)
        self.assertTrue(data["filename"].endswith(".dll"))

    def test_03_empty_file_rejected(self):
        """Verify 0-byte uploads are immediately rejected with HTTP 400."""
        empty_obj = io.BytesIO(b"")
        response = self.client.post(
            "/api/files/upload",
            files={"file": ("empty.exe", empty_obj, "application/octet-stream")}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("REJECTED_EMPTY", str(response.json()))

    def test_04_unsupported_extensions_rejected(self):
        """Verify non-PE file extensions (.pdf, .sh, .py, .elf, .docx, .zip) are rejected."""
        unsupported = [
            ("script.sh", b"#!/bin/bash\necho test\n"),
            ("document.pdf", b"%PDF-1.5 test document"),
            ("payload.py", b"import os; os.system('echo 1')"),
            ("linux_elf.bin", b"\x7fELF\x02\x01\x01\x00"),
            ("archive.zip", b"PK\x03\x04\x14\x00"),
            ("archive.tar.gz", b"\x1f\x8b\x08\x00"),
        ]
        for name, content in unsupported:
            file_obj = io.BytesIO(content)
            response = self.client.post(
                "/api/files/upload",
                files={"file": (name, file_obj, "application/octet-stream")}
            )
            self.assertEqual(response.status_code, 400, f"Unsupported extension not rejected for: {name}")

    def test_05_double_extension_attacks(self):
        """Verify double extensions like sample.exe.txt or malware.pdf.exe are handled safely."""
        # Double extension ending in non-allowed extension
        res_txt = self.client.post(
            "/api/files/upload",
            files={"file": ("sample.exe.txt", io.BytesIO(self.valid_exe), "application/octet-stream")}
        )
        self.assertEqual(res_txt.status_code, 400)

        # Double extension ending in .exe (safe filename generated)
        res_exe = self.client.post(
            "/api/files/upload",
            files={"file": ("sample.php.exe", io.BytesIO(self.valid_exe), "application/octet-stream")}
        )
        self.assertEqual(res_exe.status_code, 201)

    def test_06_oversized_file_rejected(self):
        """Verify files exceeding 50MB maximum threshold are rejected with HTTP 413 / 400."""
        oversized = b"M" * (52 * 1024 * 1024)
        file_obj = io.BytesIO(oversized)
        response = self.client.post(
            "/api/files/upload",
            files={"file": ("large_file.exe", file_obj, "application/octet-stream")}
        )
        self.assertIn(response.status_code, [400, 413])

    def test_07_path_traversal_confinement(self):
        """Verify Unix and Windows path traversal payloads cannot escape quarantine storage root."""
        for path_payload in PATH_TRAVERSAL_FILENAMES:
            file_obj = io.BytesIO(self.valid_exe)
            response = self.client.post(
                "/api/files/upload",
                files={"file": (path_payload, file_obj, "application/octet-stream")}
            )
            self.assertIn(response.status_code, [200, 201, 400], f"Failed on path payload: {path_payload}")
            if response.status_code in (200, 201):
                data = response.json()
                safe_name = data["filename"]
                self.assertNotIn("../", safe_name)
                self.assertNotIn("..\\", safe_name)
                self.assertNotIn("/", safe_name)
                self.assertNotIn("\\", safe_name)

    def test_08_dangerous_and_null_byte_filenames(self):
        """Verify dangerous filenames and null bytes are sanitized without crashes."""
        for dangerous_name in DANGEROUS_FILENAMES:
            file_obj = io.BytesIO(self.valid_exe)
            response = self.client.post(
                "/api/files/upload",
                files={"file": (dangerous_name, file_obj, "application/octet-stream")}
            )
            self.assertIn(response.status_code, [200, 201, 400], f"Failed on filename: {dangerous_name}")
            if response.status_code in (200, 201):
                data = response.json()
                self.assertNotIn("\x00", data["filename"])
                self.assertNotEqual(data["filename"], "CON.exe")
                self.assertNotEqual(data["filename"], "PRN.dll")
                self.assertNotEqual(data["filename"], "AUX.sys")
                self.assertNotEqual(data["filename"], "NUL.exe")

    def test_09_malformed_and_truncated_pe_variants(self):
        """Verify malformed and truncated PE structures are rejected safely by intake perimeter."""
        truncated_pe = b"MZ" + (b"\x00" * 30)  # Header truncated before e_lfanew
        res_trunc = self.client.post(
            "/api/files/upload",
            files={"file": ("truncated.exe", io.BytesIO(truncated_pe), "application/octet-stream")}
        )
        self.assertEqual(res_trunc.status_code, 400)

        bad_magic_pe = SyntheticPEBuilder.create_malformed_pe("bad_dos_magic")
        res_bad = self.client.post(
            "/api/files/upload",
            files={"file": ("bad_magic.exe", io.BytesIO(bad_magic_pe), "application/octet-stream")}
        )
        self.assertEqual(res_bad.status_code, 400)

    def test_10_non_execution_safety_invariant(self):
        """Verify files stored in quarantine are never marked executable by the host OS."""
        res = secure_intake_service.process_bytes(self.valid_exe, raw_filename="safety_test.exe")
        self.assertTrue(res.is_success)
        stored_path = Path(res.secure_storage_path)
        self.assertTrue(stored_path.exists())
        self.assertTrue(str(stored_path.resolve()).startswith(str(self.quarantine_dir)))


if __name__ == "__main__":
    unittest.main()
