"""
Module 01: Secure File Intake and Validation - API Integration Tests

Tests:
1. Upload valid .exe binary -> HTTP 201 Created & Valid JSON response.
2. Upload valid .dll binary -> HTTP 201 Created.
3. Reject invalid file extensions (.txt, .pdf, .sh, .py) -> HTTP 400 Bad Request.
4. Reject empty file (0 bytes) -> HTTP 400 Bad Request.
5. Reject oversized file -> HTTP 413 Payload Too Large.
6. Path traversal filename attempts (../../evil.exe) -> sanitized safely.
7. Dangerous filenames (null bytes, Windows reserved CON.exe) -> safely handled.
8. Duplicate file uploads -> assigned unique analysis IDs.
9. GET /api/files/{analysis_id} for existing sample -> HTTP 200 OK.
10. GET /api/files/{analysis_id} for non-existent sample -> HTTP 404 Not Found.
11. Malformed input (text file masquerading as .exe) -> HTTP 400 Bad Request.
"""

import struct
import io
import hashlib
import unittest
import warnings

# Suppress Starlette internal deprecation warnings during testing
warnings.filterwarnings("ignore", category=DeprecationWarning)

from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.db.session import init_db, SessionLocal
from tests.auth_helpers import make_analyst


def generate_synthetic_pe(size: int = 512) -> bytes:
    """
    Constructs a harmless synthetic Windows PE binary in memory.
    - DOS 'MZ' header at offset 0
    - e_lfanew pointer at offset 0x3C pointing to offset 0x80 (128)
    - PE signature 'PE\\0\\0' at offset 0x80
    Total size: `size` bytes.
    """
    buffer = bytearray(max(size, 256))
    buffer[0:2] = b"MZ"
    struct.pack_into("<I", buffer, 0x3C, 0x80)
    buffer[0x80:0x84] = b"PE\x00\x00"
    return bytes(buffer)


class TestFileIntakeAPI(unittest.TestCase):
    """Integration test suite for the Secure File Intake endpoints."""

    @classmethod
    def setUpClass(cls):
        # SEC-05: uploads now require an authenticated ANALYST/ADMIN identity.
        init_db()
        cls._db = SessionLocal()
        _, cls._auth_headers = make_analyst(cls._db)

    @classmethod
    def tearDownClass(cls):
        cls._db.close()

    def setUp(self):
        self.client = TestClient(app)
        self.client.headers.update(self._auth_headers)

    def test_upload_valid_exe(self):
        """Test uploading a valid synthetic .exe PE file."""
        pe_bytes = generate_synthetic_pe(1024)
        expected_sha256 = hashlib.sha256(pe_bytes).hexdigest()
        expected_md5 = hashlib.md5(pe_bytes).hexdigest()

        response = self.client.post(
            "/api/files/upload",
            files={"file": ("ethio_sample.exe", io.BytesIO(pe_bytes), "application/octet-stream")}
        )

        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertTrue(data["analysis_id"].startswith("ANL-"))
        self.assertEqual(data["filename"], "ethio_sample.exe")
        self.assertEqual(data["size"], 1024)
        self.assertEqual(data["sha256"], expected_sha256)
        self.assertEqual(data["md5"], expected_md5)
        self.assertEqual(data["status"], "READY")

    def test_upload_valid_dll(self):
        """Test uploading a valid synthetic .dll PE file."""
        pe_bytes = generate_synthetic_pe(512)
        response = self.client.post(
            "/api/files/upload",
            files={"file": ("module_payload.dll", io.BytesIO(pe_bytes), "application/octet-stream")}
        )

        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertTrue(data["analysis_id"].startswith("ANL-"))
        self.assertEqual(data["filename"], "module_payload.dll")
        self.assertEqual(data["status"], "READY")

    def test_reject_invalid_extension(self):
        """Test that non-PE extensions (.txt, .sh, .pdf) are rejected with 400 Bad Request."""
        invalid_extensions = ["script.sh", "notes.txt", "document.pdf", "script.py"]
        pe_bytes = generate_synthetic_pe(256)

        for filename in invalid_extensions:
            response = self.client.post(
                "/api/files/upload",
                files={"file": (filename, io.BytesIO(pe_bytes), "application/octet-stream")}
            )
            self.assertEqual(response.status_code, 400)
            self.assertIn("Unsupported file extension", str(response.json()))

    def test_reject_empty_file(self):
        """Test that 0-byte uploads are rejected with 400 Bad Request."""
        response = self.client.post(
            "/api/files/upload",
            files={"file": ("empty_sample.exe", io.BytesIO(b""), "application/octet-stream")}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("empty", str(response.json()).lower())

    def test_reject_oversized_file(self):
        """Test that uploads exceeding the max file size limit are rejected with 413."""
        # Temporarily lower the size threshold for testing
        original_limit = settings.MAX_FILE_SIZE_BYTES
        try:
            settings.MAX_FILE_SIZE_BYTES = 500  # 500 bytes
            from app.analyzers.file_intake import secure_intake_service
            secure_intake_service.max_file_size = 500

            large_pe = generate_synthetic_pe(1024)  # 1024 bytes > 500
            response = self.client.post(
                "/api/files/upload",
                files={"file": ("large_sample.exe", io.BytesIO(large_pe), "application/octet-stream")}
            )
            self.assertEqual(response.status_code, 413)
        finally:
            settings.MAX_FILE_SIZE_BYTES = original_limit
            from app.analyzers.file_intake import secure_intake_service
            secure_intake_service.max_file_size = original_limit

    def test_path_traversal_filename_sanitization(self):
        """Test that path traversal attempts in filename are stripped safely."""
        pe_bytes = generate_synthetic_pe(256)
        traversal_names = [
            ("../../etc/shadow.exe", "shadow.exe"),
            ("..\\..\\Windows\\System32\\calc.exe", "calc.exe"),
            ("C:/test/payload.dll", "payload.dll"),
        ]

        for dirty_name, expected_clean in traversal_names:
            response = self.client.post(
                "/api/files/upload",
                files={"file": (dirty_name, io.BytesIO(pe_bytes), "application/octet-stream")}
            )
            self.assertEqual(response.status_code, 201)
            data = response.json()
            self.assertEqual(data["filename"], expected_clean)

    def test_dangerous_reserved_filename_handling(self):
        """Test that Windows reserved device names (CON.exe, AUX.dll) are safely prefixed."""
        pe_bytes = generate_synthetic_pe(256)
        response = self.client.post(
            "/api/files/upload",
            files={"file": ("CON.exe", io.BytesIO(pe_bytes), "application/octet-stream")}
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["filename"], "safe_CON.exe")

    def test_duplicate_file_upload_unique_analysis_ids(self):
        """Test that uploading the same sample twice produces unique analysis IDs."""
        pe_bytes = generate_synthetic_pe(256)
        res1 = self.client.post(
            "/api/files/upload",
            files={"file": ("dup.exe", io.BytesIO(pe_bytes), "application/octet-stream")}
        )
        res2 = self.client.post(
            "/api/files/upload",
            files={"file": ("dup.exe", io.BytesIO(pe_bytes), "application/octet-stream")}
        )

        self.assertEqual(res1.status_code, 201)
        self.assertEqual(res2.status_code, 201)
        id1 = res1.json()["analysis_id"]
        id2 = res2.json()["analysis_id"]
        self.assertNotEqual(id1, id2)

    def test_get_file_record_success(self):
        """Test retrieving an existing analysis record by analysis_id."""
        pe_bytes = generate_synthetic_pe(512)
        upload_res = self.client.post(
            "/api/files/upload",
            files={"file": ("lookup_test.exe", io.BytesIO(pe_bytes), "application/octet-stream")}
        )
        analysis_id = upload_res.json()["analysis_id"]

        get_res = self.client.get(f"/api/files/{analysis_id}")
        self.assertEqual(get_res.status_code, 200)
        data = get_res.json()
        self.assertEqual(data["analysis_id"], analysis_id)
        self.assertEqual(data["filename"], "lookup_test.exe")
        self.assertEqual(data["status"], "READY")

    def test_get_file_record_not_found(self):
        """Test that requesting a non-existent analysis_id returns 404."""
        response = self.client.get("/api/files/ANL-999999")
        self.assertEqual(response.status_code, 404)

    def test_reject_malformed_non_pe_executable(self):
        """Test that a plain text file named sample.exe with no PE header is rejected with 400."""
        fake_pe = b"This is a fake script pretending to be an EXE binary."
        response = self.client.post(
            "/api/files/upload",
            files={"file": ("fake_sample.exe", io.BytesIO(fake_pe), "application/octet-stream")}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("not a valid Windows PE", str(response.json()))


if __name__ == "__main__":
    unittest.main()
