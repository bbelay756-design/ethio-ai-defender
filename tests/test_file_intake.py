"""
Unit tests for Module 01: Secure File Intake.

Tests:
1. Valid PE byte headers acceptance.
2. Path traversal attack sanitization.
3. Windows reserved names handling.
4. Empty file rejection.
5. Oversized payload rejection.
6. Quarantine storage and hash accuracy.
7. Corrupt/non-PE rejection when enforcement is active.
"""

import struct
import tempfile
import hashlib
import unittest
from pathlib import Path

from app.analyzers.file_intake import SecureFileIntake, IntakeStatus
from app.utils.sanitizer import sanitize_filename


def create_minimal_pe_binary() -> bytes:
    """
    Constructs a minimal, harmless byte buffer representing a valid DOS and PE header.
    Contains:
    - DOS 'MZ' signature at byte 0
    - e_lfanew pointer at offset 0x3C pointing to offset 0x80 (128)
    - PE signature 'PE\\0\\0' at offset 0x80
    Total size: 256 bytes.
    """
    buffer = bytearray(256)
    # DOS Magic 'MZ'
    buffer[0:2] = b"MZ"
    # Offset 0x3C (60) contains pointer to PE signature (offset 0x80 / 128)
    struct.pack_into("<I", buffer, 0x3C, 0x80)
    # PE signature at offset 0x80 (128)
    buffer[0x80:0x84] = b"PE\x00\x00"
    return bytes(buffer)


class TestSecureFileIntake(unittest.TestCase):
    """Unit tests for the Secure File Intake module."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.quarantine_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sanitize_filename_prevents_path_traversal(self):
        """Verify that path traversal attempts are stripped completely."""
        malicious_inputs = [
            ("../../etc/shadow", "shadow"),
            ("..\\..\\Windows\\System32\\calc.exe", "calc.exe"),
            ("C:/evil/malware.exe", "malware.exe"),
            ("../../../run.dll", "run.dll"),
            ("..//..//test.exe", "test.exe"),
        ]

        for raw, expected in malicious_inputs:
            sanitized = sanitize_filename(raw)
            self.assertNotIn("/", sanitized)
            self.assertNotIn("\\", sanitized)
            self.assertNotIn("..", sanitized)
            self.assertEqual(sanitized, expected)

    def test_sanitize_filename_windows_reserved(self):
        """Verify that Windows reserved device names are prefixed safely."""
        reserved = ["CON.exe", "aux.dll", "prn.bin", "NUL.exe", "com1.exe"]
        for name in reserved:
            sanitized = sanitize_filename(name)
            self.assertTrue(sanitized.startswith("safe_"))

    def test_intake_accepts_valid_pe(self):
        """Test that a valid PE header structure is accepted and quarantined."""
        intake = SecureFileIntake(quarantine_dir=self.quarantine_path, enforce_pe_check=True)
        sample_data = create_minimal_pe_binary()

        result = intake.process_bytes(sample_data, raw_filename="sample_payload.exe")

        self.assertEqual(result.status, IntakeStatus.READY)
        self.assertTrue(result.is_success)
        self.assertTrue(result.is_pe_candidate)
        self.assertEqual(result.size, 256)
        self.assertIsNotNone(result.secure_storage_path)
        self.assertTrue(result.secure_storage_path.exists())

        expected_sha256 = hashlib.sha256(sample_data).hexdigest()
        self.assertEqual(result.sha256, expected_sha256)

    def test_intake_rejects_empty_file(self):
        """Test that 0-byte submissions are safely rejected."""
        intake = SecureFileIntake(quarantine_dir=self.quarantine_path)
        result = intake.process_bytes(b"", raw_filename="empty.exe")

        self.assertEqual(result.status, IntakeStatus.REJECTED_EMPTY)
        self.assertFalse(result.is_success)
        self.assertEqual(result.size, 0)

    def test_intake_rejects_oversized_file(self):
        """Test that files exceeding configured limits are rejected."""
        intake = SecureFileIntake(max_file_size=100, quarantine_dir=self.quarantine_path)
        sample_data = create_minimal_pe_binary()  # 256 bytes

        result = intake.process_bytes(sample_data, raw_filename="toolarge.exe")

        self.assertEqual(result.status, IntakeStatus.REJECTED_OVERSIZED)
        self.assertFalse(result.is_success)
        self.assertEqual(result.size, 256)

    def test_intake_rejects_invalid_pe_header(self):
        """Test that non-PE files with .exe extension are rejected when PE check is enforced."""
        intake = SecureFileIntake(quarantine_dir=self.quarantine_path, enforce_pe_check=True)
        plain_text = b"This is a text file with an .exe extension, not a Windows PE binary."

        result = intake.process_bytes(plain_text, raw_filename="fake_binary.exe")

        self.assertEqual(result.status, IntakeStatus.REJECTED_INVALID_PE)
        self.assertFalse(result.is_success)
        self.assertFalse(result.is_pe_candidate)


if __name__ == "__main__":
    unittest.main()

