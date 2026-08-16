"""
Unit tests for Module 02: File Hash Analyzer.

Tests:
1. NIST/RFC standard cryptographic test vectors (Empty data, standard test strings).
2. Small file chunked hashing.
3. Large file chunked streaming hashing (> 64KB chunks) verifying memory safety & hash integrity.
4. Missing file exception handling.
5. Directory / I/O access error handling.
6. Standard dictionary contract verification {"sha256": "...", "sha1": "...", "md5": "..."}.
7. SHA-256 deduplication lookup and persistence check.
"""

import tempfile
import unittest
from pathlib import Path

from app.analyzers.hash_analyzer import (
    FileHashAnalyzer,
    HashResult,
    FileNotFoundErrorCustom,
    FileAccessError,
)
from app.core.storage import AnalysisStore, FileRecord


class TestFileHashAnalyzer(unittest.TestCase):
    """Unit tests for the File Hash Analyzer service."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.records_path = Path(self.temp_dir.name) / "records"
        self.store = AnalysisStore(records_dir=self.records_path)
        self.analyzer = FileHashAnalyzer(store=self.store)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_empty_data_test_vectors(self):
        """Verify empty byte sequence matches standard RFC/NIST cryptographic test vectors."""
        res = self.analyzer.compute_from_bytes(b"")

        expected_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        expected_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        expected_md5 = "d41d8cd98f00b204e9800998ecf8427e"

        self.assertEqual(res.sha256, expected_sha256)
        self.assertEqual(res.sha1, expected_sha1)
        self.assertEqual(res.md5, expected_md5)
        self.assertEqual(res.file_size_bytes, 0)
        self.assertEqual(res.to_dict(), {
            "sha256": expected_sha256,
            "sha1": expected_sha1,
            "md5": expected_md5
        })

    def test_standard_known_string_test_vector(self):
        """Verify standard 'The quick brown fox jumps over the lazy dog' test vector."""
        sample_text = b"The quick brown fox jumps over the lazy dog"
        res = self.analyzer.compute_from_bytes(sample_text)

        expected_sha256 = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        expected_sha1 = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        expected_md5 = "9e107d9d372bb6826bd81d3542a419d6"

        self.assertEqual(res.sha256, expected_sha256)
        self.assertEqual(res.sha1, expected_sha1)
        self.assertEqual(res.md5, expected_md5)
        self.assertEqual(res.file_size_bytes, len(sample_text))

    def test_small_file_streaming(self):
        """Verify chunked streaming on a small file matches in-memory hash."""
        small_data = b"ETHIO-AI Defender Static Malware Analysis Platform"
        sample_file = Path(self.temp_dir.name) / "small_sample.bin"
        sample_file.write_bytes(small_data)

        file_res = self.analyzer.compute_from_file(sample_file, chunk_size=16)
        bytes_res = self.analyzer.compute_from_bytes(small_data)

        self.assertEqual(file_res.sha256, bytes_res.sha256)
        self.assertEqual(file_res.sha1, bytes_res.sha1)
        self.assertEqual(file_res.md5, bytes_res.md5)
        self.assertEqual(file_res.file_size_bytes, len(small_data))

    def test_large_file_streaming(self):
        """Verify chunked streaming on a large file (200 KB) with small chunk size (16 KB)."""
        # Create a 200 KB synthetic repetitive payload
        chunk = b"SecurityResearchDefensiveTriageEthiopia2026!" * 100
        large_data = chunk * 50  # ~220 KB
        large_file = Path(self.temp_dir.name) / "large_sample.bin"
        large_file.write_bytes(large_data)

        # Stream with small 16KB chunk size
        file_res = self.analyzer.compute_from_file(large_file, chunk_size=16384)
        bytes_res = self.analyzer.compute_from_bytes(large_data)

        self.assertEqual(file_res.sha256, bytes_res.sha256)
        self.assertEqual(file_res.sha1, bytes_res.sha1)
        self.assertEqual(file_res.md5, bytes_res.md5)
        self.assertEqual(file_res.file_size_bytes, len(large_data))

    def test_missing_file_raises_custom_error(self):
        """Verify that attempting to hash a non-existent file raises FileNotFoundErrorCustom."""
        non_existent = Path(self.temp_dir.name) / "non_existent_binary.exe"
        with self.assertRaises(FileNotFoundErrorCustom):
            self.analyzer.compute_from_file(non_existent)

    def test_directory_path_raises_file_access_error(self):
        """Verify that passing a directory path instead of a file raises FileAccessError."""
        target_dir = Path(self.temp_dir.name)
        with self.assertRaises(FileAccessError):
            self.analyzer.compute_from_file(target_dir)

    def test_sha256_deduplication_lookup(self):
        """Verify determining whether a SHA-256 has already been analyzed."""
        test_sha256 = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"

        # Initially, hash is unknown
        self.assertFalse(self.analyzer.is_sha256_analyzed(test_sha256))
        self.assertIsNone(self.analyzer.get_sample_by_sha256(test_sha256))

        # Register a sample record in the store
        record = FileRecord(
            analysis_id="ANL-000100",
            filename="registered_sample.exe",
            original_filename="original.exe",
            size=1024,
            sha256=test_sha256,
            md5="9e107d9d372bb6826bd81d3542a419d6",
            sha1="2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            status="READY",
            uploaded_at="2026-08-16T22:00:00Z",
            file_type="PE Executable (.exe)",
            quarantined_path="/quarantine/sample.bin",
        )
        self.store.save_record(record)

        # Now, hash must be identified as previously analyzed
        self.assertTrue(self.analyzer.is_sha256_analyzed(test_sha256))
        found_rec = self.analyzer.get_sample_by_sha256(test_sha256)
        self.assertIsNotNone(found_rec)
        self.assertEqual(found_rec.analysis_id, "ANL-000100")
        self.assertEqual(found_rec.filename, "registered_sample.exe")


if __name__ == "__main__":
    unittest.main()
