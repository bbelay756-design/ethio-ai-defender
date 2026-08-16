"""
Unit tests for Module 05: Entropy Analyzer.

Tests:
1. Mathematical precision on exact test vectors (0.0, 1.0, 2.0, 3.0, 8.0).
2. All-zero data (Entropy = 0.0, Classification = 'LOW').
3. Repeated byte sequences (Entropy = 0.0).
4. Uniformly distributed data (Entropy = 8.0, Classification = 'VERY_HIGH').
5. Boundary values (empty data, 1-byte, 256 unique bytes).
6. Classification thresholds (LOW, NORMAL, HIGH, VERY_HIGH).
7. PE binary whole-file and per-section entropy analysis.
8. File-based static entropy analysis on disk and missing file handling.
9. Structured JSON output contract formatting.
"""

import os
import tempfile
import unittest
from pathlib import Path

from app.analyzers.entropy_analyzer import (
    EntropyAnalyzer,
    calculate_shannon_entropy,
    classify_entropy_score,
    EntropyAnalysisResult,
    SectionEntropyResult,
)
from tests.test_section_analyzer import build_custom_sections_pe


class TestEntropyAnalyzer(unittest.TestCase):
    """Unit tests for the Shannon Entropy Analyzer."""

    def setUp(self):
        self.analyzer = EntropyAnalyzer()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Mathematical Accuracy Tests
    def test_all_zeros_entropy(self):
        """Verify that all-zero data has exactly 0.0 entropy."""
        data = b"\x00" * 2048
        entropy = calculate_shannon_entropy(data)
        self.assertAlmostEqual(entropy, 0.0, places=6)
        self.assertEqual(classify_entropy_score(entropy), "LOW")

    def test_repeated_single_character(self):
        """Verify that repeated single non-zero characters have 0.0 entropy."""
        data = b"A" * 1000
        entropy = calculate_shannon_entropy(data)
        self.assertAlmostEqual(entropy, 0.0, places=6)
        self.assertEqual(classify_entropy_score(entropy), "LOW")

    def test_two_state_equal_distribution(self):
        """Verify that 2 states with 50% probability each produce exactly 1.0000 entropy."""
        data = b"AB" * 500  # 500 'A's, 500 'B's
        entropy = calculate_shannon_entropy(data)
        self.assertAlmostEqual(entropy, 1.0, places=6)
        self.assertEqual(classify_entropy_score(entropy), "LOW")

    def test_four_state_equal_distribution(self):
        """Verify that 4 states with 25% probability each produce exactly 2.0000 entropy."""
        data = b"ABCD" * 250  # 250 each of A, B, C, D
        entropy = calculate_shannon_entropy(data)
        self.assertAlmostEqual(entropy, 2.0, places=6)
        self.assertEqual(classify_entropy_score(entropy), "LOW")

    def test_eight_state_equal_distribution(self):
        """Verify that 8 states with 12.5% probability each produce exactly 3.0000 entropy."""
        data = bytes(range(8)) * 128
        entropy = calculate_shannon_entropy(data)
        self.assertAlmostEqual(entropy, 3.0, places=6)
        self.assertEqual(classify_entropy_score(entropy), "LOW")

    def test_uniform_256_byte_distribution(self):
        """Verify that a uniform distribution of all 256 byte values produces exactly 8.0000 entropy."""
        data = bytes(range(256)) * 10
        entropy = calculate_shannon_entropy(data)
        self.assertAlmostEqual(entropy, 8.0, places=6)
        self.assertEqual(classify_entropy_score(entropy), "VERY_HIGH")

    # 2. Boundary Values Tests
    def test_boundary_empty_data(self):
        """Verify that empty byte sequence returns 0.0 without error."""
        entropy = calculate_shannon_entropy(b"")
        self.assertEqual(entropy, 0.0)
        self.assertEqual(classify_entropy_score(entropy), "LOW")

    def test_boundary_single_byte(self):
        """Verify that a 1-byte buffer returns 0.0 entropy."""
        entropy = calculate_shannon_entropy(b"\xFF")
        self.assertEqual(entropy, 0.0)

    def test_boundary_single_byte_256_pattern(self):
        """Verify that exactly 256 bytes with each byte 0..255 once returns 8.0."""
        data = bytes(range(256))
        entropy = calculate_shannon_entropy(data)
        self.assertAlmostEqual(entropy, 8.0, places=6)

    # 3. Qualitative Classification Tiers Tests
    def test_classification_tiers(self):
        """Verify the 4 classification bands (LOW, NORMAL, HIGH, VERY_HIGH)."""
        self.assertEqual(classify_entropy_score(0.0), "LOW")
        self.assertEqual(classify_entropy_score(3.99), "LOW")
        self.assertEqual(classify_entropy_score(4.0), "NORMAL")
        self.assertEqual(classify_entropy_score(6.25), "NORMAL")
        self.assertEqual(classify_entropy_score(6.79), "NORMAL")
        self.assertEqual(classify_entropy_score(6.8), "HIGH")
        self.assertEqual(classify_entropy_score(7.49), "HIGH")
        self.assertEqual(classify_entropy_score(7.5), "VERY_HIGH")
        self.assertEqual(classify_entropy_score(8.0), "VERY_HIGH")

    # 4. PE Binary & Section Analysis Tests
    def test_pe_binary_and_sections_analysis(self):
        """Verify full file and section entropy extraction on a synthetic PE binary."""
        spec = [
            (".text", 0x1000, 0x400, 0x60000020),   # NOP sled (repeated \x90) -> low entropy
            (".rdata", 0x800, 0x200, 0x40000040),   # Read data
        ]
        pe_bytes = build_custom_sections_pe(spec)
        res = self.analyzer.analyze_bytes(pe_bytes)

        self.assertTrue(res.is_valid)
        self.assertGreater(res.file_entropy, 0.0)
        self.assertEqual(len(res.sections), 2)

        # First section is .text
        text_sec = res.sections[0]
        self.assertEqual(text_sec.name, ".text")
        self.assertIsInstance(text_sec.entropy, float)
        self.assertIn(text_sec.classification, ["LOW", "NORMAL", "HIGH", "VERY_HIGH"])

    # 5. File System & Disk Analysis Tests
    def test_analyze_file_from_disk(self):
        """Verify static entropy analysis from a physical file."""
        data = b"Hello Security World! " * 100
        test_file = Path(self.temp_dir.name) / "sample_doc.bin"
        test_file.write_bytes(data)

        res = self.analyzer.analyze_file(test_file)
        self.assertTrue(res.is_valid)
        self.assertGreater(res.file_entropy, 0.0)
        self.assertLess(res.file_entropy, 8.0)

    def test_analyze_file_missing_handling(self):
        """Verify graceful failure on non-existent file path."""
        missing = Path(self.temp_dir.name) / "does_not_exist.bin"
        res = self.analyzer.analyze_file(missing)

        self.assertFalse(res.is_valid)
        self.assertIn("not found", res.error_message)

    # 6. JSON Schema Contract Tests
    def test_output_schema_contract(self):
        """Verify the exact dictionary schema specified for Module 05."""
        spec = [(".text", 0x1000, 0x200, 0x60000020)]
        pe_bytes = build_custom_sections_pe(spec)
        res = self.analyzer.analyze_bytes(pe_bytes)

        d = res.to_dict()
        self.assertIn("file_entropy", d)
        self.assertIn("sections", d)
        self.assertIsInstance(d["file_entropy"], float)
        self.assertIsInstance(d["sections"], list)

        if d["sections"]:
            sec_dict = d["sections"][0]
            expected_keys = {"name", "entropy", "classification"}
            self.assertEqual(set(sec_dict.keys()), expected_keys)
            self.assertIsInstance(sec_dict["entropy"], float)
            self.assertIsInstance(sec_dict["classification"], str)


if __name__ == "__main__":
    unittest.main()
