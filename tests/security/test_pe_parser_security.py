"""
Module 18 - Security Testing: Step 4 - PE Parser Security & Robustness.
Tests PE parsing engine resilience against crafted binary fuzzing mutations and boundary anomalies.
"""

import unittest
from app.analyzers.pe_analyzer import pe_static_analyzer_service
from app.analyzers.section_analyzer import pe_section_analyzer_service
from app.analyzers.entropy_analyzer import entropy_analyzer_service
from app.analyzers.import_analyzer import windows_api_import_analyzer_service
from app.testing.synthetic_pe import SyntheticPEBuilder


class TestPEParserSecurity(unittest.TestCase):
    """Exhaustive robustness and safety testing for PE static parsing components."""

    def test_01_invalid_dos_header_handling(self):
        """Verify parser returns safe error result when DOS magic is invalid."""
        bad_dos = SyntheticPEBuilder.create_malformed_pe("bad_dos_magic")
        res = pe_static_analyzer_service.analyze_bytes(bad_dos)
        self.assertFalse(res.is_valid)
        self.assertIsNotNone(res.error_message)

    def test_02_invalid_pe_signature_handling(self):
        """Verify parser handles invalid PE signature without raising unhandled exceptions."""
        bad_pe = SyntheticPEBuilder.create_malformed_pe("bad_pe_magic")
        res = pe_static_analyzer_service.analyze_bytes(bad_pe)
        self.assertFalse(res.is_valid)

    def test_03_truncated_header_handling(self):
        """Verify parser safely terminates on truncated header payloads."""
        truncated = SyntheticPEBuilder.create_malformed_pe("truncated_dos")
        res = pe_static_analyzer_service.analyze_bytes(truncated)
        self.assertFalse(res.is_valid)

    def test_04_zero_and_excessive_sections_handling(self):
        """Verify section analyzer gracefully handles binaries with 0 or 65535 sections."""
        zero_sec = SyntheticPEBuilder.create_malformed_pe("zero_sections")
        res_sec0 = pe_section_analyzer_service.analyze_bytes(zero_sec)
        self.assertEqual(res_sec0.total_sections, 0)

        excessive_sec = SyntheticPEBuilder.create_malformed_pe("excessive_sections")
        res_sec_max = pe_section_analyzer_service.analyze_bytes(excessive_sec)
        self.assertIsNotNone(res_sec_max)

    def test_05_corrupt_optional_header_magic(self):
        """Verify parser handles corrupt optional header magic (neither PE32 nor PE32+)."""
        corrupt_opt = SyntheticPEBuilder.create_malformed_pe("corrupt_optional_magic")
        res = pe_static_analyzer_service.analyze_bytes(corrupt_opt)
        self.assertIsNotNone(res)

    def test_06_entropy_analyzer_on_malformed_bytes(self):
        """Verify Shannon entropy analyzer handles zero-length and all-zero bytes without ZeroDivisionError."""
        all_zeros = SyntheticPEBuilder.create_malformed_pe("all_zero_bytes")
        ent_res = entropy_analyzer_service.analyze_bytes(all_zeros)
        self.assertEqual(ent_res.file_entropy, 0.0)
        self.assertEqual(ent_res.file_classification, "LOW")

    def test_07_import_analyzer_on_non_pe(self):
        """Verify import analyzer safely returns empty import result on arbitrary garbage bytes."""
        garbage = SyntheticPEBuilder.create_malformed_pe("random_garbage")
        imp_res = windows_api_import_analyzer_service.analyze_bytes(garbage)
        self.assertEqual(imp_res.total_imports, 0)
        self.assertEqual(len(imp_res.imports), 0)


if __name__ == "__main__":
    unittest.main()
