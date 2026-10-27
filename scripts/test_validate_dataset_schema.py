#!/usrusr/bin/env python3
"""
Unit tests for EMBER 2018 Dataset Schema Validator
"""

import unittest
import json
import tempfile
import os
import sys
from pathlib import Path

# Add scripts directory to path
sys.path.insert(0, str(Path(__file__).parent / "scripts"))

from validate_dataset_schema import (
    EmberSchemaValidator, ValidationResult, Severity, ValidationSummary
)


class TestEmberSchemaValidator(unittest.TestCase):
    """Unit tests for the EMBER 2018 schema validator."""

    def setUp(self):
        self.validator = EmberSchemaValidator()

    def _make_valid_record(self, label=0, sha256=None, split="train"):
        """Create a valid minimal EMBER record."""
        if sha256 is None:
            sha256 = "a" * 64
        return {
            "sha256": sha256,
            "appeared": "2017-01",
            "label": label,
            "general": {
                "file_size": 1000,
                "vsize": 4096,
                "has_debug": 0,
                "exports": 0,
                "imports": 10,
                "has_relocations": 1,
                "has_resources": 0,
                "has_signature": 0,
                "has_tls": 0,
                "symbols": 0
            },
            "header": {
                "coff": {
                    "timestamp": 1234567890,
                    "machine": "I386",
                    "characteristics": ["EXECUTABLE_IMAGE"]
                },
                "optional": {
                    "subsystem": "WINDOWS_CUI",
                    "dll_characteristics": ["DYNAMIC_BASE"],
                    "magic": "PE32",
                    "major_image_version": 1,
                    "minor_image_version": 0,
                    "major_linker_version": 1,
                    "minor_linker_version": 0,
                    "major_operating_system_version": 6,
                    "minor_operating_system_version": 1,
                    "major_subsystem_version": 6,
                    "minor_subsystem_version": 0,
                    "sizeof_code": 1024,
                    "sizeof_headers": 512,
                    "sizeof_heap_commit": 4096
                }
            },
            "imports": {"KERNEL32.dll": ["GetTickCount"]},
            "exports": [],
            "section": {
                "entry": ".text",
                "sections": [
                    {
                        "name": ".text",
                        "size": 1024,
                        "entropy": 6.5,
                        "vsize": 4096,
                        "props": ["CNT_CODE", "MEM_EXECUTE", "MEM_READ"]
                    }
                ]
            },
            "histogram": [1] * 256,
            "byteentropy": [1] * 256,
            "strings": {
                "numstrings": 10,
                "avlength": 8.5,
                "printabledist": [1] * 96,
                "printables": 100,
                "entropy": 4.5,
                "paths": 0,
                "urls": 0,
                "registry": 0,
                "MZ": 1
            }
        }

    def test_valid_record_passes(self):
        """A fully valid record should pass validation."""
        record = self._make_valid_record()
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 0)
        self.assertEqual(self.validator.summary.valid_records, 1)

    def test_missing_top_level_field_fails(self):
        """Missing required top-level field should produce error."""
        record = self._make_valid_record()
        del record["sha256"]
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertEqual(self.validator.summary.valid_records, 0)
        self.assertIn("Missing required top-level field: sha256",
                      self.validator.summary.results[0].message)

    def test_invalid_sha256_format_fails(self):
        """Invalid SHA-256 format should produce error."""
        record = self._make_valid_record(sha256="not_a_valid_sha256")
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("Invalid SHA-256 format", self.validator.summary.results[0].message)

    def test_sha256_too_short_fails(self):
        """SHA-256 that's too short should fail."""
        record = self._make_valid_record(sha256="abc")
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)

    def test_invalid_label_fails(self):
        """Label outside {-1, 0, 1} should fail."""
        record = self._make_valid_record(label=2)
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("Invalid label value", self.validator.summary.results[0].message)

    def test_negative_one_label_in_test_fails(self):
        """Label -1 in test split should fail."""
        record = self._make_valid_record(label=-1)
        self.validator._validate_record(record, Path("test.jsonl"), 1, "test")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("Unlabeled sample", self.validator.summary.results[0].message)

    def test_negative_one_label_in_train_passes(self):
        """Label -1 in training split should pass."""
        record = self._make_valid_record(label=-1)
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 0)
        self.assertEqual(self.validator.summary.valid_records, 1)

    def test_invalid_appeared_format_fails(self):
        """Invalid appeared format should fail."""
        record = self._make_valid_record()
        record["appeared"] = "2017/01"
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("Invalid appeared format", self.validator.summary.results[0].message)

    def test_invalid_appeared_month_fails(self):
        """Invalid month in appeared should fail."""
        record = self._make_valid_record()
        record["appeared"] = "2017-13"
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)

    def test_missing_general_field_fails(self):
        """Missing general field should error."""
        record = self._make_valid_record()
        del record["general"]["file_size"]
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("Missing required general field: file_size", self.validator.summary.results[0].message)

    def test_file_size_too_small_fails(self):
        """File size < 64 should error."""
        record = self._make_valid_record()
        record["general"]["file_size"] = 32
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("file_size must be integer >= 64", self.validator.summary.results[0].message)

    def test_file_size_zero_fails(self):
        """File size 0 should error."""
        record = self._make_valid_record()
        record["general"]["file_size"] = 0
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)

    def test_histogram_wrong_length_fails(self):
        """Histogram must have exactly 256 elements."""
        record = self._make_valid_record()
        record["histogram"] = [1] * 100
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("Histogram must have exactly 256 elements", self.validator.summary.results[0].message)

    def test_histogram_sum_zero_fails(self):
        """Histogram with sum zero should error."""
        record = self._make_valid_record()
        record["histogram"] = [0] * 256
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("Histogram sum is zero", self.validator.summary.results[0].message)

    def test_histogram_negative_value_fails(self):
        """Negative histogram values should error."""
        record = self._make_valid_record()
        record["histogram"][0] = -1
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("must be non-negative integer", self.validator.summary.results[0].message)

    def test_byteentropy_wrong_length_fails(self):
        """Byteentropy must have 256 elements."""
        record = self._make_valid_record()
        record["byteentropy"] = [1] * 100
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("Byteentropy must have exactly 256 elements", self.validator.summary.results[0].message)

    def test_strings_printabledist_wrong_length_warning(self):
        """printabledist should have 96 elements (warning)."""
        record = self._make_valid_record()
        record["strings"]["printabledist"] = [1] * 50
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        # This is a warning, not an error
        self.assertEqual(self.validator.summary.errors, 0)
        self.assertEqual(self.validator.summary.warnings, 1)
        self.assertIn("printabledist should have 96 elements", self.validator.summary.results[0].message)

    def test_duplicate_sha256_detected(self):
        """Duplicate SHA-256 should be detected."""
        record = self._make_valid_record(sha256="a" * 64)
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.validator._validate_record(record, Path("test.jsonl"), 2, "train")
        self.assertEqual(len(self.validator.summary.duplicate_sha256), 1)
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("Duplicate SHA-256", self.validator.summary.results[-1].message)

    def test_cross_split_duplicate_detected_by_shared_validator(self):
        # Cross-split SHA-256 duplicates are detected when using a shared validator
        # instance (single validator across all splits, enabled by default in CLI).
        record = self._make_valid_record(sha256="b" * 64, label=1)
        # Process train split first
        self.validator._validate_record(record, Path("train.jsonl"), 1, "train")
        # Process test split with same SHA-256 but different label
        record2 = self._make_valid_record(sha256="b" * 64, label=0)
        self.validator._validate_record(record2, Path("test.jsonl"), 1, "test")
        # Duplicate should be flagged
        duplicate_found = any(
            "Duplicate SHA-256" in r.message for r in self.validator.summary.results
        )
        self.assertTrue(duplicate_found, "Duplicate SHA-256 not found in results")
        # Conflicting label should also be flagged
        conflict_found = any(
            "Conflicting labels" in r.message for r in self.validator.summary.results
        )
        self.assertTrue(conflict_found, "Conflicting labels not found in results")

    def test_missing_imports_field_warning(self):
        """Missing imports field should warning (it's required in top-level)."""
        record = self._make_valid_record()
        del record["imports"]
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("Missing required top-level field: imports", self.validator.summary.results[0].message)

    def test_imports_not_dict_fails(self):
        """Imports must be a dict."""
        record = self._make_valid_record()
        record["imports"] = "not_a_dict"
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("Imports must be a dictionary", self.validator.summary.results[0].message)

    def test_exports_not_list_fails(self):
        """Exports must be a list."""
        record = self._make_valid_record()
        record["exports"] = "not_a_list"
        self.validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(self.validator.summary.errors, 1)
        self.assertIn("Exports must be a list", self.validator.summary.results[0].message)

    def test_invalid_json_decoding(self):
        """Invalid JSON should produce error."""
        # This is tested at file level, not record level
        pass

    def test_duplicate_detection_across_records(self):
        """Multiple records with same SHA-256 should be detected."""
        record = self._make_valid_record(sha256="c" * 64)
        validator = EmberSchemaValidator()
        validator._validate_record(record, Path("test.jsonl"), 1, "train")
        validator._validate_record(record, Path("test.jsonl"), 2, "train")
        self.assertEqual(len(validator.summary.duplicate_sha256), 1)
        self.assertEqual(validator.summary.errors, 1)


class TestValidateAppearedFormat(unittest.TestCase):
    """Test the appeared format validation helper."""

    def setUp(self):
        self.validator = EmberSchemaValidator()

    def test_valid_formats(self):
        valid = ["2017-01", "2017-12", "2018-01", "2020-06", "2099-12"]
        for fmt in valid:
            self.assertTrue(self.validator._validate_appeared_format(fmt), f"Failed for {fmt}")

    def test_invalid_formats(self):
        invalid = ["2017/01", "17-01", "2017", "2017-1", "2017-13", "2017-00", "abcd-ef", ""]
        for fmt in invalid:
            self.assertFalse(self.validator._validate_appeared_format(fmt), f"Should fail for {fmt}")


class TestDuplicateDetection(unittest.TestCase):
    """Test duplicate SHA-256 detection logic."""

    def test_duplicate_tracking(self):
        validator = EmberSchemaValidator()
        sha = "a" * 64

        # First occurrence
        record = {"sha256": sha, "appeared": "2017-01", "label": 0,
                  "general": {"file_size": 100, "vsize": 100, "has_debug": 0, "exports": 0,
                              "imports": 0, "has_relocations": 0, "has_resources": 0,
                              "has_signature": 0, "has_tls": 0, "symbols": 0},
                  "header": {"coff": {"timestamp": 0, "machine": "I386", "characteristics": []},
                             "optional": {"subsystem": "WINDOWS_CUI", "dll_characteristics": [],
                                          "magic": "PE32", "major_image_version": 1, "minor_image_version": 0,
                                          "major_linker_version": 1, "minor_image_version": 0,
                                          "major_operating_system_version": 6, "minor_operating_system_version": 0,
                                          "major_subsystem_version": 6, "minor_operating_system_version": 0,
                                          "sizeof_code": 100, "sizeof_headers": 100, "sizeof_heap_commit": 100}},
                  "imports": {}, "exports": [],
                  "section": {"entry": ".text", "sections": []},
                  "histogram": [1]*256, "byteentropy": [1]*256,
                  "strings": {"numstrings": 0, "avlength": 0, "printabledist": [0]*96,
                              "printables": 0, "entropy": 0, "paths": 0, "urls": 0, "registry": 0, "MZ": 0}}

        validator._validate_record(record, Path("test.jsonl"), 1, "train")
        self.assertEqual(len(validator.summary.sha256_seen), 1)
        self.assertEqual(len(validator.summary.duplicate_sha256), 0)

        # Second occurrence
        validator._validate_record(record, Path("test.jsonl"), 2, "train")
        self.assertEqual(len(validator.summary.duplicate_sha256), 1)
        self.assertIn(sha, validator.summary.duplicate_sha256)


if __name__ == "__main__":
    unittest.main(verbosity=2)