"""
Unit and integration tests for EMBER 2018 JSONL Adapter (app/ml/ember_adapter.py).

Covers all 14 required verification areas:
1. Valid labeled record.
2. Benign and malicious label handling.
3. Explicit handling of unlabeled records.
4. Missing required fields.
5. Missing feature groups.
6. Incorrect field types.
7. Malformed JSON and empty lines.
8. NaN and infinite values.
9. Incorrect feature dimensions.
10. Deterministic output for repeated processing.
11. Feature ordering and vector shape.
12. Multiple records processed incrementally (streaming and batching).
13. Clear handling of unsupported or incompatible schema.
14. Compatibility with existing feature-vector representation and serializer.
15. Independent reference-derived validation of component transformations.
"""

import copy
import json
import math
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict

import numpy as np
from sklearn.feature_extraction import FeatureHasher

from app.ml.ember_adapter import (
    EMBER_FEATURE_VERSION,
    EMBER_TOTAL_DIM,
    FEATURE_GROUP_DIMS,
    FEATURE_GROUP_NAMES,
    LABEL_BENIGN,
    LABEL_MALICIOUS,
    LABEL_UNLABELED,
    EmberAdapterError,
    EmberDatasetAdapter,
    parse_ember_record,
    validate_ember_record,
)
from app.ml.ember_v2 import EMBER_V2_FEATURE_GROUPS, EMBER_V2_TOTAL_DIM
from app.ml.serialize import (
    FeatureMetadata,
    FeatureVectorSerializer,
    create_ember_v2_metadata,
)


def create_synthetic_record(**overrides: Any) -> Dict[str, Any]:
    """
    Construct a valid synthetic EMBER 2018 Feature Version 2 JSON record.
    Uses purely synthetic, non-malware placeholder data.
    """
    record: Dict[str, Any] = {
        "sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "appeared": "2018-06",
        "label": LABEL_BENIGN,
        "general": {
            "file_size": 24576,
            "vsize": 32768,
            "has_debug": 1,
            "exports": 3,
            "imports": 12,
            "has_relocations": 1,
            "has_resources": 1,
            "has_signature": 0,
            "has_tls": 0,
            "symbols": 0,
        },
        "header": {
            "coff": {
                "timestamp": 1528675200,
                "machine": "I386",
                "characteristics": ["EXECUTABLE_IMAGE", "32BIT_MACHINE", "RELOCS_STRIPPED"],
            },
            "optional": {
                "subsystem": "WINDOWS_GUI",
                "dll_characteristics": ["DYNAMIC_BASE", "NX_COMPAT"],
                "magic": "PE32",
                "major_image_version": 1,
                "minor_image_version": 0,
                "major_linker_version": 14,
                "minor_linker_version": 10,
                "major_operating_system_version": 6,
                "minor_operating_system_version": 1,
                "major_subsystem_version": 6,
                "minor_subsystem_version": 0,
                "sizeof_code": 8192,
                "sizeof_headers": 1024,
                "sizeof_heap_commit": 4096,
            },
        },
        "section": {
            "entry": ".text",
            "sections": [
                {
                    "name": ".text",
                    "size": 8192,
                    "entropy": 6.12,
                    "vsize": 8000,
                    "props": ["MEM_READ", "MEM_EXECUTE", "CNT_CODE"],
                },
                {
                    "name": ".rdata",
                    "size": 4096,
                    "entropy": 4.50,
                    "vsize": 4000,
                    "props": ["MEM_READ", "CNT_INITIALIZED_DATA"],
                },
                {
                    "name": ".data",
                    "size": 2048,
                    "entropy": 2.10,
                    "vsize": 3000,
                    "props": ["MEM_READ", "MEM_WRITE", "CNT_INITIALIZED_DATA"],
                },
            ],
        },
        "imports": {
            "KERNEL32.dll": ["ExitProcess", "CreateFileA", "CloseHandle", "GetLastError"],
            "USER32.dll": ["MessageBoxA", "ShowWindow", "PostQuitMessage"],
            "ADVAPI32.dll": ["RegOpenKeyExA", "RegQueryValueExA"],
        },
        "exports": ["SyntheticInit", "SyntheticExecute", "SyntheticCleanup"],
        "histogram": [5] * 256,
        "byteentropy": [2] * 256,
        "strings": {
            "numstrings": 25,
            "avlength": 14.8,
            "printables": 370,
            "printabledist": [4] * 96,
            "entropy": 4.15,
            "paths": 1,
            "urls": 2,
            "registry": 1,
            "MZ": 1,
        },
        "datadirectories": [
            {"size": 128, "virtual_address": 0x1000},
            {"size": 256, "virtual_address": 0x2000},
            {"size": 512, "virtual_address": 0x3000},
        ],
    }

    for k, v in overrides.items():
        if v is None:
            record.pop(k, None)
        else:
            record[k] = v

    return record


class TestEmberAdapterBasics(unittest.TestCase):
    """Test suite for adapter initialization and basic contracts."""

    def setUp(self):
        self.adapter = EmberDatasetAdapter()

    def test_adapter_constants_match_contract(self):
        """Verify adapter dimensions match EMBER v2 specification."""
        self.assertEqual(EMBER_TOTAL_DIM, 2381)
        self.assertEqual(EMBER_FEATURE_VERSION, 2)
        self.assertEqual(self.adapter.total_dim, 2381)
        self.assertEqual(EMBER_TOTAL_DIM, EMBER_V2_TOTAL_DIM)

        expected_group_sum = sum(FEATURE_GROUP_DIMS.values())
        self.assertEqual(expected_group_sum, 2381)
        self.assertEqual(len(FEATURE_GROUP_NAMES), 9)

    def test_unsupported_feature_version_init(self):
        """Verify adapter rejects unsupported feature versions at initialization."""
        with self.assertRaises(EmberAdapterError) as ctx:
            EmberDatasetAdapter(feature_version=1)
        self.assertIn("Unsupported feature version", str(ctx.exception))

        with self.assertRaises(EmberAdapterError):
            EmberDatasetAdapter(feature_version=3)


class TestEmberAdapterRecordParsing(unittest.TestCase):
    """Test suite for single record parsing, label handling, and schema validation."""

    def setUp(self):
        self.adapter = EmberDatasetAdapter()

    # 1. Valid labeled record
    def test_valid_labeled_record(self):
        """Requirement 1: Verify parsing of a valid labeled record."""
        rec = create_synthetic_record()
        vector, label = self.adapter.parse_record(rec)

        self.assertIsInstance(vector, np.ndarray)
        self.assertEqual(vector.shape, (2381,))
        self.assertEqual(vector.dtype, np.float32)
        self.assertTrue(np.all(np.isfinite(vector)))
        self.assertEqual(label, LABEL_BENIGN)

    # 2. Benign and malicious label handling
    def test_benign_and_malicious_label_handling(self):
        """Requirement 2: Verify explicit handling of benign (0) and malicious (1) labels."""
        benign_rec = create_synthetic_record(label=LABEL_BENIGN)
        vec_b, label_b = self.adapter.parse_record(benign_rec)
        self.assertEqual(label_b, 0)
        self.assertEqual(vec_b.shape, (2381,))

        malicious_rec = create_synthetic_record(label=LABEL_MALICIOUS)
        vec_m, label_m = self.adapter.parse_record(malicious_rec)
        self.assertEqual(label_m, 1)
        self.assertEqual(vec_m.shape, (2381,))

    # 3. Explicit handling of unlabeled records
    def test_unlabeled_records_preserved(self):
        """Requirement 3: Verify unlabeled records (-1) are preserved and never converted."""
        unlabeled_rec = create_synthetic_record(label=LABEL_UNLABELED)
        vector, label = self.adapter.parse_record(unlabeled_rec, split="train")

        self.assertEqual(label, -1)
        self.assertNotEqual(label, 0)
        self.assertNotEqual(label, 1)
        self.assertEqual(vector.shape, (2381,))

    def test_unlabeled_records_rejected_in_test_split(self):
        """Requirement 3: Verify unlabeled records are rejected if split is 'test'."""
        unlabeled_rec = create_synthetic_record(label=LABEL_UNLABELED)
        with self.assertRaises(EmberAdapterError) as ctx:
            self.adapter.parse_record(unlabeled_rec, split="test")
        self.assertIn("test split", str(ctx.exception))

    def test_invalid_label_values_rejected(self):
        """Requirement 3: Verify invalid labels (outside -1, 0, 1) are rejected."""
        for invalid_label in [2, -2, 99, "0", "1", None, True, False]:
            rec = create_synthetic_record(label=invalid_label)
            with self.assertRaises(EmberAdapterError):
                self.adapter.parse_record(rec)

    # 4. Missing required fields
    def test_missing_required_top_level_fields(self):
        """Requirement 4: Verify rejection when required top-level fields are missing."""
        for field in ["sha256", "appeared", "label", "general", "header", "section", "imports", "exports", "histogram", "byteentropy", "strings"]:
            rec = create_synthetic_record()
            del rec[field]
            with self.assertRaises(EmberAdapterError) as ctx:
                self.adapter.parse_record(rec)
            self.assertIn(field, str(ctx.exception))

    def test_missing_general_fields(self):
        """Requirement 4: Verify rejection when required general fields are missing."""
        rec = create_synthetic_record()
        del rec["general"]["vsize"]
        with self.assertRaises(EmberAdapterError) as ctx:
            self.adapter.parse_record(rec)
        self.assertIn("vsize", str(ctx.exception))

    def test_general_supports_file_size_and_size(self):
        """Requirement 4: Verify field name mapping: general.size vs general.file_size."""
        # Using file_size
        rec1 = create_synthetic_record()
        rec1["general"]["file_size"] = 12345
        rec1["general"].pop("size", None)
        v1, _ = self.adapter.parse_record(rec1)
        self.assertEqual(v1[616], 12345.0)

        # Using size
        rec2 = create_synthetic_record()
        rec2["general"].pop("file_size", None)
        rec2["general"]["size"] = 54321
        v2, _ = self.adapter.parse_record(rec2)
        self.assertEqual(v2[616], 54321.0)

    # 5. Missing feature groups
    def test_missing_feature_groups(self):
        """Requirement 5: Verify rejection when entire feature groups are missing."""
        groups = ["histogram", "byteentropy", "strings", "general", "header", "section", "imports", "exports"]
        for group in groups:
            rec = create_synthetic_record()
            del rec[group]
            with self.assertRaises(EmberAdapterError):
                self.adapter.parse_record(rec)

    # 6. Incorrect field types
    def test_incorrect_field_types(self):
        """Requirement 6: Verify rejection on incorrect types for fields."""
        # Record is a list instead of dict
        with self.assertRaises(EmberAdapterError):
            self.adapter.parse_record([{"sha256": "abc"}])  # type: ignore

        # Histogram is a string
        rec_str_hist = create_synthetic_record(histogram="invalid_string")
        with self.assertRaises(EmberAdapterError):
            self.adapter.parse_record(rec_str_hist)

        # Byteentropy is an integer
        rec_int_be = create_synthetic_record(byteentropy=123)
        with self.assertRaises(EmberAdapterError):
            self.adapter.parse_record(rec_int_be)

        # Imports is a list instead of dict
        rec_list_imp = create_synthetic_record(imports=["kernel32.dll"])
        with self.assertRaises(EmberAdapterError):
            self.adapter.parse_record(rec_list_imp)

        # Exports is a dict instead of list
        rec_dict_exp = create_synthetic_record(exports={"func": 1})
        with self.assertRaises(EmberAdapterError):
            self.adapter.parse_record(rec_dict_exp)

        # sha256 is not 64 hex characters
        rec_bad_sha = create_synthetic_record(sha256="not_a_valid_sha256")
        with self.assertRaises(EmberAdapterError):
            self.adapter.parse_record(rec_bad_sha)

        # appeared is wrong format
        rec_bad_app = create_synthetic_record(appeared="2018/06")
        with self.assertRaises(EmberAdapterError):
            self.adapter.parse_record(rec_bad_app)

    # 8. NaN and infinite values
    def test_nan_in_histogram(self):
        """Requirement 8: Verify rejection of NaN values in histogram."""
        bad_hist = [1.0] * 256
        bad_hist[10] = float("nan")
        rec = create_synthetic_record(histogram=bad_hist)
        with self.assertRaises(EmberAdapterError) as ctx:
            self.adapter.parse_record(rec)
        self.assertTrue("nan" in str(ctx.exception).lower() or "non-finite" in str(ctx.exception).lower())

    def test_inf_in_byteentropy(self):
        """Requirement 8: Verify rejection of infinite values in byteentropy."""
        bad_be = [1.0] * 256
        bad_be[50] = float("inf")
        rec = create_synthetic_record(byteentropy=bad_be)
        with self.assertRaises(EmberAdapterError) as ctx:
            self.adapter.parse_record(rec)
        self.assertTrue("inf" in str(ctx.exception).lower() or "non-finite" in str(ctx.exception).lower())

    def test_nan_in_strings_scalars(self):
        """Requirement 8: Verify rejection of NaN in strings scalar fields."""
        rec = create_synthetic_record()
        rec["strings"]["entropy"] = float("nan")
        with self.assertRaises(EmberAdapterError):
            self.adapter.parse_record(rec)

    def test_nan_in_general_fields(self):
        """Requirement 8: Verify rejection of NaN in general metadata fields."""
        rec = create_synthetic_record()
        rec["general"]["vsize"] = float("nan")
        with self.assertRaises(EmberAdapterError):
            self.adapter.parse_record(rec)

    def test_nan_in_section_entropy(self):
        """Requirement 8: Verify rejection of NaN in section entropy."""
        rec = create_synthetic_record()
        rec["section"]["sections"][0]["entropy"] = float("nan")
        with self.assertRaises(EmberAdapterError):
            self.adapter.parse_record(rec)

    # 9. Incorrect feature dimensions
    def test_incorrect_histogram_dimension(self):
        """Requirement 9: Verify rejection when histogram length is not 256."""
        # 255 items
        rec_short = create_synthetic_record(histogram=[1] * 255)
        with self.assertRaises(EmberAdapterError) as ctx:
            self.adapter.parse_record(rec_short)
        self.assertIn("256", str(ctx.exception))

        # 257 items
        rec_long = create_synthetic_record(histogram=[1] * 257)
        with self.assertRaises(EmberAdapterError) as ctx:
            self.adapter.parse_record(rec_long)
        self.assertIn("256", str(ctx.exception))

    def test_incorrect_byteentropy_dimension(self):
        """Requirement 9: Verify rejection when byteentropy length is not 256."""
        rec_short = create_synthetic_record(byteentropy=[1] * 200)
        with self.assertRaises(EmberAdapterError) as ctx:
            self.adapter.parse_record(rec_short)
        self.assertIn("256", str(ctx.exception))

    def test_incorrect_printabledist_dimension(self):
        """Requirement 9: Verify rejection when strings.printabledist is not 96."""
        rec = create_synthetic_record()
        rec["strings"]["printabledist"] = [1] * 95
        with self.assertRaises(EmberAdapterError) as ctx:
            self.adapter.parse_record(rec)
        self.assertIn("96", str(ctx.exception))

    # 10. Deterministic output for repeated processing
    def test_deterministic_processing(self):
        """Requirement 10: Verify repeated parsing of same record produces identical vectors."""
        rec = create_synthetic_record()
        vec_initial, label_initial = self.adapter.parse_record(rec)

        for _ in range(10):
            vec_repeat, label_repeat = self.adapter.parse_record(rec)
            self.assertEqual(label_repeat, label_initial)
            self.assertTrue(np.array_equal(vec_repeat, vec_initial))

    # 11. Feature ordering and vector shape
    def test_feature_ordering_and_slices(self):
        """Requirement 11: Verify exact slice boundaries and shapes for each feature group."""
        rec = create_synthetic_record()
        vector, _ = self.adapter.parse_record(rec)

        self.assertEqual(vector.shape, (2381,))
        self.assertEqual(vector.dtype, np.float32)

        # Verify slices according to contract
        slice_offsets = {
            "histogram": (0, 256),
            "byteentropy": (256, 512),
            "strings": (512, 616),
            "general": (616, 626),
            "header": (626, 688),
            "section": (688, 943),
            "imports": (943, 2223),
            "exports": (2223, 2351),
            "datadirectories": (2351, 2381),
        }

        for name, (start, end) in slice_offsets.items():
            expected_dim = FEATURE_GROUP_DIMS[name]
            self.assertEqual(end - start, expected_dim, f"Slice length mismatch for {name}")
            group_slice = vector[start:end]
            self.assertEqual(group_slice.shape, (expected_dim,), f"Shape mismatch for {name}")
            self.assertTrue(np.all(np.isfinite(group_slice)), f"Non-finite slice for {name}")

    # 13. Clear handling of unsupported or incompatible schema
    def test_incompatible_schema_version_in_record(self):
        """Requirement 13: Verify record declaring incompatible feature version is rejected."""
        rec = create_synthetic_record(feature_version=1)
        with self.assertRaises(EmberAdapterError) as ctx:
            self.adapter.parse_record(rec)
        self.assertIn("Incompatible schema", str(ctx.exception))

    def test_validation_function_returns_actionable_errors(self):
        """Requirement 13: Verify validate_ember_record reports multiple actionable errors."""
        bad_rec = {
            "appeared": "2018/99",
            "label": 5,
            "histogram": [1] * 10,
        }
        errors = validate_ember_record(bad_rec)
        self.assertGreater(len(errors), 0)
        error_blob = " ".join(errors).lower()
        self.assertIn("missing required top-level field", error_blob)
        self.assertIn("histogram", error_blob)
        self.assertIn("label", error_blob)


class TestEmberAdapterStreamingAndBatching(unittest.TestCase):
    """Test suite for incremental streaming and batch processing (bounded memory)."""

    def setUp(self):
        self.adapter = EmberDatasetAdapter()

    # 7. Malformed JSON and empty lines
    def test_empty_lines_and_malformed_json(self):
        """Requirement 7: Verify empty lines are skipped and malformed JSON raises line-numbered error."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as f:
            rec1 = create_synthetic_record(sha256="0" * 64, label=0)
            f.write("\n\n")  # leading empty lines
            f.write(json.dumps(rec1) + "\n")
            f.write("   \n")  # whitespace line
            f.write("INVALID JSON CONTENT HERE\n")
            f_path = f.name

        try:
            records = []
            with self.assertRaises(EmberAdapterError) as ctx:
                for item in self.adapter.parse_jsonl(f_path):
                    records.append(item)
            # The first record should have been processed before encountering line 5 error
            self.assertEqual(len(records), 1)
            self.assertIn("line 5", str(ctx.exception).lower())
        finally:
            if os.path.exists(f_path):
                os.remove(f_path)

    def test_empty_file_handling(self):
        """Requirement 7: Verify empty JSONL file produces empty iterator without crashing."""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as f:
            f.write("")
            f_path = f.name

        try:
            items = list(self.adapter.parse_jsonl(f_path))
            self.assertEqual(len(items), 0)
        finally:
            if os.path.exists(f_path):
                os.remove(f_path)

    # 12. Multiple records processed incrementally
    def test_incremental_streaming(self):
        """Requirement 12: Verify multiple records can be streamed sequentially."""
        num_records = 10
        records_data = []
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as f:
            for i in range(num_records):
                sha = f"{i:02x}" * 32
                lbl = i % 2
                rec = create_synthetic_record(sha256=sha, label=lbl)
                records_data.append((sha, lbl))
                f.write(json.dumps(rec) + "\n")
            f_path = f.name

        try:
            yielded = list(self.adapter.parse_jsonl(f_path))
            self.assertEqual(len(yielded), num_records)
            for idx, (vec, lbl, sha) in enumerate(yielded):
                exp_sha, exp_lbl = records_data[idx]
                self.assertEqual(sha, exp_sha)
                self.assertEqual(lbl, exp_lbl)
                self.assertEqual(vec.shape, (2381,))
                self.assertEqual(vec.dtype, np.float32)
        finally:
            if os.path.exists(f_path):
                os.remove(f_path)

    def test_batch_processing_and_max_records(self):
        """Requirement 12: Verify batched streaming (parse_jsonl_batches) and max_records limit."""
        total_records = 7
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".jsonl") as f:
            for i in range(total_records):
                sha = f"{i:02x}" * 32
                rec = create_synthetic_record(sha256=sha, label=i % 2)
                f.write(json.dumps(rec) + "\n")
            f_path = f.name

        try:
            # Batch size 3 over 7 records -> batches of 3, 3, 1
            batches = list(self.adapter.parse_jsonl_batches(f_path, batch_size=3))
            self.assertEqual(len(batches), 3)

            X1, y1, shas1 = batches[0]
            self.assertEqual(X1.shape, (3, 2381))
            self.assertEqual(y1.shape, (3,))
            self.assertEqual(len(shas1), 3)

            X2, y2, shas2 = batches[1]
            self.assertEqual(X2.shape, (3, 2381))
            self.assertEqual(y2.shape, (3,))

            X3, y3, shas3 = batches[2]
            self.assertEqual(X3.shape, (1, 2381))
            self.assertEqual(y3.shape, (1,))

            # With max_records = 4
            limited_batches = list(self.adapter.parse_jsonl_batches(f_path, batch_size=3, max_records=4))
            self.assertEqual(len(limited_batches), 2)
            self.assertEqual(limited_batches[0][0].shape[0], 3)
            self.assertEqual(limited_batches[1][0].shape[0], 1)
        finally:
            if os.path.exists(f_path):
                os.remove(f_path)


class TestEmberAdapterCompatibilityAndParity(unittest.TestCase):
    """Test suite for representation compatibility and independent reference validation."""

    def setUp(self):
        self.adapter = EmberDatasetAdapter()

    # 14. Compatibility with existing feature-vector representation
    def test_compatibility_with_feature_vector_serializer(self):
        """Requirement 14: Verify adapter vectors can be serialized with FeatureVectorSerializer."""
        rec = create_synthetic_record()
        vector, label = self.adapter.parse_record(rec)

        metadata = create_ember_v2_metadata(vector, sample_sha256=rec["sha256"])
        serializer = FeatureVectorSerializer(contract="ember-v2")

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_file = Path(tmp_dir) / "test_vector.npz"
            serializer.serialize(vector, metadata, out_file)
            self.assertTrue(out_file.exists())

            loaded_vec, loaded_meta = serializer.deserialize(out_file)
            self.assertEqual(loaded_vec.shape, (2381,))
            self.assertEqual(loaded_vec.dtype, np.float32)
            self.assertTrue(np.array_equal(loaded_vec, vector))
            self.assertEqual(loaded_meta.sample_sha256, rec["sha256"])

    # Independent reference-derived verification tests
    def test_independent_histogram_normalization_parity(self):
        """Compare adapter histogram slice against independently computed L1 normalization."""
        raw_counts = [i * 3 for i in range(256)]
        total = float(sum(raw_counts))
        expected_hist = np.array([c / total for c in raw_counts], dtype=np.float32)

        rec = create_synthetic_record(histogram=raw_counts)
        vector, _ = self.adapter.parse_record(rec)
        actual_hist = vector[0:256]

        np.testing.assert_allclose(actual_hist, expected_hist, rtol=1e-6, atol=1e-7)

    def test_independent_byteentropy_normalization_parity(self):
        """Compare adapter byteentropy slice against independently computed L1 normalization."""
        raw_be = [(i % 16) + 1 for i in range(256)]
        total = float(sum(raw_be))
        expected_be = np.array([c / total for c in raw_be], dtype=np.float32)

        rec = create_synthetic_record(byteentropy=raw_be)
        vector, _ = self.adapter.parse_record(rec)
        actual_be = vector[256:512]

        np.testing.assert_allclose(actual_be, expected_be, rtol=1e-6, atol=1e-7)

    def test_independent_general_features_parity(self):
        """Compare adapter general slice against independent extraction."""
        rec = create_synthetic_record()
        gen = rec["general"]
        expected_gen = np.array([
            float(gen["file_size"]),
            float(gen["vsize"]),
            float(gen["has_debug"]),
            float(gen["exports"]),
            float(gen["imports"]),
            float(gen["has_relocations"]),
            float(gen["has_resources"]),
            float(gen["has_signature"]),
            float(gen["has_tls"]),
            float(gen["symbols"]),
        ], dtype=np.float32)

        vector, _ = self.adapter.parse_record(rec)
        actual_gen = vector[616:626]

        np.testing.assert_array_equal(actual_gen, expected_gen)

    def test_independent_strings_features_parity(self):
        """Compare adapter strings slice against independently computed features."""
        rec = create_synthetic_record()
        s = rec["strings"]
        pdist_counts = np.array(s["printabledist"], dtype=np.float32)
        norm_pdist = pdist_counts / pdist_counts.sum()

        expected_strings = np.hstack([
            np.float32(s["numstrings"]),
            np.float32(s["avlength"]),
            np.float32(s["printables"]),
            norm_pdist,
            np.float32(s["entropy"]),
            np.float32(s["paths"]),
            np.float32(s["urls"]),
            np.float32(s["registry"]),
            np.float32(s["MZ"]),
        ]).astype(np.float32)

        vector, _ = self.adapter.parse_record(rec)
        actual_strings = vector[512:616]

        np.testing.assert_allclose(actual_strings, expected_strings, rtol=1e-6, atol=1e-7)

    def test_independent_hasher_parity_imports_and_exports(self):
        """Compare adapter imports/exports slices against independent FeatureHasher calls."""
        rec = create_synthetic_record()

        # Independent FeatureHasher for exports
        ind_exp_hasher = FeatureHasher(128, input_type="string", alternate_sign=True)
        expected_exports = ind_exp_hasher.transform([rec["exports"]]).toarray()[0].astype(np.float32)

        # Independent FeatureHashers for imports
        ind_lib_hasher = FeatureHasher(256, input_type="string", alternate_sign=True)
        ind_imp_hasher = FeatureHasher(1024, input_type="string", alternate_sign=True)
        unique_libs = list(set([k.lower() for k in rec["imports"].keys()]))
        import_pairs = [k.lower() + ":" + f for k, flist in rec["imports"].items() for f in flist]
        expected_libs = ind_lib_hasher.transform([unique_libs]).toarray()[0].astype(np.float32)
        expected_imports = ind_imp_hasher.transform([import_pairs]).toarray()[0].astype(np.float32)

        vector, _ = self.adapter.parse_record(rec)

        actual_libs = vector[943:1199]
        actual_imports = vector[1199:2223]
        actual_exports = vector[2223:2351]

        np.testing.assert_array_equal(actual_libs, expected_libs)
        np.testing.assert_array_equal(actual_imports, expected_imports)
        np.testing.assert_array_equal(actual_exports, expected_exports)


if __name__ == "__main__":
    unittest.main()
