"""
Tests for EMBER v2 Feature Extractor and Serialization
"""

import unittest
import tempfile
import os
import json
import numpy as np
import hashlib
from pathlib import Path
import sys

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.ml.ember_v2 import EMBERFeatureExtractor, EMBER_V2_TOTAL_DIM, EMBER_V2_FEATURE_GROUPS
from app.ml.serialize import (
    FeatureVectorSerializer,
    FeatureMetadata,
    create_ember_v2_metadata,
    serialize_features,
    deserialize_features,
    serialize_batch,
    deserialize_features,
)


class TestEmberV2FeatureExtractor(unittest.TestCase):
    """Tests for EMBER v2 Feature Extractor."""
    
    def setUp(self):
        self.extractor = EMBERFeatureExtractor(feature_version=2)
    
    def test_total_dimension(self):
        """Verify total feature dimension is 2381."""
        self.assertEqual(EMBER_V2_TOTAL_DIM, 2381)
        self.assertEqual(self.extractor.TOTAL_DIM, 2381)
        self.assertEqual(self.extractor.total_dim, 2381)
    
    def test_feature_groups(self):
        """Verify feature groups and dimensions match contract."""
        groups = EMBER_V2_FEATURE_GROUPS
        self.assertEqual(len(groups), 9)
        
        expected = {
            "histogram": 256,
            "byteentropy": 256,
            "strings": 104,
            "general": 10,
            "header": 62,
            "section": 255,
            "imports": 1280,
            "exports": 128,
            "datadirectories": 30,
        }
        
        for group in groups:
            self.assertEqual(group.dim, expected[group.name])
        
        total = sum(g.dim for g in groups)
        self.assertEqual(total, 2381)
    
    def test_feature_version(self):
        """Verify feature version is 2."""
        self.assertEqual(self.extractor.feature_version, 2)
        self.assertEqual(self.extractor.FEATURE_VERSION, 2)
    
    def test_total_dim_property(self):
        """Test total_dim property."""
        self.assertEqual(self.extractor.total_dim, 2381)
    
    def test_feature_group_order(self):
        """Verify feature group order matches reference."""
        expected_order = [
            "histogram", "byteentropy", "strings", "general",
            "header", "section", "imports", "exports", "datadirectories"
        ]
        self.assertEqual(self.extractor.FEATURE_GROUP_NAMES, expected_order)
    
    def test_feature_group_dims(self):
        """Verify feature group dimensions."""
        expected_dims = {
            "histogram": 256,
            "byteentropy": 256,
            "strings": 104,
            "general": 10,
            "header": 62,
            "section": 255,
            "imports": 1280,
            "exports": 128,
            "datadirectories": 30,
        }
        self.assertEqual(self.extractor.FEATURE_GROUP_DIMS, expected_dims)
    
    def test_extract_empty_bytes(self):
        """Test extraction on empty bytes."""
        result = self.extractor.feature_vector(b"")
        self.assertEqual(result.shape[0], 2381)
        self.assertEqual(result.dtype, np.float32)
        # Should be all zeros for empty input
        self.assertTrue(np.all(result == 0))
    
    def test_extract_invalid_pe(self):
        """Test extraction on non-PE bytes."""
        result = self.extractor.feature_vector(b"not a PE file")
        self.assertEqual(result.shape[0], 2381)
        self.assertEqual(result.dtype, np.float32)
        # Should not crash, returns valid array
    
    def test_determinism(self):
        """Test deterministic extraction."""
        test_bytes = b"MZ" + b"\x00" * 1000  # Minimal valid-ish PE
        result1 = self.extractor.feature_vector(test_bytes)
        result2 = self.extractor.feature_vector(test_bytes)
        np.testing.assert_array_equal(result1, result2)
    
    def test_raw_features_output(self):
        """Test raw features dictionary structure."""
        test_bytes = b"MZ" + b"\x00" * 500
        raw = self.extractor.raw_features(test_bytes)
        
        # Check required keys
        expected_keys = {
            "sha256", "histogram", "byteentropy", "strings",
            "general", "header", "section", "imports", "exports"
        }
        self.assertTrue(expected_keys.issubset(raw.keys()))
        
        # Check datadirectories exists (feature version 2)
        self.assertIn("datadirectories", raw)
    
    def test_process_raw_features(self):
        """Test processing raw features to vector."""
        test_bytes = b"MZ" + b"\x00" * 500
        raw = self.extractor.raw_features(test_bytes)
        vector = self.extractor.process_raw_features(raw)
        
        self.assertEqual(vector.shape[0], 2381)
        self.assertEqual(vector.dtype, np.float32)
    
    def test_feature_vector_dtype(self):
        """Verify output dtype is float32."""
        result = self.extractor.feature_vector(b"MZ" + b"\x00" * 100)
        self.assertEqual(result.dtype, np.float32)
    
    def test_feature_vector_shape(self):
        """Verify output shape is (2381,)."""
        result = self.extractor.feature_vector(b"MZ" + b"\x00" * 100)
        self.assertEqual(result.shape, (2381,))
    
    def test_feature_vector_finite(self):
        """Verify all values are finite."""
        result = self.extractor.feature_vector(b"MZ" + b"\x00" * 100)
        self.assertTrue(np.all(np.isfinite(result)))
    
    def test_histogram_normalization(self):
        """Test histogram L1 normalization."""
        test_bytes = b"MZ" + b"A" * 100
        raw = self.extractor.raw_features(test_bytes)
        hist = np.array(raw["histogram"])
        self.assertAlmostEqual(float(hist.sum()), 1.0, places=5)
    
    def test_byteentropy_normalization(self):
        """Test byteentropy L1 normalization."""
        test_bytes = b"MZ" + b"A" * 1000
        raw = self.extractor.raw_features(test_bytes)
        be = np.array(raw["byteentropy"])
        self.assertAlmostEqual(float(be.sum()), 1.0, places=5)
    
    def test_sha256_in_raw_features(self):
        """Verify SHA-256 is included in raw features."""
        test_bytes = b"MZ" + b"\x00" * 100
        raw = self.extractor.raw_features(test_bytes)
        self.assertIn("sha256", raw)
        self.assertEqual(len(raw["sha256"]), 64)
    
    def test_get_feature_metadata(self):
        """Test metadata generation."""
        test_bytes = b"MZ" + b"\x00" * 100
        vector = self.extractor.feature_vector(test_bytes)
        meta = self.extractor.get_feature_metadata()
        
        self.assertEqual(meta["feature_version"], 2)
        self.assertEqual(meta["total_dim"], 2381)
        self.assertEqual(meta["dtype"], "float32")
        self.assertEqual(len(meta["feature_groups"]), 9)
        self.assertIn("lief_version", meta)
        self.assertIn("sklearn_version", meta)
        self.assertIn("numpy_version", meta)


class TestFeatureSerialization(unittest.TestCase):
    """Tests for feature serialization."""
    
    def setUp(self):
        self.extractor = EMBERFeatureExtractor()
        self.test_vector = np.random.rand(2381).astype(np.float32)
        # Make it deterministic for testing
        np.random.seed(42)
        self.test_vector = np.random.rand(2381).astype(np.float32)
    
    def test_create_metadata(self):
        """Test metadata creation."""
        vector = self.test_vector
        meta = create_ember_v2_metadata(
            vector,
            sample_sha256="a" * 64,
            extractor_version="1.0.0"
        )
        
        self.assertEqual(meta.feature_contract, "ember-v2")
        self.assertEqual(meta.feature_version, 2)
        self.assertEqual(meta.schema_version, "1.0")
        self.assertEqual(meta.total_dim, 2381)
        self.assertEqual(meta.dtype, "float32")
        self.assertEqual(len(meta.feature_groups), 9)
        self.assertIsNotNone(meta.vector_sha256)
    
    def test_serialize_deserialize_roundtrip(self):
        """Test NPZ round-trip serialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test_features.npz"
            
            # Serialize
            serialize_features(vector, filepath, metadata=meta)
            
            # Deserialize
            loaded_vector, loaded_meta = deserialize_features(filepath)
            
            # Verify
            np.testing.assert_array_equal(vector, loaded_vector)
            self.assertEqual(loaded_meta.feature_contract, "ember-v2")
            self.assertEqual(loaded_meta.feature_version, 2)
            self.assertEqual(loaded_meta.total_dim, 2381)
    
    def test_serialize_deserialize_with_compression(self):
        """Test with compression enabled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test_compressed.npz"
            
            serialize_features(vector, filepath, metadata=meta, compression=True)
            loaded_vector, loaded_meta = deserialize_features(filepath)
            
            np.testing.assert_array_equal(vector, loaded_vector)
    
    def test_serialize_without_metadata(self):
        """Test serialization with auto-generated metadata."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector
            filepath = Path(tmpdir) / "test_auto.npz"
            
            serialize_features(vector, filepath)
            loaded_vector, loaded_meta = deserialize_features(filepath)
            
            np.testing.assert_array_equal(vector, loaded_vector)
            self.assertEqual(loaded_meta.feature_contract, "ember-v2")
    
    def test_deserialize_validation_contract_mismatch(self):
        """Test rejection of wrong contract."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test.npz"
            serialize_features(vector, filepath, metadata=meta)
            
            # Try to deserialize with wrong contract
            with self.assertRaises(ValueError) as cm:
                deserialize_features(filepath, contract="ethio-v1")
            self.assertIn("Contract mismatch", str(cm.exception))
    
    def test_deserialize_validation_dimension_mismatch(self):
        """Test rejection of wrong dimension."""
        import shutil
        tmpdir = tempfile.mkdtemp()
        try:
            vector = self.test_vector
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test.npz"
            serialize_features(vector, filepath, metadata=meta)
            
            # Manually corrupt the metadata
            data = np.load(filepath)
            meta_json = data["metadata"]
            if isinstance(meta_json, np.ndarray):
                meta_json = meta_json.item()
            meta_dict = json.loads(meta_json)
            meta_dict["total_dim"] = 1000  # Wrong dimension
            
            # Save corrupted file
            np.savez_compressed(
                filepath,
                vector=data["vector"],
                metadata=json.dumps(meta_dict)
            )
            
            with self.assertRaises(ValueError) as cm:
                deserialize_features(filepath)
            self.assertIn("dimension", str(cm.exception).lower())
        finally:
            # Manual cleanup to avoid Windows file locking issues
            shutil.rmtree(tmpdir, ignore_errors=True)
    
    def test_deserialize_validation_non_finite(self):
        """Test rejection of non-finite values - validation happens at serialize time."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector.copy()
            vector[0] = np.nan  # Non-finite value
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test.npz"
            
            # Validation happens at serialize time
            with self.assertRaises(ValueError) as cm:
                serialize_features(vector, filepath, metadata=meta)
            self.assertIn("non-finite", str(cm.exception).lower())
    
    def test_deserialize_validation_inf(self):
        """Test rejection of infinite values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector.copy()
            vector[0] = np.inf
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test.npz"
            
            # Validation happens at serialize time
            with self.assertRaises(ValueError) as cm:
                serialize_features(vector, filepath, metadata=meta)
            self.assertIn("non-finite", str(cm.exception).lower())
    
    def test_deserialize_wrong_dtype(self):
        """Test rejection of wrong dtype."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector.astype(np.float64)  # Wrong dtype
            meta = create_ember_v2_metadata(self.test_vector)  # metadata for float32
            filepath = Path(tmpdir) / "test.npz"
            
            # Save with wrong dtype (float64) but metadata says float32
            meta_dict = create_ember_v2_metadata(self.test_vector).to_dict()
            np.savez_compressed(
                filepath,
                vector=vector,  # float64
                metadata=json.dumps(meta_dict)
            )
            
            with self.assertRaises(ValueError) as cm:
                deserialize_features(filepath)
            self.assertIn("dtype must be float32", str(cm.exception))
    
    def test_integrity_hash_verification(self):
        """Test integrity hash verification on deserialize."""
        import shutil
        tmpdir = tempfile.mkdtemp()
        try:
            vector = self.test_vector
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test.npz"
            serialize_features(vector, filepath, metadata=meta)
            
            # Corrupt the file by modifying vector but not metadata
            data = np.load(filepath)
            corrupted_vector = data["vector"].copy()
            corrupted_vector[0] = 999.0
            
            np.savez_compressed(
                filepath,
                vector=corrupted_vector,
                metadata=data["metadata"]
            )
            
            with self.assertRaises(ValueError) as cm:
                deserialize_features(filepath)
            self.assertIn("integrity check failed", str(cm.exception).lower())
        finally:
            # Manual cleanup to avoid Windows file locking issues
            shutil.rmtree(tmpdir, ignore_errors=True)
    
    def test_metadata_validation_wrong_contract(self):
        """Test metadata validation rejects wrong contract."""
        vector = self.test_vector
        meta = create_ember_v2_metadata(vector)
        
        serializer = FeatureVectorSerializer(contract="ethio-v1")
        with self.assertRaises(ValueError) as cm:
            serializer._validate_vector(vector, meta)
        self.assertIn("Contract mismatch", str(cm.exception))
    
    def test_validate_file(self):
        """Test file validation without full load."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test.npz"
            serialize_features(vector, filepath, metadata=meta)
            
            serializer = FeatureVectorSerializer(contract="ember-v2")
            report = serializer.validate_file(filepath)
            
            self.assertTrue(report["valid"])
            self.assertEqual(report["vector_shape"], (2381,))
            self.assertEqual(report["vector_dtype"], "float32")
            self.assertIsNotNone(report["metadata"])
    
    def test_batch_serialization(self):
        """Test batch serialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vectors = {
                f"sample_{i}": np.random.rand(2381).astype(np.float32)
                for i in range(5)
            }
            
            results = serialize_batch(vectors, Path(tmpdir))
            
            self.assertEqual(len(results["success"]), 5)
            self.assertEqual(len(results["errors"]), 0)
            
            # Verify all files created
            for i in range(5):
                filepath = Path(tmpdir) / f"sample_{i}.npz"
                self.assertTrue(filepath.exists())
                
                loaded_vec, meta = deserialize_features(filepath)
                self.assertEqual(meta.feature_contract, "ember-v2")


class TestFeatureContractConstants(unittest.TestCase):
    """Test feature contract constants."""
    
    def test_total_dim_constant(self):
        self.assertEqual(EMBER_V2_TOTAL_DIM, 2381)
    
    def test_feature_groups_count(self):
        self.assertEqual(len(EMBER_V2_FEATURE_GROUPS), 9)
    
    def test_group_names(self):
        names = [g.name for g in EMBER_V2_FEATURE_GROUPS]
        expected = [
            "histogram", "byteentropy", "strings", "general",
            "header", "section", "imports", "exports", "datadirectories"
        ]
        self.assertEqual(names, expected)
    
    def test_group_dims(self):
        expected = {
            "histogram": 256,
            "byteentropy": 256,
            "strings": 104,
            "general": 10,
            "header": 62,
            "section": 255,
            "imports": 1280,
            "exports": 128,
            "datadirectories": 30,
        }
        for group in EMBER_V2_FEATURE_GROUPS:
            self.assertEqual(group.dim, expected[group.name])
    
    def test_sum_dims(self):
        total = sum(g.dim for g in EMBER_V2_FEATURE_GROUPS)
        self.assertEqual(total, 2381)


class TestDeterminism(unittest.TestCase):
    """Test deterministic extraction."""
    
    def setUp(self):
        self.extractor = EMBERFeatureExtractor()
    
    def test_repeated_extraction(self):
        """Repeated extraction of same bytes produces identical results."""
        test_bytes = b"MZ" + os.urandom(1000)
        
        results = []
        for _ in range(10):
            result = self.extractor.feature_vector(test_bytes)
            results.append(result)
        
        # All results should be identical
        for i in range(1, len(results)):
            np.testing.assert_array_equal(results[0], results[i])
    
    def test_serialization_roundtrip_deterministic(self):
        """Serialization round-trip is deterministic."""
        vector = np.random.rand(2381).astype(np.float32)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test.npz"
            
            # Serialize multiple times
            for _ in range(5):
                serialize_features(vector, filepath, metadata=meta)
                loaded_vec, _ = deserialize_features(filepath)
                np.testing.assert_array_equal(vector, loaded_vec)


class TestMalformedInputHandling(unittest.TestCase):
    """Test handling of malformed/truncated PE inputs."""
    
    def setUp(self):
        self.extractor = EMBERFeatureExtractor()
    
    def test_empty_input(self):
        """Empty input should return zero vector."""
        result = self.extractor.feature_vector(b"")
        self.assertEqual(result.shape[0], 2381)
        self.assertTrue(np.all(result == 0))
    
    def test_truncated_dos_header(self):
        """Truncated DOS header handled gracefully."""
        result = self.extractor.feature_vector(b"MZ")
        self.assertEqual(result.shape[0], 2381)
        # Should not crash
    
    def test_non_pe_input(self):
        """Non-PE input handled gracefully."""
        result = self.extractor.feature_vector(b"not a PE file at all")
        self.assertEqual(result.shape[0], 2381)
        # Should not crash
    
    def test_large_input(self):
        """Large input handled within limits."""
        # 10MB of random data
        large_input = os.urandom(10 * 1024 * 1024)
        result = self.extractor.feature_vector(large_input)
        self.assertEqual(result.shape[0], 2381)
    
    def test_mz_only(self):
        """Just MZ signature."""
        result = self.extractor.feature_vector(b"MZ")
        self.assertEqual(result.shape[0], 2381)


class TestEthioCustomFeatureBoundary(unittest.TestCase):
    """Tests for ETHIO custom feature boundary."""
    
    def test_ember_v2_contract_distinct_from_ethio(self):
        """EMBER v2 and ETHIO contracts are distinct."""
        serializer_ember = FeatureVectorSerializer(contract="ember-v2")
        serializer_ethio = FeatureVectorSerializer(contract="ethio-v1")
        
        self.assertNotEqual(
            serializer_ember.contract,
            serializer_ethio.contract
        )
        
        self.assertEqual(serializer_ember.contract, "ember-v2")
        self.assertEqual(serializer_ethio.contract, "ethio-v1")
    
    def test_embargo_v2_cannot_load_ethio(self):
        """EMBER v2 serializer rejects ethio-v1 artifacts."""
        vector = np.random.rand(100).astype(np.float32)
        meta = FeatureMetadata(
            feature_contract="ethio-v1",
            feature_version=1,
            schema_version="1.0",
            total_dim=100,
            dtype="float32",
            feature_groups=[],
            extractor_version="1.0.0",
            lief_version="1.0.0",
            sklearn_version="1.9.1",
            numpy_version="2.5.4",
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "test.npz"
            serialize_features(vector, filepath, metadata=meta, contract="ethio-v1")
            
            # Try to load with ember-v2 serializer - should fail
            with self.assertRaises(ValueError) as cm:
                deserialize_features(filepath, contract="ember-v2")
            self.assertIn("dimension", str(cm.exception).lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)