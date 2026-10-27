"""
Tests for Feature Serialization Module
"""

import unittest
import tempfile
import json
import numpy as np
import hashlib
from pathlib import Path
import sys
import os

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.ml.serialize import (
    FeatureVectorSerializer,
    FeatureMetadata,
    create_ember_v2_metadata,
    serialize_features,
    deserialize_features,
    serialize_batch,
)


class TestFeatureMetadata(unittest.TestCase):
    """Test FeatureMetadata dataclass."""
    
    def test_creation(self):
        meta = FeatureMetadata(
            feature_contract="ember-v2",
            feature_version=2,
            schema_version="1.0",
            total_dim=2381,
            dtype="float32",
            feature_groups=[{"name": "test", "dim": 10}],
            extractor_version="1.0.0",
            lief_version="1.0.0",
            sklearn_version="1.9.1",
            numpy_version="2.5.4",
        )
        self.assertEqual(meta.feature_contract, "ember-v2")
        self.assertEqual(meta.feature_version, 2)
    
    def test_to_from_dict(self):
        meta = FeatureMetadata(
            feature_contract="ember-v2",
            feature_version=2,
            schema_version="1.0",
            total_dim=2381,
            dtype="float32",
            feature_groups=[],
            extractor_version="1.0.0",
            lief_version="1.0.0",
            sklearn_version="1.9.1",
            numpy_version="2.5.4",
        )
        
        d = meta.to_dict()
        self.assertEqual(d["feature_contract"], "ember-v2")
        
        meta2 = FeatureMetadata.from_dict(d)
        self.assertEqual(meta2.feature_contract, "ember-v2")


class TestFeatureVectorSerializer(unittest.TestCase):
    """Test FeatureVectorSerializer class."""
    
    def setUp(self):
        self.serializer = FeatureVectorSerializer(contract="ember-v2")
        self.test_vector = np.random.rand(2381).astype(np.float32)
        np.random.seed(42)
        self.test_vector = np.random.rand(2381).astype(np.float32)
    
    def test_init_valid_contract(self):
        serializer = FeatureVectorSerializer(contract="ember-v2")
        self.assertEqual(serializer.contract, "ember-v2")
        
        serializer = FeatureVectorSerializer(contract="ethio-v1")
        self.assertEqual(serializer.contract, "ethio-v1")
    
    def test_init_invalid_contract(self):
        with self.assertRaises(ValueError):
            FeatureVectorSerializer(contract="invalid-contract")
    
    def test_validate_vector_valid(self):
        meta = FeatureMetadata(
            feature_contract="ember-v2",
            feature_version=2,
            schema_version="1.0",
            total_dim=2381,
            dtype="float32",
            feature_groups=[],
            extractor_version="1.0.0",
            lief_version="1.0.0",
            sklearn_version="1.9.1",
            numpy_version="2.5.4",
        )
        
        vector = np.random.rand(2381).astype(np.float32)
        self.serializer._validate_vector(vector, meta)  # Should not raise
    
    def test_validate_vector_wrong_contract(self):
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
        
        vector = np.random.rand(2381).astype(np.float32)
        with self.assertRaises(ValueError) as cm:
            self.serializer._validate_vector(vector, meta)
        self.assertIn("Contract mismatch", str(cm.exception))
    
    def test_validate_vector_wrong_dim(self):
        meta = FeatureMetadata(
            feature_contract="ember-v2",
            feature_version=2,
            schema_version="1.0",
            total_dim=1000,  # Wrong
            dtype="float32",
            feature_groups=[],
            extractor_version="1.0.0",
            lief_version="1.0.0",
            sklearn_version="1.9.1",
            numpy_version="2.5.4",
        )
        
        vector = np.random.rand(2381).astype(np.float32)
        with self.assertRaises(ValueError) as cm:
            self.serializer._validate_vector(vector, meta)
        self.assertIn("dimension", str(cm.exception).lower())
    
    def test_validate_vector_wrong_dtype(self):
        meta = FeatureMetadata(
            feature_contract="ember-v2",
            feature_version=2,
            schema_version="1.0",
            total_dim=2381,
            dtype="float32",
            feature_groups=[],
            extractor_version="1.0.0",
            lief_version="1.0.0",
            sklearn_version="1.9.1",
            numpy_version="2.5.4",
        )
        
        vector = np.random.rand(2381).astype(np.float64)  # Wrong dtype
        with self.assertRaises(ValueError) as cm:
            self.serializer._validate_vector(vector, meta)
        self.assertIn("dtype must be float32", str(cm.exception))
    
    def test_validate_vector_non_finite(self):
        meta = FeatureMetadata(
            feature_contract="ember-v2",
            feature_version=2,
            schema_version="1.0",
            total_dim=2381,
            dtype="float32",
            feature_groups=[],
            extractor_version="1.0.0",
            lief_version="1.0.0",
            sklearn_version="1.9.1",
            numpy_version="2.5.4",
        )
        
        vector = np.random.rand(2381).astype(np.float32)
        vector[0] = np.nan
        with self.assertRaises(ValueError) as cm:
            self.serializer._validate_vector(vector, meta)
        self.assertIn("non-finite", str(cm.exception).lower())
    
    def test_validate_vector_inf(self):
        meta = FeatureMetadata(
            feature_contract="ember-v2",
            feature_version=2,
            schema_version="1.0",
            total_dim=2381,
            dtype="float32",
            feature_groups=[],
            extractor_version="1.0.0",
            lief_version="1.0.0",
            sklearn_version="1.9.1",
            numpy_version="2.5.4",
        )
        
        vector = np.random.rand(2381).astype(np.float32)
        vector[0] = np.inf
        with self.assertRaises(ValueError) as cm:
            self.serializer._validate_vector(vector, meta)
        self.assertIn("non-finite", str(cm.exception).lower())


class TestSerializeDeserialize(unittest.TestCase):
    """Integration tests for serialize/deserialize."""
    
    def setUp(self):
        np.random.seed(42)
        self.test_vector = np.random.rand(2381).astype(np.float32)
    
    def test_serialize_deserialize_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test.npz"
            
            serialize_features(vector, filepath, metadata=meta)
            loaded_vector, loaded_meta = deserialize_features(filepath)
            
            np.testing.assert_array_equal(vector, loaded_vector)
            self.assertEqual(loaded_meta.feature_contract, "ember-v2")
            self.assertEqual(loaded_meta.total_dim, 2381)
    
    def test_serialize_with_compression(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test.npz"
            
            serialize_features(vector, filepath, metadata=meta, compression=True)
            loaded_vector, loaded_meta = deserialize_features(filepath)
            
            np.testing.assert_array_equal(vector, loaded_vector)
    
    def test_serialize_without_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector
            filepath = Path(tmpdir) / "test.npz"
            
            serialize_features(vector, filepath)
            loaded_vector, loaded_meta = deserialize_features(filepath)
            
            np.testing.assert_array_equal(vector, loaded_vector)
            self.assertEqual(loaded_meta.feature_contract, "ember-v2")
    
    def test_deserialize_wrong_contract(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test.npz"
            serialize_features(vector, filepath, metadata=meta)
            
            with self.assertRaises(ValueError) as cm:
                deserialize_features(filepath, contract="ethio-v1")
            self.assertIn("Contract mismatch", str(cm.exception))
    
    def test_deserialize_dimension_mismatch(self):
        """Test rejection of wrong dimension."""
        import shutil
        tmpdir = tempfile.mkdtemp()
        try:
            vector = self.test_vector
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test.npz"
            serialize_features(vector, filepath, metadata=meta)
            
            # Corrupt metadata
            data = np.load(filepath)
            meta_json = data["metadata"]
            if isinstance(meta_json, np.ndarray):
                meta_json = meta_json.item()
            meta_dict = json.loads(meta_json)
            meta_dict["total_dim"] = 1000
            
            np.savez_compressed(
                filepath,
                vector=data["vector"],
                metadata=json.dumps(meta_dict)
            )
            
            with self.assertRaises(ValueError) as cm:
                deserialize_features(filepath)
            self.assertIn("dimension", str(cm.exception).lower())
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
    
    def test_deserialize_nan(self):
        """Test rejection of NaN values - validation happens at serialize time."""
        vector = self.test_vector.copy()
        vector[0] = np.nan
        meta = create_ember_v2_metadata(vector)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "test.npz"
            
            # Validation happens at serialize time
            with self.assertRaises(ValueError) as cm:
                serialize_features(vector, filepath, metadata=meta)
            self.assertIn("non-finite", str(cm.exception).lower())
    
    def test_deserialize_inf(self):
        """Test rejection of infinite values - validation happens at serialize time."""
        vector = self.test_vector.copy()
        vector[0] = np.inf
        meta = create_ember_v2_metadata(vector)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "test.npz"
            
            # Validation happens at serialize time
            with self.assertRaises(ValueError) as cm:
                serialize_features(vector, filepath, metadata=meta)
            self.assertIn("non-finite", str(cm.exception).lower())
    
    def test_deserialize_wrong_dtype(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vector = self.test_vector.astype(np.float64)
            meta = create_ember_v2_metadata(self.test_vector)
            filepath = Path(tmpdir) / "test.npz"
            
            meta_dict = create_ember_v2_metadata(self.test_vector).to_dict()
            np.savez_compressed(
                filepath,
                vector=vector,  # float64
                metadata=json.dumps(meta_dict)
            )
            
            with self.assertRaises(ValueError) as cm:
                deserialize_features(filepath)
            self.assertIn("dtype must be float32", str(cm.exception))
    
    def test_integrity_hash(self):
        """Test integrity hash verification on deserialize."""
        import shutil
        tmpdir = tempfile.mkdtemp()
        try:
            vector = self.test_vector
            meta = create_ember_v2_metadata(vector)
            filepath = Path(tmpdir) / "test.npz"
            serialize_features(vector, filepath, metadata=meta)
            
            # Corrupt vector but not metadata
            data = np.load(filepath)
            corrupted = data["vector"].copy()
            corrupted[0] = 999.0
            
            np.savez_compressed(
                filepath,
                vector=corrupted,
                metadata=data["metadata"]
            )
            
            with self.assertRaises(ValueError) as cm:
                deserialize_features(filepath)
            self.assertIn("integrity", str(cm.exception).lower())
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
    
    def test_validate_file(self):
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


class TestBatchSerialization(unittest.TestCase):
    """Test batch serialization."""
    
    def setUp(self):
        np.random.seed(42)
        self.vectors = {
            f"sample_{i}": np.random.rand(2381).astype(np.float32)
            for i in range(3)
        }
    
    def test_serialize_batch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results = serialize_batch(self.vectors, Path(tmpdir))
            
            self.assertEqual(len(results["success"]), 3)
            self.assertEqual(len(results["errors"]), 0)
            
            # Verify all files created
            for i in range(3):
                filepath = Path(tmpdir) / f"sample_{i}.npz"
                self.assertTrue(filepath.exists())
                
                loaded_vec, meta = deserialize_features(filepath)
                self.assertEqual(meta.feature_contract, "ember-v2")


class TestEdgeCases(unittest.TestCase):
    """Edge case tests."""
    
    def test_empty_vector_rejected(self):
        serializer = FeatureVectorSerializer(contract="ember-v2")
        vector = np.array([], dtype=np.float32)
        meta = FeatureMetadata(
            feature_contract="ember-v2",
            feature_version=2,
            schema_version="1.0",
            total_dim=0,
            dtype="float32",
            feature_groups=[],
            extractor_version="1.0.0",
            lief_version="1.0.0",
            sklearn_version="1.9.1",
            numpy_version="2.5.4",
        )
        
        with self.assertRaises(ValueError) as cm:
            serializer._validate_vector(vector, meta)
        self.assertIn("Dimension mismatch", str(cm.exception))
    
    def test_negative_dimension_rejected(self):
        serializer = FeatureVectorSerializer(contract="ember-v2")
        meta = FeatureMetadata(
            feature_contract="ember-v2",
            feature_version=2,
            schema_version="1.0",
            total_dim=-1,
            dtype="float32",
            feature_groups=[],
            extractor_version="1.0.0",
            lief_version="1.0.0",
            sklearn_version="1.9.1",
            numpy_version="2.5.4",
        )
        
        vector = np.array([], dtype=np.float32)
        with self.assertRaises(ValueError):
            serializer._validate_vector(vector, meta)


class TestRuntimeMetadata(unittest.TestCase):
    """Tests for runtime dependency-version metadata (C8)."""

    def test_installed_versions_reported(self):
        """Verify get_serialize_metadata returns actual installed versions."""
        import importlib.metadata
        from app.ml.serialize import get_serialize_metadata

        result = get_serialize_metadata()

        # LIEF may or may not be installed
        try:
            expected_lief = importlib.metadata.version("lief")
        except importlib.metadata.PackageNotFoundError:
            expected_lief = "not-installed"

        expected_sklearn = importlib.metadata.version("scikit-learn")
        expected_numpy = importlib.metadata.version("numpy")

        self.assertEqual(result["lief_version"], expected_lief)
        self.assertEqual(result["sklearn_version"], expected_sklearn)
        self.assertEqual(result["numpy_version"], expected_numpy)

    def test_missing_lief_only_affects_lief_field(self):
        """Verify a missing LIEF affects only lief_version, not other fields."""
        import importlib.metadata
        from app.ml.serialize import get_serialize_metadata

        original_version = importlib.metadata.version

        def fake_version(dist_name):
            if dist_name == "lief":
                raise importlib.metadata.PackageNotFoundError(dist_name)
            return original_version(dist_name)

        import app.ml.serialize as serialize_mod
        monkeypatch = None
        # Use unittest.mock to patch
        from unittest.mock import patch
        with patch.object(importlib.metadata, "version", side_effect=fake_version):
            result = get_serialize_metadata()

        self.assertEqual(result["lief_version"], "not-installed")
        # Other fields should still reflect real installed versions
        self.assertEqual(result["sklearn_version"], original_version("scikit-learn"))
        self.assertEqual(result["numpy_version"], original_version("numpy"))

    def test_missing_sklearn_propagates_error(self):
        """Verify missing scikit-learn raises PackageNotFoundError (not masked)."""
        import importlib.metadata
        from unittest.mock import patch

        def fake_version(dist_name):
            if dist_name == "scikit-learn":
                raise importlib.metadata.PackageNotFoundError(dist_name)
            return "1.0.0" if dist_name == "lief" else "2.0.0"

        from app.ml.serialize import get_serialize_metadata
        with patch.object(importlib.metadata, "version", side_effect=fake_version):
            with self.assertRaises(importlib.metadata.PackageNotFoundError):
                get_serialize_metadata()

    def test_missing_numpy_propagates_error(self):
        """Verify missing NumPy raises PackageNotFoundError (not masked)."""
        import importlib.metadata
        from unittest.mock import patch

        def fake_version(dist_name):
            if dist_name == "numpy":
                raise importlib.metadata.PackageNotFoundError(dist_name)
            return "1.0.0" if dist_name == "lief" else "1.9.0"

        from app.ml.serialize import get_serialize_metadata
        with patch.object(importlib.metadata, "version", side_effect=fake_version):
            with self.assertRaises(importlib.metadata.PackageNotFoundError):
                get_serialize_metadata()

    def test_serialization_preserves_runtime_versions(self):
        """Verify serialization/deserialization preserves runtime version fields."""
        import tempfile
        from pathlib import Path
        import numpy as np
        from app.ml.serialize import serialize_features, deserialize_features, create_ember_v2_metadata

        vector = np.random.rand(2381).astype(np.float32)
        np.random.seed(42)
        vector = np.random.rand(2381).astype(np.float32)

        meta = create_ember_v2_metadata(vector)
        expected_lief = meta.lief_version
        expected_sklearn = meta.sklearn_version
        expected_numpy = meta.numpy_version

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "test_runtime.npz"
            serialize_features(vector, filepath, metadata=meta)

            loaded_vector, loaded_meta = deserialize_features(filepath)

            self.assertEqual(loaded_meta.lief_version, expected_lief)
            self.assertEqual(loaded_meta.sklearn_version, expected_sklearn)
            self.assertEqual(loaded_meta.numpy_version, expected_numpy)
            np.testing.assert_array_equal(vector, loaded_vector)

    def test_create_ember_v2_metadata_uses_runtime_versions(self):
        """Verify create_ember_v2_metadata uses get_serialize_metadata."""
        import numpy as np
        from app.ml.serialize import create_ember_v2_metadata, get_serialize_metadata

        vector = np.random.rand(2381).astype(np.float32)
        meta = create_ember_v2_metadata(vector)
        runtime = get_serialize_metadata()

        self.assertEqual(meta.lief_version, runtime["lief_version"])
        self.assertEqual(meta.sklearn_version, runtime["sklearn_version"])
        self.assertEqual(meta.numpy_version, runtime["numpy_version"])

    def test_missing_lief_marker_is_schema_compatible(self):
        """Verify 'not-installed' marker is a valid string for the schema."""
        import importlib.metadata
        from unittest.mock import patch
        from app.ml.serialize import get_serialize_metadata

        def fake_version(dist_name):
            if dist_name == "lief":
                raise importlib.metadata.PackageNotFoundError(dist_name)
            return "1.9.0" if dist_name == "scikit-learn" else "2.5.2"

        with patch.object(importlib.metadata, "version", side_effect=fake_version):
            result = get_serialize_metadata()

        self.assertEqual(result["lief_version"], "not-installed")
        self.assertIsInstance(result["lief_version"], str)
        self.assertEqual(result["sklearn_version"], "1.9.0")
        self.assertEqual(result["numpy_version"], "2.5.2")


if __name__ == "__main__":
    unittest.main(verbosity=2)