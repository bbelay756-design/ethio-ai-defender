"""
Feature Serialization for ETHIO-AI Defender ML Pipeline

Provides versioned serialization for EMBER v2 and custom feature vectors
with metadata validation and integrity checks.
"""

import json
import hashlib
import importlib.metadata
import numpy as np
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import warnings

try:
    import lief
except ImportError:
    lief = None


# Serialization format version
SERIALIZATION_VERSION = "1.0"
EMBER_FEATURE_VERSION = 2


@dataclass
class FeatureMetadata:
    """Metadata for serialized feature vectors."""
    # Feature contract
    feature_contract: str  # "ember-v2" or "ethio-v1"
    feature_version: int
    schema_version: str  # Serialization schema version
    
    # Feature vector properties
    total_dim: int
    dtype: str  # "float32"
    feature_groups: list  # List of group metadata
    
    # Extractor info
    extractor_version: str
    lief_version: str
    sklearn_version: str
    numpy_version: str
    
    # Provenance (optional)
    sample_sha256: Optional[str] = None
    extraction_timestamp: Optional[str] = None
    extraction_config: Optional[Dict[str, Any]] = None
    
    # Integrity
    vector_sha256: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'FeatureMetadata':
        return cls(**d)


class FeatureVectorSerializer:
    """
    Serializes and deserializes feature vectors with metadata validation.
    
    Uses NPZ format for efficient numerical array storage with JSON metadata.
    """
    
    # Supported feature contracts
    SUPPORTED_CONTRACTS = {
        "ember-v2": {
            "expected_dim": 2381,
            "feature_version": 2,
            "feature_groups": [
                "histogram", "byteentropy", "strings", "general",
                "header", "section", "imports", "exports", "datadirectories"
            ],
            "group_dims": {
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
        },
        "ethio-v1": {
            "expected_dim": None,  # Variable
            "feature_version": 1,
            "feature_groups": [],  # Custom
            "group_dims": {}
        }
    }
    
    def __init__(self, contract: str = "ember-v2"):
        """
        Initialize serializer for a specific feature contract.
        
        Args:
            contract: Feature contract identifier ("ember-v2" or "ethio-v1")
        """
        if contract not in self.SUPPORTED_CONTRACTS:
            raise ValueError(f"Unsupported feature contract: {contract}")
        
        self.contract = contract
        self.contract_spec = self.SUPPORTED_CONTRACTS[contract]
    
    def serialize(
        self,
        vector: np.ndarray,
        metadata: FeatureMetadata,
        output_path: Union[str, Path],
        compression: bool = True
    ) -> None:
        """
        Serialize feature vector with metadata to NPZ file.
        
        Args:
            vector: Feature vector (float32 array)
            metadata: Feature metadata
            output_path: Output file path
            compression: Use NPZ compression
        """
        # Validate before serialization
        self._validate_vector(vector, metadata)
        
        # Compute vector hash for integrity
        vector_bytes = vector.tobytes()
        vector_hash = hashlib.sha256(vector_bytes).hexdigest()
        metadata.vector_sha256 = vector_hash
        
        # Prepare metadata dict
        meta_dict = metadata.to_dict()
        
        # Write NPZ file
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if compression:
            np.savez_compressed(
                output_path,
                vector=vector.astype(np.float32),
                metadata=json.dumps(meta_dict, separators=(',', ':'))
            )
        else:
            np.savez(
                output_path,
                vector=vector.astype(np.float32),
                metadata=json.dumps(meta_dict, separators=(',', ':'))
            )
    
    def deserialize(self, input_path: Union[str, Path]) -> tuple:
        """
        Deserialize feature vector with metadata validation.
        
        Args:
            input_path: Path to NPZ file
            
        Returns:
            Tuple of (vector, FeatureMetadata)
            
        Raises:
            ValueError: If validation fails
            FileNotFoundError: If file not found
        """
        input_path = Path(input_path)
        if not input_path.exists():
            raise FileNotFoundError(f"Feature file not found: {input_path}")
        
        # Load NPZ
        try:
            data = np.load(input_path, allow_pickle=False)
        except Exception as e:
            raise ValueError(f"Failed to load NPZ file: {e}")
        
        # Extract vector and metadata
        if "vector" not in data:
            raise ValueError("NPZ file missing 'vector' array")
        if "metadata" not in data:
            raise ValueError("NPZ file missing 'metadata'")
        
        vector = data["vector"]
        meta_json = data["metadata"]
        
        if isinstance(meta_json, np.ndarray):
            meta_json = meta_json.item()
        elif isinstance(meta_json, bytes):
            meta_json = meta_json.decode('utf-8')
        
        try:
            meta_dict = json.loads(meta_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid metadata JSON: {e}")
        
        metadata = FeatureMetadata.from_dict(meta_dict)
        
        # Validate
        self._validate_vector(vector, metadata)
        
        # Verify integrity hash
        if metadata.vector_sha256:
            vector_hash = hashlib.sha256(vector.tobytes()).hexdigest()
            if vector_hash != metadata.vector_sha256:
                raise ValueError(
                    f"Vector integrity check failed: "
                    f"expected {metadata.vector_sha256}, got {vector_hash}"
                )
        
        return vector, metadata
    
    def _validate_vector(self, vector: np.ndarray, metadata: FeatureMetadata) -> None:
        """Validate feature vector against metadata and contract."""
        # Check dtype
        if vector.dtype != np.float32:
            raise ValueError(f"Vector dtype must be float32, got {vector.dtype}")
        
        # Check dimensions
        expected_dim = self.contract_spec.get("expected_dim")
        if expected_dim is not None and vector.shape[0] != expected_dim:
            raise ValueError(
                f"Dimension mismatch: expected {expected_dim}, got {vector.shape[0]}"
            )
        
        # Check metadata contract matches
        if metadata.feature_contract != self.contract:
            raise ValueError(
                f"Contract mismatch: serializer for '{self.contract}', "
                f"metadata has '{metadata.feature_contract}'"
            )
        
        # Check version
        if metadata.feature_version != self.contract_spec["feature_version"]:
            raise ValueError(
                f"Feature version mismatch: expected {self.contract_spec['feature_version']}, "
                f"got {metadata.feature_version}"
            )
        
        # Check dimension matches metadata
        if metadata.total_dim != vector.shape[0]:
            raise ValueError(
                f"Metadata dimension ({metadata.total_dim}) "
                f"doesn't match vector shape ({vector.shape[0]})"
            )
        
        # Check dtype
        if metadata.dtype != "float32":
            raise ValueError(f"Metadata dtype must be float32, got {metadata.dtype}")
        
        # Check for non-finite values
        if not np.all(np.isfinite(vector)):
            raise ValueError("Vector contains non-finite values (NaN or Inf)")
    
    def validate_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Validate a serialized feature file without loading full vector.
        
        Returns validation report.
        """
        path = Path(file_path)
        report = {
            "file": str(path),
            "exists": path.exists(),
            "valid": False,
            "errors": [],
            "warnings": [],
            "metadata": None,
            "vector_shape": None,
            "vector_dtype": None,
        }
        
        if not path.exists():
            report["errors"].append("File not found")
            return report
        
        try:
            data = np.load(path, allow_pickle=False)
            
            # Check required arrays
            if "vector" not in data:
                report["errors"].append("Missing 'vector' array")
            else:
                report["vector_shape"] = data["vector"].shape
                report["vector_dtype"] = str(data["vector"].dtype)
            
            if "metadata" not in data:
                report["errors"].append("Missing 'metadata'")
            else:
                meta_json = data["metadata"]
                if isinstance(meta_json, np.ndarray):
                    meta_json = meta_json.item()
                elif isinstance(meta_json, bytes):
                    meta_json = meta_json.decode('utf-8')
                
                try:
                    meta = json.loads(meta_json)
                    report["metadata"] = meta
                    
                    # Validate metadata
                    if meta.get("feature_contract") != self.contract:
                        report["warnings"].append(
                            f"Contract mismatch: expected {self.contract}, got {meta.get('feature_contract')}"
                        )
                    
                    # Check dimension match
                    if "vector" in data and "total_dim" in meta:
                        if data["vector"].shape[0] != meta["total_dim"]:
                            report["errors"].append(
                                f"Dimension mismatch: vector {data['vector'].shape[0]} vs metadata {meta['total_dim']}"
                            )
                    
                except json.JSONDecodeError as e:
                    report["errors"].append(f"Invalid metadata JSON: {e}")
            
            report["valid"] = len(report["errors"]) == 0
            
        except Exception as e:
            report["errors"].append(f"Failed to load file: {e}")
            report["valid"] = False
        
        return report


def get_serialize_metadata() -> Dict[str, str]:
    """Read installed package versions at runtime.

    Returns a dict with keys ``lief_version``, ``sklearn_version``,
    and ``numpy_version``.

    LIEF is an optional dependency: when it is not installed the
    corresponding field is set to the truthful marker ``"not-installed"``
    rather than a fabricated version string.

    scikit-learn and NumPy are required dependencies of the serialization
    and extraction pipeline.  If either is missing, ``PackageNotFoundError``
    is allowed to propagate so that the problem is not silently masked.
    """
    # LIEF — optional: truthful marker when absent
    try:
        lief_v = importlib.metadata.version("lief")
    except importlib.metadata.PackageNotFoundError:
        lief_v = "not-installed"

    # scikit-learn — required: let errors propagate
    sklearn_v = importlib.metadata.version("scikit-learn")

    # NumPy — required: let errors propagate
    numpy_v = importlib.metadata.version("numpy")

    return {
        "lief_version": lief_v,
        "sklearn_version": sklearn_v,
        "numpy_version": numpy_v,
    }


def _get_lief_version() -> str:
    """Backward-compatible wrapper returning only the LIEF version."""
    return get_serialize_metadata()["lief_version"]


def _get_sklearn_version() -> str:
    """Backward-compatible wrapper returning only the scikit-learn version."""
    return get_serialize_metadata()["sklearn_version"]


def _get_numpy_version() -> str:
    """Backward-compatible wrapper returning only the NumPy version."""
    return get_serialize_metadata()["numpy_version"]


def create_ember_v2_metadata(
    vector: np.ndarray,
    sample_sha256: Optional[str] = None,
    extractor_version: str = "1.0.0",
    extraction_config: Optional[Dict[str, Any]] = None
) -> FeatureMetadata:
    """Create metadata for EMBER v2 feature vector."""
    from datetime import datetime
    
    # Compute vector hash
    vector_hash = hashlib.sha256(vector.tobytes()).hexdigest()
    
    return FeatureMetadata(
        feature_contract="ember-v2",
        feature_version=2,
        schema_version="1.0",
        total_dim=vector.shape[0],
        dtype="float32",
        feature_groups=[
            {"name": "histogram", "dim": 256},
            {"name": "byteentropy", "dim": 256},
            {"name": "strings", "dim": 104},
            {"name": "general", "dim": 10},
            {"name": "header", "dim": 62},
            {"name": "section", "dim": 255},
            {"name": "imports", "dim": 1280},
            {"name": "exports", "dim": 128},
            {"name": "datadirectories", "dim": 30},
        ],
        extractor_version=extractor_version,
        **get_serialize_metadata(),
        sample_sha256=sample_sha256,
        extraction_timestamp=datetime.utcnow().isoformat() + "Z",
        extraction_config=extraction_config,
        vector_sha256=vector_hash,
    )


def serialize_features(
    vector: np.ndarray,
    output_path: Union[str, Path],
    contract: str = "ember-v2",
    metadata: Optional[FeatureMetadata] = None,
    compression: bool = True
) -> None:
    """Convenience function to serialize feature vector."""
    serializer = FeatureVectorSerializer(contract=contract)
    
    if metadata is None:
        metadata = create_ember_v2_metadata(vector)
    
    serializer.serialize(vector, metadata, output_path, compression)


def deserialize_features(
    input_path: Union[str, Path],
    contract: str = "ember-v2"
) -> tuple:
    """Convenience function to deserialize feature vector."""
    serializer = FeatureVectorSerializer(contract=contract)
    return serializer.deserialize(input_path)


# Convenience functions for batch operations
def serialize_batch(
    vectors: Dict[str, np.ndarray],
    output_dir: Union[str, Path],
    contract: str = "ember-v2",
    metadata_fn: Optional[callable] = None,
    compression: bool = True
) -> Dict[str, Any]:
    """
    Serialize multiple feature vectors.
    
    Args:
        vectors: Dict of sample_id -> feature vector
        output_dir: Output directory
        contract: Feature contract
        metadata_fn: Function(sample_id, vector) -> FeatureMetadata
        compression: Use compression
        
    Returns:
        Dict with results and any errors
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    serializer = FeatureVectorSerializer(contract=contract)
    results = {"success": [], "errors": []}
    
    for sample_id, vector in vectors.items():
        try:
            if metadata_fn:
                metadata = metadata_fn(sample_id, vector)
            else:
                metadata = create_ember_v2_metadata(vector)
            
            output_path = output_dir / f"{sample_id}.npz"
            serializer.serialize(vector, metadata, output_path, compression)
            results["success"].append(sample_id)
        except Exception as e:
            results["errors"].append({"sample_id": sample_id, "error": str(e)})
    
    return results