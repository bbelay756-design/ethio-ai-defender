"""
EMBER Baseline Model Classifier Service for ETHIO-AI Defender.

Provides a decoupled, verified interface for offline machine learning inference:
- Cryptographic SHA-256 verification against a trusted configured digest prior to unpickling.
- Strict isolation from untrusted upload paths and user-controlled directories.
- Comprehensive metadata, feature schema (2,381 dims, v2), and class label validation.
- Dynamic positive-class probability indexing via estimator `classes_` attribute.
- Defensive input validation (dimension, dtype, finiteness, bounded batch size).
- Typed prediction results including calibrated operational threshold decisions.
- Zero mutation of production database state or deterministic analyzer verdicts.
"""

import hashlib
import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import joblib
import numpy as np

from app.core.config import BASE_DIR
from app.core.logger import logger
from app.ml.ember_v2 import EMBERFeatureExtractor, EMBER_V2_TOTAL_DIM

# Cryptographically verified trusted baseline model SHA-256 digest
TRUSTED_BASELINE_MODEL_SHA256 = "f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684"

# Default primary and fallback approved artifact storage directories
DEFAULT_PRIMARY_MODEL_DIR = Path(r"D:\ethio_ai_defender_artifacts\ember_baseline_v1")
DEFAULT_SECONDARY_MODEL_DIR = BASE_DIR / "storage" / "models" / "ember_baseline_v1"

# Approved base directories permitted for model loading
APPROVED_BASE_DIRS = [
    Path(r"D:\ethio_ai_defender_artifacts"),
    BASE_DIR / "storage" / "models",
]

# Explicitly forbidden path substrings (uploads, quarantine, and user-controlled areas)
FORBIDDEN_PATH_SEGMENTS = {"uploads", "quarantine", "user_data"}

# Maximum supported batch size for offline inference to bound resource consumption
MAX_INFERENCE_BATCH_SIZE = 1000


class EmberModelError(ValueError):
    """Raised when model artifact loading, verification, or inference fails."""
    pass


@dataclass(frozen=True)
class ClassifierPredictionResult:
    """
    Typed, immutable prediction outcome for single-sample inference.
    Supports both attribute and dictionary-style access for backwards compatibility.
    """
    malicious_score: float
    is_malicious: bool
    is_malicious_1pct_fpr: bool
    is_malicious_01pct_fpr: bool
    active_threshold: float
    thresholds: Dict[str, float]
    model_name: str
    model_version: str
    model_sha256: str
    feature_dim: int

    @property
    def malicious_probability(self) -> float:
        """Alias for malicious_score for backwards compatibility."""
        return self.malicious_score

    def __getitem__(self, item: str) -> Any:
        if item == "malicious_probability":
            return self.malicious_score
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def __contains__(self, item: str) -> bool:
        return item == "malicious_probability" or hasattr(self, item)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation."""
        res = asdict(self)
        res["malicious_probability"] = self.malicious_score
        return res


class EmberModelClassifier:
    """
    Decoupled inference service for EMBER baseline gradient-boosted decision tree classifier.
    Strictly isolated for controlled offline testing.
    """

    def __init__(
        self,
        model_dir: Optional[Union[str, Path]] = None,
        verify_checksum: bool = True,
        trusted_sha256: Optional[str] = None,
        allow_custom_path: bool = False,
    ) -> None:
        """
        Initialize and load the trained baseline model from model_dir.

        Args:
            model_dir: Directory containing model.joblib, model.joblib.sha256, metadata.json.
                       Defaults to primary approved artifact path or secondary repository path.
            verify_checksum: If True, enforces SHA-256 integrity match before deserialization.
            trusted_sha256: Expected cryptographic digest. If None, uses TRUSTED_BASELINE_MODEL_SHA256
                            or the ETHIO_ML_TRUSTED_MODEL_SHA256 environment variable.
            allow_custom_path: If True, permits non-standard directories (used strictly in test fixtures).
        """
        # Resolve target model directory
        if model_dir is None:
            if DEFAULT_PRIMARY_MODEL_DIR.exists():
                self.model_dir = DEFAULT_PRIMARY_MODEL_DIR
            else:
                self.model_dir = DEFAULT_SECONDARY_MODEL_DIR
        else:
            self.model_dir = Path(model_dir).resolve()

        self.allow_custom_path = allow_custom_path
        self._validate_path_security(self.model_dir, allow_custom_path=allow_custom_path)

        self.model_path = self.model_dir / "model.joblib"
        self.checksum_path = self.model_dir / "model.joblib.sha256"
        self.metadata_path = self.model_dir / "metadata.json"

        # Resolve trusted authority digest
        configured_sha = (
            trusted_sha256
            or os.getenv("ETHIO_ML_TRUSTED_MODEL_SHA256", None)
        )
        if configured_sha:
            self.trusted_sha256 = configured_sha.strip().lower()
        elif allow_custom_path:
            # In test mode with custom path, read from sidecar or allow caller injection
            if self.checksum_path.exists():
                raw = self.checksum_path.read_text(encoding="utf-8").strip().lower()
                self.trusted_sha256 = raw.split()[0] if raw else ""
            else:
                self.trusted_sha256 = ""
        else:
            self.trusted_sha256 = TRUSTED_BASELINE_MODEL_SHA256.lower()

        self.model: Optional[Any] = None
        self.metadata: Dict[str, Any] = {}
        self.model_file_sha256: str = ""
        self._malicious_class_index: int = 1
        self.extractor = EMBERFeatureExtractor(feature_version=2, print_warning=False)

        if self.model_path.exists():
            self._load_model(verify_checksum=verify_checksum)

    def _validate_path_security(self, path: Path, allow_custom_path: bool = False) -> None:
        """
        Validate that the model directory is in an approved location and not inside
        an upload, quarantine, or user-controlled directory.
        """
        path_str = str(path).lower().replace("\\", "/")
        path_parts = set(p.lower() for p in path.parts)

        # Strictly prohibit loading models from user-controlled or upload directories
        for forbidden in FORBIDDEN_PATH_SEGMENTS:
            if forbidden in path_parts or f"/{forbidden}/" in path_str:
                raise EmberModelError(
                    f"Security violation: Loading models from '{forbidden}' directory is prohibited: {path}"
                )

        if allow_custom_path:
            return

        # Verify path resides under an approved base directory
        is_approved = False
        for base in APPROVED_BASE_DIRS:
            try:
                base_resolved = base.resolve()
                if path == base_resolved or base_resolved in path.parents:
                    is_approved = True
                    break
            except Exception:
                continue

        if not is_approved:
            raise EmberModelError(
                f"Model directory '{path}' is not in approved allowlist. "
                f"Approved base paths: {[str(b) for b in APPROVED_BASE_DIRS]}"
            )

    def _load_model(self, verify_checksum: bool = True) -> None:
        """
        Verify checksum and load serialized joblib model.
        Fails closed on any corruption, mismatch, or validation failure.
        """
        if not self.model_path.exists():
            raise EmberModelError(f"Model file not found: {self.model_path}")

        # Compute file SHA-256
        hasher = hashlib.sha256()
        with open(self.model_path, "rb") as f:
            while chunk := f.read(1048576):
                hasher.update(chunk)
        computed_sha = hasher.hexdigest().lower()
        self.model_file_sha256 = computed_sha

        # Integrity verification
        if verify_checksum:
            if not self.trusted_sha256:
                if not self.checksum_path.exists():
                    raise EmberModelError(
                        f"Checksum file missing: {self.checksum_path}. "
                        "Unverified model loading is prohibited."
                    )
                raw = self.checksum_path.read_text(encoding="utf-8").strip().lower()
                self.trusted_sha256 = raw.split()[0] if raw else ""

            # Check computed hash against expected authority digest
            if computed_sha != self.trusted_sha256:
                raise EmberModelError(
                    f"Model SHA-256 checksum mismatch! Expected {self.trusted_sha256}, "
                    f"computed {computed_sha}. Model artifact may be corrupted or tampered."
                )

            # Check sidecar checksum file if present (do not trust sidecar alone as sole authority)
            if self.checksum_path.exists():
                sidecar_text = self.checksum_path.read_text(encoding="utf-8").strip().lower()
                sidecar_sha = sidecar_text.split()[0] if sidecar_text else ""
                if sidecar_sha != self.trusted_sha256:
                    raise EmberModelError(
                        f"Sidecar checksum tampering detected! "
                        f"Sidecar specifies {sidecar_sha}, but trusted authority requires {self.trusted_sha256}."
                    )

        # Load and validate metadata
        if self.metadata_path.exists():
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            except Exception as e:
                raise EmberModelError(f"Malformed metadata JSON in {self.metadata_path}: {e}") from e
            self._validate_metadata(self.metadata)
        else:
            self.metadata = {}

        # Safely deserialize model
        try:
            loaded_estimator = joblib.load(self.model_path)
        except Exception as e:
            raise EmberModelError(f"Failed to deserialize model artifact: {e}") from e

        # Validate estimator interface and class mapping
        if not hasattr(loaded_estimator, "predict_proba"):
            raise EmberModelError("Deserialized model does not implement 'predict_proba'.")

        if not hasattr(loaded_estimator, "classes_"):
            raise EmberModelError("Deserialized model missing required 'classes_' attribute.")

        classes = list(loaded_estimator.classes_)
        if 1 not in classes:
            raise EmberModelError(
                f"Malicious class (1) not found in estimator classes: {classes}. "
                "Inference mapping is invalid."
            )
        self._malicious_class_index = classes.index(1)

        self.model = loaded_estimator
        logger.info(
            f"Successfully loaded and verified EmberModelClassifier from {self.model_dir} "
            f"(SHA-256: {computed_sha}, malicious class index: {self._malicious_class_index})"
        )

    def _validate_metadata(self, metadata: Dict[str, Any]) -> None:
        """
        Validate model metadata contract against EMBER v2 specifications.
        """
        dataset_meta = metadata.get("dataset", {})
        if "feature_dim" in dataset_meta:
            meta_dim = dataset_meta["feature_dim"]
            if meta_dim != EMBER_V2_TOTAL_DIM:
                raise EmberModelError(
                    f"Metadata specifies incompatible feature_dim {meta_dim}; expected {EMBER_V2_TOTAL_DIM}"
                )

        if "feature_version" in dataset_meta:
            meta_ver = dataset_meta["feature_version"]
            if meta_ver != 2:
                raise EmberModelError(
                    f"Metadata specifies incompatible feature_version {meta_ver}; expected 2"
                )

    @property
    def is_loaded(self) -> bool:
        """Returns True if a model has been successfully loaded and verified."""
        return self.model is not None

    @property
    def calibrated_thresholds(self) -> Dict[str, float]:
        """Extract calibrated decision thresholds from metadata."""
        thresholds = {"default": 0.5}
        cal_data = self.metadata.get("calibrated_thresholds", {})

        # Support both ML-04 calibration schemas (fpr_1pct_target and fpr_0_01)
        if "fpr_1pct_target" in cal_data:
            thresholds["1pct_fpr"] = float(cal_data["fpr_1pct_target"]["threshold"])
        elif "fpr_0_01" in cal_data:
            thresholds["1pct_fpr"] = float(cal_data["fpr_0_01"]["calibrated_threshold"])

        if "fpr_01pct_target" in cal_data:
            thresholds["01pct_fpr"] = float(cal_data["fpr_01pct_target"]["threshold"])
        elif "fpr_0_001" in cal_data:
            thresholds["01pct_fpr"] = float(cal_data["fpr_0_001"]["calibrated_threshold"])

        if "default_05" in cal_data:
            thresholds["default"] = float(cal_data["default_05"]["threshold"])

        return thresholds

    def validate_features(self, X: np.ndarray) -> np.ndarray:
        """
        Validate feature vector dimension, type, finiteness, and batch size.

        Args:
            X: Input array of shape (N, 2381) or (2381,).

        Returns:
            Validated float32 numpy array with shape (N, 2381).

        Raises:
            EmberModelError: If shape is malformed, batch size exceeded, or contains NaN/Inf.
        """
        try:
            arr = np.asarray(X, dtype=np.float32)
        except Exception as e:
            raise EmberModelError(f"Cannot cast feature input to float32 array: {e}") from e

        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        elif arr.ndim != 2:
            raise EmberModelError(f"Expected 1D or 2D feature array, received shape {arr.shape}")

        if arr.shape[0] > MAX_INFERENCE_BATCH_SIZE:
            raise EmberModelError(
                f"Batch size {arr.shape[0]} exceeds maximum supported limit of {MAX_INFERENCE_BATCH_SIZE}"
            )

        if arr.shape[1] != EMBER_V2_TOTAL_DIM:
            raise EmberModelError(
                f"Feature vector dimension mismatch: expected {EMBER_V2_TOTAL_DIM}, received {arr.shape[1]}"
            )

        if not np.all(np.isfinite(arr)):
            raise EmberModelError("Feature vector contains non-finite values (NaN or Inf).")

        return arr

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Predict probability of being malicious for input feature vector(s).
        Dynamically uses the malicious-class index discovered from estimator.classes_.

        Args:
            X: Feature array of shape (N, 2381) or (2381,).

        Returns:
            1D array of malicious probabilities in [0.0, 1.0].
        """
        if not self.is_loaded:
            raise EmberModelError("Model is not loaded. Cannot perform inference.")

        validated_X = self.validate_features(X)
        try:
            proba = self.model.predict_proba(validated_X)
        except Exception as e:
            raise EmberModelError(f"Inference execution failed: {e}") from e

        return proba[:, self._malicious_class_index].astype(np.float64)

    def predict(self, X: np.ndarray, threshold: Optional[float] = None) -> np.ndarray:
        """
        Predict binary label (0=benign, 1=malicious) at given threshold.

        Args:
            X: Feature array of shape (N, 2381) or (2381,).
            threshold: Decision threshold. Defaults to 1% FPR threshold if calibrated, else 0.5.

        Returns:
            1D array of integer predictions (0 or 1).
        """
        if threshold is None:
            threshold = self.calibrated_thresholds.get("1pct_fpr", 0.5)

        probs = self.predict_proba(X)
        return (probs >= threshold).astype(np.int32)

    def predict_single(
        self,
        features: np.ndarray,
        threshold: Optional[float] = None,
    ) -> ClassifierPredictionResult:
        """
        Run inference on a single 2,381-dimensional feature vector and return a typed result.

        Args:
            features: 1D array of 2,381 float32 features.
            threshold: Optional custom decision threshold.

        Returns:
            Typed ClassifierPredictionResult instance.
        """
        probs = self.predict_proba(features)
        prob = float(probs[0])

        thresholds = self.calibrated_thresholds
        tau_1pct = thresholds.get("1pct_fpr", 0.5)
        tau_01pct = thresholds.get("01pct_fpr", 0.8)

        active_threshold = threshold if threshold is not None else tau_1pct
        is_malicious = prob >= active_threshold

        return ClassifierPredictionResult(
            malicious_score=prob,
            is_malicious=bool(is_malicious),
            is_malicious_1pct_fpr=bool(prob >= tau_1pct),
            is_malicious_01pct_fpr=bool(prob >= tau_01pct),
            active_threshold=float(active_threshold),
            thresholds=thresholds,
            model_name=self.metadata.get("model_name", "ember-baseline-hgb"),
            model_version=self.metadata.get("model_version", "1.0.0"),
            model_sha256=self.model_file_sha256,
            feature_dim=EMBER_V2_TOTAL_DIM,
        )

    def predict_pe_bytes(
        self,
        bytez: bytes,
        threshold: Optional[float] = None,
    ) -> ClassifierPredictionResult:
        """
        Run inference on raw PE bytes via the EMBERFeatureExtractor.

        Note: Feature extraction from raw PE bytes is subject to the parity limitations
        documented in ML-06. Predictions should be evaluated for offline research only.

        Args:
            bytez: Raw binary bytes of the PE sample.
            threshold: Optional custom decision threshold.

        Returns:
            Typed ClassifierPredictionResult instance.
        """
        if not bytez:
            raise EmberModelError("Empty byte buffer supplied for PE inference.")

        try:
            features = self.extractor.feature_vector(bytez)
        except Exception as e:
            raise EmberModelError(f"Raw PE feature extraction failed: {e}") from e

        return self.predict_single(features, threshold=threshold)
