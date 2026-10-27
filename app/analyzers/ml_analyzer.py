"""
Module 19b: EMBER Machine Learning Offline Static Analyzer

Responsibility:
Performs controlled offline machine learning static evaluation of Windows PE binaries
and pre-extracted EMBER v2 feature vectors using the verified HistGradientBoostingClassifier.

Safety & Isolation Guarantees:
- Strictly static in-memory analysis; never executes uploaded samples.
- Isolated from production blocking policy; does not alter threat scores or deterministic verdicts.
- Enforces explicit feature schema compatibility checks between raw-PE extraction and training schema.
- Flags raw PE predictions as unverified parity, preventing automated blocking claims.
- Graceful degradation: failure (missing model, bad digest, corrupted vector) returns explicit
  UNAVAILABLE or FAILED status, never silently benign.
- Strictly sanitized user-facing errors (no secret or internal path leakage).
"""

import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Optional, Union

import numpy as np

from app.core.config import BASE_DIR, settings
from app.core.logger import logger
from app.ml.classifier import (
    EmberModelClassifier,
    EmberModelError,
    ClassifierPredictionResult,
)
from app.ml.ember_v2 import EMBERFeatureExtractor, EMBER_V2_TOTAL_DIM


@dataclass
class MLAnalysisResult:
    """
    Structured outcome of the EMBER ML Analysis stage.
    Conforms to the standard analyzer result contract with explicit parity metadata.
    """
    available: bool = False
    status: str = "UNAVAILABLE"  # 'SUCCESS', 'UNAVAILABLE', 'FAILED', 'OFFLINE_TEST_UNVERIFIED_PARITY'
    message: str = "ML analysis initialized."
    malicious_score: Optional[float] = None
    is_malicious: Optional[bool] = None
    is_malicious_1pct_fpr: Optional[bool] = None
    is_malicious_01pct_fpr: Optional[bool] = None
    active_threshold: Optional[float] = None
    thresholds: Dict[str, float] = field(default_factory=dict)
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    model_sha256: Optional[str] = None
    feature_dim: int = EMBER_V2_TOTAL_DIM
    feature_parity_status: str = "UNVERIFIED"  # 'VERIFIED_FEATURE_VECTOR', 'UNVERIFIED_RAW_PE_PARITY'
    is_reliable: bool = False
    execution_time_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns the standardized analyzer output contract dictionary."""
        return {
            "available": self.available,
            "status": self.status,
            "message": self.message,
            "malicious_score": self.malicious_score,
            "is_malicious": self.is_malicious,
            "is_malicious_1pct_fpr": self.is_malicious_1pct_fpr,
            "is_malicious_01pct_fpr": self.is_malicious_01pct_fpr,
            "active_threshold": self.active_threshold,
            "thresholds": self.thresholds,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "model_sha256": self.model_sha256,
            "feature_dim": self.feature_dim,
            "feature_parity_status": self.feature_parity_status,
            "is_reliable": self.is_reliable,
            "execution_time_ms": self.execution_time_ms,
            "error": self.error,
        }


class MLAnalyzer:
    """
    Isolated static analysis component adapting the EMBER baseline classifier.
    Designed exclusively for controlled offline testing without modifying production verdicts.
    """

    def __init__(
        self,
        classifier: Optional[EmberModelClassifier] = None,
        enforce_parity_gate: bool = True,
    ) -> None:
        """
        Initialize the ML analyzer service.

        Args:
            classifier: Optional pre-configured EmberModelClassifier instance.
            enforce_parity_gate: If True, flags raw-PE feature extraction as unverified parity.
        """
        self.enforce_parity_gate = enforce_parity_gate
        self._classifier = classifier
        self._init_error: Optional[str] = None

        if self._classifier is None:
            self._attempt_lazy_init()

    def _attempt_lazy_init(self) -> None:
        """Attempt to instantiate the default verified baseline classifier."""
        try:
            self._classifier = EmberModelClassifier(verify_checksum=True)
        except Exception as e:
            self._classifier = None
            self._init_error = f"ML classifier initialization failed: {self._sanitize_error(str(e))}"
            logger.warning(f"MLAnalyzer: {self._init_error}")

    @property
    def is_available(self) -> bool:
        """Returns True if the ML classifier is loaded and ready for inference."""
        return self._classifier is not None and self._classifier.is_loaded

    def _sanitize_error(self, err_msg: str) -> str:
        """
        Sanitize error messages to avoid leaking filesystem paths, environment details,
        or raw binary contents to callers.
        """
        clean = str(err_msg)
        # Redact common filesystem path patterns
        for path_prefix in [str(BASE_DIR), str(settings.STORAGE_BASE_DIR), "C:\\", "D:\\"]:
            if path_prefix in clean:
                clean = clean.replace(path_prefix, "[REDACTED_PATH]/")
        return clean

    def analyze_feature_vector(
        self,
        features: np.ndarray,
        threshold: Optional[float] = None,
    ) -> MLAnalysisResult:
        """
        Evaluate a pre-extracted 2,381-dimensional feature vector.
        This provides verified offline evaluation conforming to the EMBER v2 schema contract.

        Args:
            features: 1D array of 2,381 float32 features.
            threshold: Optional custom decision threshold.

        Returns:
            MLAnalysisResult with verified parity and reliable status.
        """
        t0 = time.perf_counter()

        if not self.is_available:
            return MLAnalysisResult(
                available=False,
                status="UNAVAILABLE",
                message="ML classifier service is unavailable.",
                error=self._init_error or "Model artifact not loaded or integrity verification failed.",
                execution_time_ms=round((time.perf_counter() - t0) * 1000, 2),
            )

        try:
            pred = self._classifier.predict_single(features, threshold=threshold)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

            return MLAnalysisResult(
                available=True,
                status="SUCCESS",
                message="Feature vector evaluated successfully via verified EMBER baseline model.",
                malicious_score=pred.malicious_score,
                is_malicious=pred.is_malicious,
                is_malicious_1pct_fpr=pred.is_malicious_1pct_fpr,
                is_malicious_01pct_fpr=pred.is_malicious_01pct_fpr,
                active_threshold=pred.active_threshold,
                thresholds=pred.thresholds,
                model_name=pred.model_name,
                model_version=pred.model_version,
                model_sha256=pred.model_sha256,
                feature_dim=pred.feature_dim,
                feature_parity_status="VERIFIED_FEATURE_VECTOR",
                is_reliable=True,
                execution_time_ms=elapsed_ms,
            )
        except EmberModelError as eme:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            return MLAnalysisResult(
                available=False,
                status="FAILED",
                message="Feature vector validation or inference failed.",
                error=self._sanitize_error(str(eme)),
                execution_time_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            return MLAnalysisResult(
                available=False,
                status="FAILED",
                message="Unexpected error during ML inference.",
                error=self._sanitize_error(str(e)),
                execution_time_ms=elapsed_ms,
            )

    def analyze_pe_bytes(
        self,
        content: bytes,
        threshold: Optional[float] = None,
    ) -> MLAnalysisResult:
        """
        Run static feature extraction and controlled evaluation on raw PE binary bytes.

        Enforces parity gate: Because bitwise feature extraction parity between the local
        LIEF extractor and the 2018 reference training features is not yet proven on real
        paired binaries, this method explicitly flags the result as unverified parity
        and sets is_reliable=False.

        Args:
            content: Raw PE binary bytes.
            threshold: Optional custom decision threshold.

        Returns:
            MLAnalysisResult indicating unverified parity limitations.
        """
        t0 = time.perf_counter()

        # Input and resource checks
        if not content:
            return MLAnalysisResult(
                available=False,
                status="FAILED",
                message="Cannot analyze empty byte buffer.",
                error="Empty content buffer.",
                execution_time_ms=round((time.perf_counter() - t0) * 1000, 2),
            )

        if len(content) > settings.MAX_FILE_SIZE_BYTES:
            return MLAnalysisResult(
                available=False,
                status="FAILED",
                message=f"Sample size exceeds maximum configured limit of {settings.MAX_FILE_SIZE_BYTES} bytes.",
                error="Payload size limit exceeded.",
                execution_time_ms=round((time.perf_counter() - t0) * 1000, 2),
            )

        if not self.is_available:
            return MLAnalysisResult(
                available=False,
                status="UNAVAILABLE",
                message="ML classifier service is unavailable.",
                error=self._init_error or "Model artifact not loaded or integrity verification failed.",
                execution_time_ms=round((time.perf_counter() - t0) * 1000, 2),
            )

        try:
            # Extract features from PE bytes without executing sample
            extractor = self._classifier.extractor
            features = extractor.feature_vector(content)

            # Check if parity gate requires flagging unverified raw PE extraction
            if self.enforce_parity_gate:
                # Run prediction strictly for offline telemetry, but flag status
                pred = self._classifier.predict_single(features, threshold=threshold)
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

                return MLAnalysisResult(
                    available=True,
                    status="OFFLINE_TEST_UNVERIFIED_PARITY",
                    message=(
                        "Offline test evaluation complete. Raw-PE feature extraction parity with "
                        "EMBER 2018 training dataset is unverified. Predictions must not be used "
                        "for automated blocking or production verdict assignment."
                    ),
                    malicious_score=pred.malicious_score,
                    is_malicious=pred.is_malicious,
                    is_malicious_1pct_fpr=pred.is_malicious_1pct_fpr,
                    is_malicious_01pct_fpr=pred.is_malicious_01pct_fpr,
                    active_threshold=pred.active_threshold,
                    thresholds=pred.thresholds,
                    model_name=pred.model_name,
                    model_version=pred.model_version,
                    model_sha256=pred.model_sha256,
                    feature_dim=pred.feature_dim,
                    feature_parity_status="UNVERIFIED_RAW_PE_PARITY",
                    is_reliable=False,  # Explicitly false until empirical parity is proven
                    execution_time_ms=elapsed_ms,
                )
            else:
                pred = self._classifier.predict_single(features, threshold=threshold)
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
                return MLAnalysisResult(
                    available=True,
                    status="SUCCESS",
                    message="Raw PE features evaluated via baseline model.",
                    malicious_score=pred.malicious_score,
                    is_malicious=pred.is_malicious,
                    is_malicious_1pct_fpr=pred.is_malicious_1pct_fpr,
                    is_malicious_01pct_fpr=pred.is_malicious_01pct_fpr,
                    active_threshold=pred.active_threshold,
                    thresholds=pred.thresholds,
                    model_name=pred.model_name,
                    model_version=pred.model_version,
                    model_sha256=pred.model_sha256,
                    feature_dim=pred.feature_dim,
                    feature_parity_status="EXPERIMENTAL_UNVERIFIED_PARITY",
                    is_reliable=False,
                    execution_time_ms=elapsed_ms,
                )

        except EmberModelError as eme:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            return MLAnalysisResult(
                available=False,
                status="FAILED",
                message="Feature extraction or inference failed on PE bytes.",
                error=self._sanitize_error(str(eme)),
                execution_time_ms=elapsed_ms,
            )
        except Exception as e:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            return MLAnalysisResult(
                available=False,
                status="FAILED",
                message="Extraction error encountered during PE parsing.",
                error=self._sanitize_error(str(e)),
                execution_time_ms=elapsed_ms,
            )

    def analyze_file(
        self,
        file_path: Union[str, Path],
        threshold: Optional[float] = None,
    ) -> MLAnalysisResult:
        """
        Safely read a local PE file and execute static ML analysis.

        Args:
            file_path: Path to local PE binary.
            threshold: Optional custom decision threshold.

        Returns:
            MLAnalysisResult instance.
        """
        try:
            target = Path(file_path)
            if not target.exists():
                return MLAnalysisResult(
                    available=False,
                    status="FAILED",
                    message="File not found.",
                    error="Target file does not exist.",
                )
            content = target.read_bytes()
            return self.analyze_pe_bytes(content, threshold=threshold)
        except Exception as e:
            return MLAnalysisResult(
                available=False,
                status="FAILED",
                message="Failed to read target file for ML analysis.",
                error=self._sanitize_error(str(e)),
            )


# Singleton service instance for optional offline testing
ml_analyzer_service = MLAnalyzer()
