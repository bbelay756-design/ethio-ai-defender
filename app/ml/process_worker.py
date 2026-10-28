"""
Process-Isolated Worker Service for EMBER ML Static Analysis.

Responsibility:
Executes potentially blocking PE parsing (LIEF C++) and scikit-learn ML inference
in an isolated child operating system process with hard wall-clock timeout enforcement.

Safety & Isolation Guarantees:
- Enforces strict wall-clock deadline: timeouts terminate the OS process via TerminateProcess.
- Native C++ or OpenMP loops cannot hang the parent application process.
- Single worker concurrency: bounded memory and CPU footprint.
- Defensive IPC validation: checks structure, types, finite ranges [0.0, 1.0].
- Sanitized error messages: no filesystem paths or confidential environment info leaked.
- Fail-safe: crashes, timeouts, or invalid worker states fail closed without impacting
  deterministic static analyzers or threat scoring.
"""

import math
import multiprocessing as mp
from multiprocessing.connection import Connection
import os
from pathlib import Path
import threading
import time
from typing import Any, Dict, Optional, Union

import numpy as np

from app.core.config import BASE_DIR, settings
from app.core.logger import logger
from app.ml.classifier import (
    EmberModelClassifier,
    EmberModelError,
    ClassifierPredictionResult,
    TRUSTED_BASELINE_MODEL_SHA256,
)
from app.ml.ember_v2 import EMBERFeatureExtractor, EMBER_V2_TOTAL_DIM


def _sanitize_error_str(err: Any) -> str:
    """Sanitize error messages to redact filesystem paths and internals."""
    clean = str(err)
    for p in [str(BASE_DIR), str(settings.STORAGE_BASE_DIR), "C:\\", "D:\\", "c:\\", "d:\\"]:
        if p in clean:
            clean = clean.replace(p, "[REDACTED_PATH]/")
    return clean


def _validate_prediction_dict(result_dict: Any) -> Dict[str, Any]:
    """Validate structure and value invariants of prediction result dictionary."""
    if not isinstance(result_dict, dict):
        raise ValueError(f"Worker response must be a dict, got {type(result_dict).__name__}")

    required_keys = ["malicious_score", "is_malicious", "active_threshold", "thresholds"]
    for k in required_keys:
        if k not in result_dict:
            raise ValueError(f"Worker response missing required key: '{k}'")

    score = result_dict["malicious_score"]
    if score is None or not isinstance(score, (int, float)):
        raise ValueError(f"malicious_score must be numeric, got {type(score).__name__}")

    if math.isnan(score) or math.isinf(score):
        raise ValueError("malicious_score must be a finite number; got NaN or Inf")

    if not (0.0 <= float(score) <= 1.0):
        raise ValueError(f"malicious_score {score} out of bounds [0.0, 1.0]")

    return result_dict


def _ml_worker_loop(
    conn: Connection,
    model_dir: Optional[str] = None,
    verify_checksum: bool = True,
    trusted_sha256: Optional[str] = None,
    allow_custom_path: bool = False,
) -> None:
    """
    Child process entry point.
    Initializes classifier and feature extractor once, then responds to IPC requests.
    """
    classifier: Optional[EmberModelClassifier] = None
    extractor: Optional[EMBERFeatureExtractor] = None

    try:
        classifier = EmberModelClassifier(
            model_dir=model_dir,
            verify_checksum=verify_checksum,
            trusted_sha256=trusted_sha256,
            allow_custom_path=allow_custom_path,
        )
        extractor = classifier.extractor
        conn.send({
            "status": "READY",
            "model_name": classifier.model_name,
            "model_version": classifier.model_version,
            "model_sha256": classifier.model_file_sha256,
            "thresholds": classifier.calibrated_thresholds,
            "is_loaded": classifier.is_loaded,
        })
    except Exception as exc:
        try:
            conn.send({
                "status": "INIT_ERROR",
                "error": _sanitize_error_str(str(exc)),
                "error_type": type(exc).__name__,
            })
        except Exception:
            pass
        finally:
            conn.close()
            return

    # Main IPC service loop
    while True:
        try:
            if not conn.poll(None):
                break
            msg = conn.recv()
        except (EOFError, BrokenPipeError, ConnectionResetError):
            break
        except Exception:
            break

        if not isinstance(msg, dict):
            try:
                conn.send({"status": "ERROR", "error": "Invalid IPC message format"})
            except Exception:
                pass
            continue

        cmd = msg.get("cmd")

        if cmd == "SHUTDOWN":
            break

        elif cmd == "PING":
            try:
                conn.send({"status": "PONG"})
            except Exception:
                break

        elif cmd == "EVALUATE_PE":
            content = msg.get("content")
            threshold = msg.get("threshold")
            try:
                if not isinstance(content, (bytes, bytearray)):
                    raise ValueError("PE content must be raw bytes")
                if len(content) == 0:
                    raise ValueError("PE content buffer is empty")

                # Extract features in worker process (LIEF C++ parsing is isolated here)
                features = extractor.feature_vector(bytes(content))
                pred = classifier.predict_single(features, threshold=threshold)
                res_dict = pred.to_dict()
                res_dict["feature_dim"] = len(features)
                conn.send({"status": "OK", "result": res_dict})
            except EmberModelError as eme:
                conn.send({
                    "status": "ERROR",
                    "error": _sanitize_error_str(str(eme)),
                    "error_type": "EmberModelError",
                })
            except Exception as e:
                conn.send({
                    "status": "ERROR",
                    "error": _sanitize_error_str(str(e)),
                    "error_type": type(e).__name__,
                })

        elif cmd == "EVALUATE_FEATURES":
            features = msg.get("features")
            threshold = msg.get("threshold")
            try:
                if not isinstance(features, np.ndarray):
                    features = np.asarray(features, dtype=np.float32)
                pred = classifier.predict_single(features, threshold=threshold)
                res_dict = pred.to_dict()
                conn.send({"status": "OK", "result": res_dict})
            except EmberModelError as eme:
                conn.send({
                    "status": "ERROR",
                    "error": _sanitize_error_str(str(eme)),
                    "error_type": "EmberModelError",
                })
            except Exception as e:
                conn.send({
                    "status": "ERROR",
                    "error": _sanitize_error_str(str(e)),
                    "error_type": type(e).__name__,
                })

        else:
            try:
                conn.send({"status": "ERROR", "error": f"Unknown command: '{cmd}'"})
            except Exception:
                break

    try:
        conn.close()
    except Exception:
        pass


class MLProcessWorker:
    """
    Manager for the process-isolated ML inference worker.
    Maintains a single worker process with strict wall-clock deadline enforcement.
    """

    def __init__(
        self,
        timeout_seconds: Optional[float] = None,
        model_dir: Optional[Union[str, Path]] = None,
        verify_checksum: bool = True,
        trusted_sha256: Optional[str] = None,
        allow_custom_path: bool = False,
        max_tasks_before_recycle: int = 500,
        handshake_timeout_seconds: float = 25.0,
    ) -> None:
        self.timeout_seconds = float(
            timeout_seconds if timeout_seconds is not None else settings.ML_TIMEOUT_SECONDS
        )
        self.model_dir = str(model_dir) if model_dir is not None else None
        self.verify_checksum = verify_checksum
        self.trusted_sha256 = trusted_sha256
        self.allow_custom_path = allow_custom_path
        self.max_tasks_before_recycle = max_tasks_before_recycle
        self.handshake_timeout_seconds = handshake_timeout_seconds

        self._ctx = mp.get_context("spawn")
        self._lock = threading.Lock()
        self._process: Optional[mp.Process] = None
        self._parent_conn: Optional[Connection] = None
        self._task_count: int = 0
        self._init_metadata: Dict[str, Any] = {}
        self._is_available: bool = False
        self._init_error: Optional[str] = None

    @property
    def is_available(self) -> bool:
        """True if the worker process is running and reported successful initialization."""
        return self._is_available and self.is_running()

    @property
    def init_error(self) -> Optional[str]:
        return self._init_error

    @property
    def metadata(self) -> Dict[str, Any]:
        return self._init_metadata

    def is_running(self) -> bool:
        """True if child process is active and has not terminated."""
        return self._process is not None and self._process.is_alive()

    @property
    def pid(self) -> Optional[int]:
        """PID of running worker process."""
        return self._process.pid if self._process is not None else None

    def start(self) -> bool:
        """
        Start worker process and complete handshake.
        Returns True if successful, False if initialization failed.
        """
        with self._lock:
            return self._start_locked()

    def _start_locked(self) -> bool:
        if self._process is not None and self._process.is_alive():
            return True

        self._cleanup_process()
        self._init_error = None
        self._is_available = False

        parent_conn, child_conn = self._ctx.Pipe(duplex=True)
        proc = self._ctx.Process(
            target=_ml_worker_loop,
            args=(
                child_conn,
                self.model_dir,
                self.verify_checksum,
                self.trusted_sha256,
                self.allow_custom_path,
            ),
            daemon=True,
        )

        try:
            proc.start()
        except Exception as e:
            child_conn.close()
            parent_conn.close()
            self._init_error = f"Failed to spawn ML worker process: {_sanitize_error_str(e)}"
            logger.error(self._init_error)
            return False

        # Close child handle in parent process
        child_conn.close()
        self._process = proc
        self._parent_conn = parent_conn
        self._task_count = 0

        # Wait for handshake with strict startup deadline
        if not self._parent_conn.poll(self.handshake_timeout_seconds):
            self._terminate_process_locked()
            self._init_error = (
                f"ML worker process failed to initialize within {self.handshake_timeout_seconds}s timeout"
            )
            logger.error(self._init_error)
            return False

        try:
            msg = self._parent_conn.recv()
        except (EOFError, BrokenPipeError, ConnectionResetError) as exc:
            self._terminate_process_locked()
            self._init_error = f"ML worker process crashed during startup: {_sanitize_error_str(exc)}"
            logger.error(self._init_error)
            return False

        if not isinstance(msg, dict) or msg.get("status") != "READY":
            self._terminate_process_locked()
            err = msg.get("error") if isinstance(msg, dict) else "Unknown handshake failure"
            self._init_error = f"ML worker initialization rejected: {_sanitize_error_str(err)}"
            logger.warning(self._init_error)
            return False

        self._init_metadata = msg
        self._is_available = True
        logger.info(f"ML worker process started successfully (PID: {proc.pid})")
        return True

    def _terminate_process_locked(self) -> None:
        """Forcefully terminates and cleans up worker process handles."""
        proc = self._process
        conn = self._parent_conn

        self._process = None
        self._parent_conn = None
        self._is_available = False

        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

        if proc is not None:
            try:
                if proc.is_alive():
                    proc.terminate()
                    proc.join(timeout=0.5)
                    if proc.is_alive():
                        proc.kill()
                        proc.join(timeout=0.5)
            except Exception as e:
                logger.warning(f"Error during ML worker termination: {e}")
            finally:
                try:
                    proc.close()
                except Exception:
                    pass

    def _cleanup_process(self) -> None:
        self._terminate_process_locked()

    def terminate(self) -> None:
        """Public method to stop worker process immediately."""
        with self._lock:
            self._terminate_process_locked()

    def execute_pe_bytes(
        self,
        content: bytes,
        threshold: Optional[float] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Execute PE static parsing and feature inference in worker process.
        Enforces strict wall-clock timeout. If timed out, terminates process immediately.
        """
        if not content:
            raise ValueError("PE content buffer is empty")

        wall_timeout = float(timeout if timeout is not None else self.timeout_seconds)

        with self._lock:
            if not self.is_running():
                if not self._start_locked():
                    raise EmberModelError(self._init_error or "ML worker process unavailable")

            # Dispatch request
            try:
                self._parent_conn.send({
                    "cmd": "EVALUATE_PE",
                    "content": content,
                    "threshold": threshold,
                })
            except Exception as e:
                self._terminate_process_locked()
                raise RuntimeError(f"Failed to transmit payload to ML worker: {_sanitize_error_str(e)}") from e

            # Strict wall-clock deadline poll
            if not self._parent_conn.poll(wall_timeout):
                logger.warning(f"ML worker process timed out after {wall_timeout}s wall-clock limit. Terminating.")
                self._terminate_process_locked()
                raise TimeoutError(f"ML analysis exceeded strict deadline of {wall_timeout} seconds")

            # Receive result
            try:
                resp = self._parent_conn.recv()
            except (EOFError, BrokenPipeError, ConnectionResetError) as e:
                self._terminate_process_locked()
                raise RuntimeError("ML worker process terminated unexpectedly during analysis") from e

            if not isinstance(resp, dict):
                self._terminate_process_locked()
                raise ValueError("Malformed IPC message from ML worker")

            if resp.get("status") == "ERROR":
                err_msg = resp.get("error", "Worker error")
                err_type = resp.get("error_type", "EmberModelError")
                if err_type == "EmberModelError":
                    raise EmberModelError(err_msg)
                raise RuntimeError(err_msg)

            if resp.get("status") != "OK":
                self._terminate_process_locked()
                raise ValueError(f"Unexpected worker response status: {resp.get('status')}")

            # Defensive validation of output
            validated = _validate_prediction_dict(resp.get("result"))

            # Recycling check
            self._task_count += 1
            if self._task_count >= self.max_tasks_before_recycle:
                logger.info(f"Recycling ML worker process after {self._task_count} tasks.")
                self._terminate_process_locked()

            return validated

    def execute_feature_vector(
        self,
        features: np.ndarray,
        threshold: Optional[float] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Execute feature vector evaluation in worker process with timeout enforcement.
        """
        wall_timeout = float(timeout if timeout is not None else self.timeout_seconds)

        with self._lock:
            if not self.is_running():
                if not self._start_locked():
                    raise EmberModelError(self._init_error or "ML worker process unavailable")

            try:
                self._parent_conn.send({
                    "cmd": "EVALUATE_FEATURES",
                    "features": features,
                    "threshold": threshold,
                })
            except Exception as e:
                self._terminate_process_locked()
                raise RuntimeError(f"Failed to transmit feature vector to ML worker: {_sanitize_error_str(e)}") from e

            if not self._parent_conn.poll(wall_timeout):
                logger.warning(f"ML worker feature evaluation timed out after {wall_timeout}s. Terminating.")
                self._terminate_process_locked()
                raise TimeoutError(f"ML feature analysis exceeded strict deadline of {wall_timeout} seconds")

            try:
                resp = self._parent_conn.recv()
            except (EOFError, BrokenPipeError, ConnectionResetError) as e:
                self._terminate_process_locked()
                raise RuntimeError("ML worker process terminated unexpectedly during feature analysis") from e

            if not isinstance(resp, dict):
                self._terminate_process_locked()
                raise ValueError("Malformed IPC message from ML worker")

            if resp.get("status") == "ERROR":
                err_msg = resp.get("error", "Worker error")
                err_type = resp.get("error_type", "EmberModelError")
                if err_type == "EmberModelError":
                    raise EmberModelError(err_msg)
                raise RuntimeError(err_msg)

            if resp.get("status") != "OK":
                self._terminate_process_locked()
                raise ValueError(f"Unexpected worker response status: {resp.get('status')}")

            validated = _validate_prediction_dict(resp.get("result"))

            self._task_count += 1
            if self._task_count >= self.max_tasks_before_recycle:
                self._terminate_process_locked()

            return validated

    def __del__(self) -> None:
        try:
            self.terminate()
        except Exception:
            pass
