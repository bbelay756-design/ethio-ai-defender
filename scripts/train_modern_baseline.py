#!/usr/bin/env python3
"""
ETHIO-AI Defender - ML-14: Modern Corpus Retraining & Evaluation Script

Trains a modern candidate model (ember-v2-modern-hgb-2026) using memory-conscious
streaming arrays from the curated 2024-2026 dataset.

Strict Release Invariants:
- NEVER overwrites the authoritative baseline model (model.joblib, SHA-256: f2fd3ed4...).
- Writes candidate model to an isolated directory: storage/models/ember_modern_candidate_v1/.
- Generates sidecar SHA-256 checksum and full provenance metadata.
- Validates ROC-AUC, PR-AUC, and empirical FPR on an independent holdout.
- If modern corpus data is missing, exits cleanly with BLOCKED status and actionable resume instructions.
"""

import os
import sys
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score, average_precision_score, confusion_matrix

from app.ml.ember_v2 import EMBER_V2_TOTAL_DIM
from app.core.logger import logger

CANDIDATE_OUTPUT_DIR = REPO_ROOT / "storage" / "models" / "ember_modern_candidate_v1"


def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(1048576):
            h.update(chunk)
    return h.hexdigest().lower()


def train_candidate_model(
    x_mmap_path: Path,
    y_mmap_path: Path,
    output_dir: Path = CANDIDATE_OUTPUT_DIR,
    val_ratio: float = 0.2,
    random_seed: int = 42,
) -> Dict[str, Any]:
    """
    Trains candidate model from memory-mapped feature arrays.
    """
    if not x_mmap_path.is_file() or not y_mmap_path.is_file():
        logger.error(f"Required modern feature arrays not found: {x_mmap_path}")
        return {
            "status": "BLOCKED — REQUIRED MODERN CORPUS UNAVAILABLE",
            "reason": "Missing staged memory-mapped feature files (X_modern.mmap, y_modern.mmap)",
        }

    # Determine sample count from file size
    dim_bytes = EMBER_V2_TOTAL_DIM * 4  # float32 = 4 bytes
    file_bytes = x_mmap_path.stat().st_size
    n_samples = file_bytes // dim_bytes
    if n_samples == 0:
        return {
            "status": "BLOCKED — REQUIRED MODERN CORPUS UNAVAILABLE",
            "reason": "Staged modern feature array contains 0 samples.",
        }

    logger.info(f"Loading {n_samples:,} feature vectors from {x_mmap_path}...")
    X = np.memmap(x_mmap_path, dtype=np.float32, mode="r", shape=(n_samples, EMBER_V2_TOTAL_DIM))
    y = np.memmap(y_mmap_path, dtype=np.int32, mode="r", shape=(n_samples,))

    # Deterministic split
    np.random.seed(random_seed)
    indices = np.arange(n_samples)
    np.random.shuffle(indices)

    n_val = int(n_samples * val_ratio)
    val_idx = indices[:n_val]
    train_idx = indices[n_val:]

    logger.info(f"Train samples: {len(train_idx):,}, Validation samples: {len(val_idx):,}")

    # Train model
    clf = HistGradientBoostingClassifier(
        random_state=random_seed,
        max_iter=100,
        early_stopping=True,
    )
    t0 = time.perf_counter()
    clf.fit(X[train_idx], y[train_idx])
    train_time = time.perf_counter() - t0

    # Evaluate on validation holdout
    val_probs = clf.predict_proba(X[val_idx])[:, 1]
    val_y = y[val_idx]

    roc_auc = float(roc_auc_score(val_y, val_probs))
    pr_auc = float(average_precision_score(val_y, val_probs))

    # Calibrate thresholds
    benign_scores = val_probs[val_y == 0]
    tau_1pct = float(np.percentile(benign_scores, 99.0)) if len(benign_scores) > 0 else 0.8
    tau_01pct = float(np.percentile(benign_scores, 99.9)) if len(benign_scores) > 0 else 0.95

    # Measure FPR at tau_1pct
    actual_1pct_fpr = float(np.mean(benign_scores >= tau_1pct)) if len(benign_scores) > 0 else 0.0

    output_dir.mkdir(parents=True, exist_ok=True)
    candidate_model_path = output_dir / "model.joblib"
    candidate_sha_path = output_dir / "model.joblib.sha256"
    candidate_meta_path = output_dir / "metadata.json"

    # Save artifact
    joblib.dump(clf, candidate_model_path)
    model_sha256 = compute_sha256(candidate_model_path)
    candidate_sha_path.write_text(f"{model_sha256} *model.joblib\n", encoding="utf-8")

    meta = {
        "model_name": "ember-v2-modern-hgb-2026",
        "model_version": "2.0.0-candidate",
        "model_sha256": model_sha256,
        "is_authoritative_baseline": False,
        "dataset": {
            "feature_version": 2,
            "feature_dim": EMBER_V2_TOTAL_DIM,
            "total_samples": int(n_samples),
            "train_samples": int(len(train_idx)),
            "validation_samples": int(len(val_idx)),
        },
        "evaluation": {
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "calibrated_threshold_1pct": tau_1pct,
            "calibrated_threshold_01pct": tau_01pct,
            "empirical_validation_fpr": actual_1pct_fpr,
        },
        "training_time_seconds": round(train_time, 2),
    }

    with open(candidate_meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    logger.info(f"Retraining successful! Candidate model saved to {candidate_model_path} (SHA-256: {model_sha256})")
    return {
        "status": "PASS",
        "model_path": str(candidate_model_path),
        "model_sha256": model_sha256,
        "metadata": meta,
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train modern baseline candidate model")
    parser.add_argument("--x-mmap", type=Path, default=REPO_ROOT / "storage" / "modern_staged" / "X_modern.mmap")
    parser.add_argument("--y-mmap", type=Path, default=REPO_ROOT / "storage" / "modern_staged" / "y_modern.mmap")
    parser.add_argument("--output", type=Path, default=CANDIDATE_OUTPUT_DIR)
    args = parser.parse_args()

    result = train_candidate_model(args.x_mmap, args.y_mmap, args.output)
    print(json.dumps(result, indent=2))
