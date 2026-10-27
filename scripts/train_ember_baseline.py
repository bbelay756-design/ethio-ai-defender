"""
Training, Calibration, and Evaluation Pipeline for EMBER 2018 Baseline Classifier.

Conforms to ETHIO-AI Defender ML-03E specifications:
- Uses verified EMBER 2018 Feature Version 2 partitions (train_features_0/1/3, test_features).
- Filters out unlabeled (-1) samples from supervised training and validation.
- Enforces deterministic stratified 80/20 train/validation split (random_state=42).
- Verifies SHA-256 hash disjointness across train, val, and test splits (zero data leakage).
- Trains HistGradientBoostingClassifier within memory and CPU budgets.
- Calibrates operational decision thresholds on validation data at 1.0% and 0.1% FPR.
- Evaluates frozen model on locked 200,000-sample test set.
- Exports model artifact with cryptographic SHA-256 checksum and complete provenance metadata.
"""

import gc
import hashlib
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.ml.classifier import EmberModelClassifier
from app.ml.ember_adapter import EmberDatasetAdapter, EMBER_TOTAL_DIM
from app.ml.evaluator import calibrate_operational_thresholds, evaluate_frozen_model

try:
    import psutil
    def get_process_memory_mb() -> float:
        return psutil.Process().memory_info().rss / (1024 * 1024)
except ImportError:
    def get_process_memory_mb() -> float:
        return 0.0


def log_msg(msg: str) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{timestamp}] {msg}", flush=True)


def compute_file_sha256(filepath: Path) -> str:
    """Compute SHA-256 hash of a file in 1MB chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(1048576):
            h.update(chunk)
    return h.hexdigest().lower()


def run_pipeline() -> None:
    t_start = time.time()
    log_msg("=== ETHIO-AI DEFENDER: EMBER BASELINE TRAINING PIPELINE (ML-03E) ===")
    
    # ---------------------------------------------------------
    # 1. Preflight Verification
    # ---------------------------------------------------------
    log_msg("[1/6] Running preflight environment and data checks...")
    import sklearn
    log_msg(f"  Python Version:       {platform.python_version()} ({platform.platform()})")
    log_msg(f"  scikit-learn Version: {sklearn.__version__}")
    log_msg(f"  NumPy Version:        {np.__version__}")
    log_msg(f"  joblib Version:       {joblib.__version__}")
    
    data_dir = REPO_ROOT / "storage" / "ember2018"
    train_files = [
        data_dir / "train_features_0.jsonl",
        data_dir / "train_features_1.jsonl",
        data_dir / "train_features_3.jsonl",
    ]
    test_file = data_dir / "test_features.jsonl"
    
    for tf in train_files:
        if not tf.exists():
            raise FileNotFoundError(f"Required training partition missing: {tf}")
    if not test_file.exists():
        raise FileNotFoundError(f"Required test partition missing: {test_file}")
        
    output_dir = REPO_ROOT / "storage" / "models" / "ember_baseline_v1"
    output_dir.mkdir(parents=True, exist_ok=True)
    log_msg(f"  Target Artifact Directory: {output_dir}")

    # ---------------------------------------------------------
    # 2. Ingestion Metadata & Stratified Split Indexing
    # ---------------------------------------------------------
    log_msg("[2/6] Indexing supervised records for stratified split...")
    supervised_records = []  # list of (sha256, label, file_idx, line_idx)
    test_sha_set: Set[str] = set()
    
    # Clean scan of train partitions to find supervised samples (label 0 or 1)
    for file_idx, fpath in enumerate(train_files):
        log_msg(f"  Scanning {fpath.name}...")
        with open(fpath, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f):
                stripped = line.strip()
                if not stripped:
                    continue
                record = json.loads(stripped)
                lbl = record.get("label")
                if lbl not in (0, 1):
                    continue  # strictly exclude unlabeled (-1) and any invalid labels
                sha = str(record.get("sha256", "")).lower()
                supervised_records.append((sha, lbl, file_idx, line_idx))
                
    total_supervised = len(supervised_records)
    log_msg(f"  Indexed {total_supervised:,} supervised training records (0 unlabeled -1).")
    
    # Scan of test_features to collect test SHAs for leakage verification
    log_msg(f"  Indexing test set hashes from {test_file.name}...")
    with open(test_file, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            record = json.loads(stripped)
            test_sha_set.add(str(record.get("sha256", "")).lower())
    log_msg(f"  Indexed {len(test_sha_set):,} test set hashes.")
    
    # Stratified 80/20 train/val split
    indices = np.arange(total_supervised)
    labels = np.array([r[1] for r in supervised_records], dtype=np.int8)
    
    train_idx, val_idx = train_test_split(
        indices,
        test_size=0.20,
        stratify=labels,
        random_state=42,
    )
    
    log_msg(f"  Deterministic Stratified Split (80/20, seed=42):")
    log_msg(f"    Train Split (D_train): {len(train_idx):,} samples")
    log_msg(f"    Validation Split (D_val): {len(val_idx):,} samples")
    
    # Build lookups for fast streaming population
    train_set_lookup = set(train_idx)
    val_set_lookup = set(val_idx)
    
    train_shas: Set[str] = {supervised_records[i][0] for i in train_idx}
    val_shas: Set[str] = {supervised_records[i][0] for i in val_idx}
    
    # Verify leakage invariants
    train_val_overlap = train_shas.intersection(val_shas)
    if train_val_overlap:
        raise ValueError(f"FATAL: Train/Val split overlap detected ({len(train_val_overlap)} hashes)!")
        
    train_test_overlap = train_shas.intersection(test_sha_set)
    if train_test_overlap:
        raise ValueError(f"FATAL: Train/Test data leakage detected ({len(train_test_overlap)} hashes)!")
        
    val_test_overlap = val_shas.intersection(test_sha_set)
    if val_test_overlap:
        raise ValueError(f"FATAL: Val/Test data leakage detected ({len(val_test_overlap)} hashes)!")
        
    log_msg("  [LEAKAGE CHECK PASS]: SHA-256 disjointness verified. Zero cross-split overlap.")

    # ---------------------------------------------------------
    # 3. Stream Feature Ingestion into Memory-Mapped Arrays
    # ---------------------------------------------------------
    log_msg("[3/6] Ingesting and vectorizing features into memory-mapped arrays...")
    
    # Select mmap directory: prefer D: drive (18+ GB free) or fallback to local storage
    d_drive = Path("D:/tmp_ember_mmap")
    if d_drive.parent.exists():
        mmap_dir = d_drive
    else:
        mmap_dir = REPO_ROOT / "storage" / "tmp_mmap"
    mmap_dir.mkdir(parents=True, exist_ok=True)
    log_msg(f"  Memory-mapped buffer location: {mmap_dir}")

    train_mmap_path = mmap_dir / "X_train.dat"
    val_mmap_path = mmap_dir / "X_val.dat"

    # Pre-allocate float64 memory-mapped arrays directly on disk
    # (Matches scikit-learn HistGradientBoosting float64 X_DTYPE to prevent RAM duplication)
    X_train_mmap = np.memmap(
        train_mmap_path,
        dtype=np.float64,
        mode="w+",
        shape=(len(train_idx), EMBER_TOTAL_DIM),
    )
    y_train = np.empty(len(train_idx), dtype=np.int8)

    X_val_mmap = np.memmap(
        val_mmap_path,
        dtype=np.float64,
        mode="w+",
        shape=(len(val_idx), EMBER_TOTAL_DIM),
    )
    y_val = np.empty(len(val_idx), dtype=np.int8)

    log_msg(f"  Pre-allocated on-disk mmap arrays:")
    log_msg(f"    X_train_mmap: {X_train_mmap.shape} float64 ({X_train_mmap.nbytes / (1024**3):.2f} GiB)")
    log_msg(f"    X_val_mmap:   {X_val_mmap.shape} float64 ({X_val_mmap.nbytes / (1024**3):.2f} GiB)")

    # Map index in supervised_records -> position in X_train / X_val
    train_pos_map = {idx: pos for pos, idx in enumerate(train_idx)}
    val_pos_map = {idx: pos for pos, idx in enumerate(val_idx)}

    adapter = EmberDatasetAdapter(feature_version=2, strict=True)

    current_supervised_idx = 0
    t_ingest_start = time.time()

    for fpath in train_files:
        log_msg(f"  Parsing vectors from {fpath.name}...")
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                record = json.loads(stripped)
                lbl = record.get("label")
                if lbl not in (0, 1):
                    continue

                vec, _ = adapter.parse_record(record, split="train")

                if current_supervised_idx in train_pos_map:
                    pos = train_pos_map[current_supervised_idx]
                    X_train_mmap[pos, :] = vec
                    y_train[pos] = lbl
                elif current_supervised_idx in val_pos_map:
                    pos = val_pos_map[current_supervised_idx]
                    X_val_mmap[pos, :] = vec
                    y_val[pos] = lbl

                current_supervised_idx += 1
                if current_supervised_idx % 25000 == 0:
                    X_train_mmap.flush()
                    X_val_mmap.flush()
                    log_msg(f"    Progress: {current_supervised_idx:,}/{total_supervised:,} samples vectorized...")

    X_train_mmap.flush()
    X_val_mmap.flush()
    ingest_duration = time.time() - t_ingest_start
    log_msg(f"  Vector ingestion completed in {ingest_duration:.1f}s.")

    # ---------------------------------------------------------
    # 4. Model Training (HistGradientBoostingClassifier)
    # ---------------------------------------------------------
    log_msg("[4/6] Training HistGradientBoostingClassifier baseline on memory-mapped data...")

    hgb_params = {
        "loss": "log_loss",
        "learning_rate": 0.05,
        "max_iter": 300,
        "max_leaf_nodes": 63,
        "min_samples_leaf": 50,
        "l2_regularization": 0.1,
        "early_stopping": True,
        "n_iter_no_change": 15,
        "validation_fraction": 0.1,
        "random_state": 42,
        "verbose": 1,
    }

    clf = HistGradientBoostingClassifier(**hgb_params)

    gc.collect()
    mem_before_train = get_process_memory_mb()
    log_msg(f"  Process RSS memory before fitting: {mem_before_train:.1f} MB")

    t_train_start = time.time()
    clf.fit(X_train_mmap, y_train)
    train_duration = time.time() - t_train_start

    mem_after_train = get_process_memory_mb()
    log_msg(f"  Training finished in {train_duration:.1f}s ({train_duration/60:.2f} min).")
    log_msg(f"  Iterations completed: {clf.n_iter_}")
    log_msg(f"  Peak process RSS memory during training: {mem_after_train:.1f} MB")

    # ---------------------------------------------------------
    # 5. Validation & Operational Threshold Calibration
    # ---------------------------------------------------------
    log_msg("[5/6] Calibrating decision thresholds on validation split...")
    y_val_prob = clf.predict_proba(X_val_mmap)[:, 1].astype(np.float64)

    calibrated_thresholds = calibrate_operational_thresholds(
        y_val=y_val,
        y_prob_val=y_val_prob,
        target_fprs=[0.01, 0.001],
    )
    
    from sklearn.metrics import roc_auc_score, average_precision_score
    val_roc_auc = float(roc_auc_score(y_val, y_val_prob))
    val_pr_auc = float(average_precision_score(y_val, y_val_prob))
    
    log_msg(f"  Validation ROC-AUC: {val_roc_auc:.4f}")
    log_msg(f"  Validation PR-AUC:  {val_pr_auc:.4f}")
    
    for key, cal_info in calibrated_thresholds.items():
        tau = cal_info["calibrated_threshold"]
        vm = cal_info["val_metrics"]
        log_msg(f"  Target FPR: {cal_info['target_fpr']*100:.1f}% -> Calibrated tau*: {tau:.4f} "
                f"(Val FPR: {vm['fpr']*100:.3f}%, Val Detection Rate/TPR: {vm['tpr']*100:.2f}%)")

    # Flush and close mmap arrays, then reclaim disk space
    del X_train_mmap, y_train, X_val_mmap, y_val
    gc.collect()
    
    try:
        if train_mmap_path.exists():
            train_mmap_path.unlink()
        if val_mmap_path.exists():
            val_mmap_path.unlink()
        if mmap_dir.exists() and not any(mmap_dir.iterdir()):
            mmap_dir.rmdir()
        log_msg(f"  Cleaned up temporary mmap files from {mmap_dir}.")
    except Exception as e:
        log_msg(f"  Note: mmap cleanup warning: {e}")

    # ---------------------------------------------------------
    # 6. Evaluation on Held-Out Test Set (200,000 samples)
    # ---------------------------------------------------------
    log_msg("[6/6] Evaluating frozen model on locked 200,000-sample test set...")
    t_test_start = time.time()
    
    test_batch_size = 5000
    test_probs: List[float] = []
    test_labels: List[int] = []
    batch_records = []
    
    with open(test_file, "r", encoding="utf-8") as f:
        for line_idx, line in enumerate(f, start=1):
            record = json.loads(line)
            batch_records.append(record)
            
            if len(batch_records) >= test_batch_size:
                # Vectorize batch
                batch_X = np.empty((len(batch_records), EMBER_TOTAL_DIM), dtype=np.float32)
                for i, r in enumerate(batch_records):
                    vec, lbl = adapter.parse_record(r, split="test")
                    batch_X[i] = vec
                    test_labels.append(int(lbl))
                    
                # Predict probabilities
                batch_probs = clf.predict_proba(batch_X)[:, 1]
                test_probs.extend(batch_probs.tolist())
                batch_records = []
                
                if line_idx % 50000 == 0:
                    log_msg(f"    Evaluated {line_idx:,}/200,000 test samples...")
                    
        # Flush remaining
        if batch_records:
            batch_X = np.empty((len(batch_records), EMBER_TOTAL_DIM), dtype=np.float32)
            for i, r in enumerate(batch_records):
                vec, lbl = adapter.parse_record(r, split="test")
                batch_X[i] = vec
                test_labels.append(int(lbl))
            batch_probs = clf.predict_proba(batch_X)[:, 1]
            test_probs.extend(batch_probs.tolist())

    test_eval_duration = time.time() - t_test_start
    log_msg(f"  Test evaluation completed in {test_eval_duration:.1f}s.")
    
    y_test_arr = np.array(test_labels, dtype=np.int32)
    y_prob_test_arr = np.array(test_probs, dtype=np.float64)
    
    test_evaluation = evaluate_frozen_model(
        y_test=y_test_arr,
        y_prob_test=y_prob_test_arr,
        calibrated_thresholds=calibrated_thresholds,
    )
    
    log_msg(f"  === HELD-OUT TEST EVALUATION RESULTS ===")
    log_msg(f"  Test Samples Evaluated: {test_evaluation['test_sample_count']:,}")
    log_msg(f"  Test ROC-AUC:           {test_evaluation['roc_auc']:.4f}")
    log_msg(f"  Test PR-AUC:            {test_evaluation['pr_auc']:.4f}")
    
    for key, th_eval in test_evaluation["operational_thresholds"].items():
        tm = th_eval["test_metrics"]
        log_msg(f"  Operational Point {th_eval['target_fpr']*100:.1f}% FPR:")
        log_msg(f"    Frozen Threshold:   {th_eval['frozen_threshold']:.4f}")
        log_msg(f"    Test False Positives:{tm['fp']:,} / {tm['total_benign']:,} (Test FPR: {tm['fpr']*100:.3f}%)")
        log_msg(f"    Test Detection Rate: {tm['tp']:,} / {tm['total_malicious']:,} (Test TPR: {tm['tpr']*100:.2f}%)")
        log_msg(f"    Test Precision:      {tm['precision']*100:.2f}% | Recall: {tm['recall']*100:.2f}% | F1: {tm['f1']:.4f}")

    # ---------------------------------------------------------
    # 7. Serialize Artifacts and Complete Provenance Metadata
    # ---------------------------------------------------------
    log_msg("Serializing model artifacts and provenance records...")
    model_path = output_dir / "model.joblib"
    checksum_path = output_dir / "model.joblib.sha256"
    metadata_path = output_dir / "metadata.json"
    test_eval_path = output_dir / "test_evaluation.json"
    
    # 7.1 Save model
    joblib.dump(clf, model_path, compress=3)
    model_sha256 = compute_file_sha256(model_path)
    checksum_path.write_text(model_sha256, encoding="utf-8")
    log_msg(f"  Saved model to {model_path} (SHA-256: {model_sha256})")
    
    # 7.2 Save metadata
    metadata = {
        "model_name": "ember-v2-baseline-hgb",
        "model_version": "1.0.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "model_file_sha256": model_sha256,
        "environment": {
            "python_version": platform.python_version(),
            "scikit_learn_version": sklearn.__version__,
            "numpy_version": np.__version__,
            "joblib_version": joblib.__version__,
            "os": platform.platform(),
        },
        "dataset": {
            "source": "EMBER 2018 Feature Version 2",
            "feature_version": 2,
            "feature_dim": EMBER_TOTAL_DIM,
            "archive_sha256": "b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812",
            "training_partitions": [p.name for p in train_files],
            "test_partition": test_file.name,
            "total_supervised_samples": total_supervised,
            "train_samples": len(train_idx),
            "val_samples": len(val_idx),
            "test_samples": len(y_test_arr),
        },
        "data_leakage_controls": {
            "train_val_overlap_count": len(train_val_overlap),
            "train_test_overlap_count": len(train_test_overlap),
            "val_test_overlap_count": len(val_test_overlap),
            "unlabeled_records_in_supervised_loss": 0,
        },
        "training": {
            "algorithm": "HistGradientBoostingClassifier",
            "random_seed": 42,
            "hyperparameters": hgb_params,
            "iterations_completed": int(clf.n_iter_),
            "training_duration_seconds": round(train_duration, 2),
            "ingestion_duration_seconds": round(ingest_duration, 2),
            "peak_process_memory_mb": round(mem_after_train, 2),
        },
        "validation_performance": {
            "roc_auc": round(val_roc_auc, 6),
            "pr_auc": round(val_pr_auc, 6),
        },
        "calibrated_thresholds": calibrated_thresholds,
    }
    
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    log_msg(f"  Saved metadata to {metadata_path}")
    
    # 7.3 Save test evaluation results
    with open(test_eval_path, "w", encoding="utf-8") as f:
        json.dump(test_evaluation, f, indent=2)
    log_msg(f"  Saved test evaluation to {test_eval_path}")
    
    # 7.4 Verification roundtrip via EmberModelClassifier
    log_msg("Verifying model artifact roundtrip via EmberModelClassifier...")
    classifier_service = EmberModelClassifier(model_dir=output_dir, verify_checksum=True)
    if not classifier_service.is_loaded:
        raise RuntimeError("Classifier service failed to load newly trained model artifact!")
        
    dummy_input = np.ones((1, EMBER_TOTAL_DIM), dtype=np.float32)
    prob = classifier_service.predict_proba(dummy_input)
    log_msg(f"  Inference verification test: predicted probability = {prob[0]:.4f}")
    
    total_elapsed = time.time() - t_start
    log_msg(f"=== PIPELINE COMPLETED SUCCESSFULLY IN {total_elapsed:.1f}s ({total_elapsed/60:.2f} min) ===")


if __name__ == "__main__":
    run_pipeline()
