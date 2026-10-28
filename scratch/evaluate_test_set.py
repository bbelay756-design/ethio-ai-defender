import json
import math
import sys
import time
from pathlib import Path
import numpy as np
import joblib
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)

repo_root = Path(r"C:\Users\MILKWAY\ethio-ai-defender")
sys.path.insert(0, str(repo_root))

from app.ml.ember_adapter import EmberDatasetAdapter, EMBER_TOTAL_DIM

model_path = Path(r"D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib")
meta_path = Path(r"D:\ethio_ai_defender_artifacts\ember_baseline_v1\metadata.json")
test_file = repo_root / "storage" / "ember2018" / "test_features.jsonl"

print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting Independent Test Set Evaluation...")
print(f"Loading model: {model_path}")
clf = joblib.load(model_path)
with open(meta_path, "r") as f:
    meta = json.load(f)

adapter = EmberDatasetAdapter(feature_version=2, strict=True)

batch_size = 5000
test_labels = []
test_probs = []

batch_records = []
t0 = time.time()
processed = 0

print(f"Streaming from {test_file.name}...")
with open(test_file, "r", encoding="utf-8") as f:
    for line_idx, line in enumerate(f, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        record = json.loads(stripped)
        batch_records.append(record)
        
        if len(batch_records) >= batch_size:
            batch_X = np.empty((len(batch_records), EMBER_TOTAL_DIM), dtype=np.float32)
            for i, r in enumerate(batch_records):
                vec, lbl = adapter.parse_record(r, split="test")
                batch_X[i] = vec
                test_labels.append(int(lbl))
            
            probs = clf.predict_proba(batch_X)[:, 1]
            test_probs.extend(probs.tolist())
            processed += len(batch_records)
            batch_records = []
            
            if processed % 50000 == 0:
                elapsed = time.time() - t0
                rate = processed / elapsed
                print(f"  Processed {processed:,}/200,000 ({rate:,.0f} samples/s, elapsed: {elapsed:.1f}s)...")

if batch_records:
    batch_X = np.empty((len(batch_records), EMBER_TOTAL_DIM), dtype=np.float32)
    for i, r in enumerate(batch_records):
        vec, lbl = adapter.parse_record(r, split="test")
        batch_X[i] = vec
        test_labels.append(int(lbl))
    probs = clf.predict_proba(batch_X)[:, 1]
    test_probs.extend(probs.tolist())
    processed += len(batch_records)

total_time = time.time() - t0
print(f"Inference on {processed:,} samples completed in {total_time:.2f}s ({processed/total_time:,.0f} samples/s)\n")

y_test = np.array(test_labels, dtype=np.int32)
y_prob = np.array(test_probs, dtype=np.float64)

# Calculate global discrimination metrics
roc_auc = roc_auc_score(y_test, y_prob)
pr_auc = average_precision_score(y_test, y_prob)

print(f"=== GLOBAL DISCRIMINATIVE METRICS ===")
print(f"Test ROC-AUC: {roc_auc:.8f} (Reported: {meta['test_summary']['roc_auc']:.8f})")
print(f"Test PR-AUC:  {pr_auc:.8f} (Reported: {meta['test_summary']['pr_auc']:.8f})")

def wilson_interval(count, nobs, alpha=0.05):
    """Wilson score confidence interval for binomial proportions."""
    if nobs == 0:
        return (0.0, 0.0)
    z = 1.95996  # 95% CI
    p = count / nobs
    denom = 1 + z**2 / nobs
    centre = (p + z**2 / (2 * nobs)) / denom
    spread = z * math.sqrt(p * (1 - p) / nobs + z**2 / (4 * nobs**2)) / denom
    return max(0.0, centre - spread), min(1.0, centre + spread)

thresholds = {
    "tau_05": (0.5, "Default Balanced (0.5)"),
    "tau_1pct": (meta["calibrated_thresholds"]["fpr_1pct_target"]["threshold"], "Enterprise SOC Target 1.0% FPR"),
    "tau_01pct": (meta["calibrated_thresholds"]["fpr_01pct_target"]["threshold"], "High-Confidence Target 0.1% FPR"),
}

results_summary = {
    "test_samples": len(y_test),
    "benign_count": int(np.sum(y_test == 0)),
    "malicious_count": int(np.sum(y_test == 1)),
    "roc_auc": roc_auc,
    "pr_auc": pr_auc,
    "evaluation_duration_seconds": total_time,
    "threshold_evaluations": {},
}

for key, (tau, desc) in thresholds.items():
    y_pred = (y_prob >= tau).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    
    total_b = tn + fp
    total_m = tp + fn
    fpr = fp / total_b
    tpr = tp / total_m
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tpr
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) > 0 else 0
    acc = (tp + tn) / len(y_test)
    
    fpr_ci_low, fpr_ci_high = wilson_interval(fp, total_b)
    tpr_ci_low, tpr_ci_high = wilson_interval(tp, total_m)
    
    print(f"\n=======================================================")
    print(f"Operational Operating Point: {key} ({desc})")
    print(f"Threshold: tau = {tau:.16f}")
    print(f"-------------------------------------------------------")
    print(f"Confusion Matrix: TN={tn:,}, FP={fp:,}, FN={fn:,}, TP={tp:,}")
    print(f"Total Benign Evaluated:    {total_b:,}")
    print(f"Total Malicious Evaluated: {total_m:,}")
    print(f"False Positives:           {fp:,} / {total_b:,} (FPR: {fpr*100:.3f}% [95% CI: {fpr_ci_low*100:.3f}% - {fpr_ci_high*100:.3f}%])")
    print(f"True Positives (Recall):   {tp:,} / {total_m:,} (TPR: {tpr*100:.3f}% [95% CI: {tpr_ci_low*100:.3f}% - {tpr_ci_high*100:.3f}%])")
    print(f"False Negatives (Misses):  {fn:,} / {total_m:,} (FNR: {(fn/total_m)*100:.3f}%)")
    print(f"Precision:                 {prec*100:.3f}%")
    print(f"F1-Score:                  {f1:.6f}")
    print(f"Accuracy:                  {acc*100:.3f}%")
    
    # Verify match with recorded metadata
    meta_sub = "metrics_at_" + key
    rep_metrics = meta["test_summary"][meta_sub]
    rep_cm = rep_metrics["confusion_matrix"]
    match = (tn == rep_cm["tn"] and fp == rep_cm["fp"] and fn == rep_cm["fn"] and tp == rep_cm["tp"])
    print(f"Matches Metadata Recorded CM Exactly: {match}")
    
    results_summary["threshold_evaluations"][key] = {
        "description": desc,
        "threshold": tau,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "total_benign": int(total_b),
        "total_malicious": int(total_m),
        "fpr": float(fpr),
        "fpr_ci95": [float(fpr_ci_low), float(fpr_ci_high)],
        "tpr": float(tpr),
        "tpr_ci95": [float(tpr_ci_low), float(tpr_ci_high)],
        "fnr": float(fn / total_m),
        "precision": float(prec),
        "recall": float(recall),
        "f1": float(f1),
        "accuracy": float(acc),
        "exact_metadata_match": match,
    }

out_file = repo_root / "scratch" / "ml10_independent_test_evaluation.json"
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(results_summary, f, indent=2)

print(f"\nWritten independent evaluation results to {out_file}")
