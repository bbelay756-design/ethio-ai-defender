"""
ETHIO-AI Defender — ML-12A: Local Benign Calibration Scoring Script
Evaluates the frozen EMBER baseline model on the local benign PE corpus.
Strictly static: Never executes PE files.
Preserves production integrity: Model outputs are isolated and advisory.
"""

import csv
import hashlib
import json
import math
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np

# Add repository root to Python path
REPO_ROOT = Path(r"C:\Users\MILKWAY\ethio-ai-defender")
sys.path.insert(0, str(REPO_ROOT))

from app.ml.ember_v2 import EMBERFeatureExtractor, EMBER_V2_TOTAL_DIM
from app.ml.classifier import TRUSTED_BASELINE_MODEL_SHA256, DEFAULT_PRIMARY_MODEL_DIR

MODEL_PATH = DEFAULT_PRIMARY_MODEL_DIR / "model.joblib"
THRESHOLDS = {
    "default_05": 0.500000,
    "target_1pct_fpr": 0.800395,
    "target_01pct_fpr": 0.966365,
}


def compute_sha256(data_or_path) -> str:
    hasher = hashlib.sha256()
    if isinstance(data_or_path, (str, Path)):
        with open(data_or_path, "rb") as f:
            while chunk := f.read(1048576):
                hasher.update(chunk)
    else:
        hasher.update(data_or_path)
    return hasher.hexdigest().lower()


def wilson_score_interval(successes: int, total: int, z: float = 1.95996) -> Tuple[float, float]:
    """Calculate Wilson score 95% confidence interval for a binomial proportion."""
    if total == 0:
        return (0.0, 0.0)
    p_hat = successes / total
    denominator = 1.0 + (z**2) / total
    centre_adjusted_probability = p_hat + (z**2) / (2 * total)
    adjusted_standard_deviation = math.sqrt((p_hat * (1 - p_hat) + (z**2) / (4 * total)) / total)
    lower_bound = (centre_adjusted_probability - z * adjusted_standard_deviation) / denominator
    upper_bound = (centre_adjusted_probability + z * adjusted_standard_deviation) / denominator
    return (max(0.0, float(lower_bound)), min(1.0, float(upper_bound)))


def load_authenticode_map() -> Dict[str, Dict[str, Any]]:
    auth_file = REPO_ROOT / "scratch" / "authenticode_results.json"
    if not auth_file.exists():
        return {}
    with open(auth_file, "r", encoding="utf-8-sig") as f:
        data = json.load(f)
    return {str(Path(item["Path"]).resolve()).lower(): item for item in data}


def load_wheel_records() -> Dict[str, Dict[str, Any]]:
    site_packages = REPO_ROOT / "venv" / "Lib" / "site-packages"
    records = {}
    for record_path in site_packages.glob("*.dist-info/RECORD"):
        pkg = record_path.parent.name.split("-")[0]
        with open(record_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) >= 3 and row[1].startswith("sha256="):
                    abs_path = (record_path.parent.parent / row[0]).resolve()
                    records[str(abs_path).lower()] = {
                        "package": pkg,
                        "expected_sha": row[1].split("sha256=")[1],
                        "size": int(row[2]) if row[2] else 0,
                    }
    return records


def main():
    print("=" * 80)
    print("ETHIO-AI Defender — ML-12A Local Benign Calibration Audit")
    print("=" * 80)

    # 1. Verify Model Integrity
    if not MODEL_PATH.exists():
        print(f"ERROR: Model artifact not found at {MODEL_PATH}")
        sys.exit(1)

    computed_model_sha = compute_sha256(MODEL_PATH)
    print(f"Model Artifact: {MODEL_PATH}")
    print(f"Expected SHA-256: {TRUSTED_BASELINE_MODEL_SHA256}")
    print(f"Computed SHA-256: {computed_model_sha}")

    if computed_model_sha != TRUSTED_BASELINE_MODEL_SHA256:
        print("ERROR: Cryptographic hash mismatch for model artifact!")
        sys.exit(1)
    print("Model integrity verified successfully.\n")

    # Load frozen model
    print("Loading model.joblib...")
    model = joblib.load(MODEL_PATH)
    extractor = EMBERFeatureExtractor(feature_version=2, print_warning=False)
    print(f"Model loaded: {type(model).__name__}")
    print(f"Model classes: {getattr(model, 'classes_', 'N/A')}\n")

    # Load provenance catalogs
    auth_map = load_authenticode_map()
    wheel_records = load_wheel_records()
    print(f"Loaded {len(auth_map)} Authenticode records and {len(wheel_records)} wheel distribution records.")

    # 2. Discover Approved Local PE Binaries in Workspace
    venv_path = REPO_ROOT / "venv"
    pe_candidates = sorted(list(venv_path.rglob("*.exe")) + list(venv_path.rglob("*.dll")) + list(venv_path.rglob("*.pyd")))
    pe_candidates = sorted(list(set(pe_candidates)))
    print(f"Discovered {len(pe_candidates)} candidate PE binaries in venv.\n")

    # 3. Process Each Binary (Static-Only Extraction and Inference)
    results = []
    category_summary = {}
    provenance_summary = {"VERIFIED_LEGITIMATE": 0, "LIKELY_LEGITIMATE": 0, "UNKNOWN": 0, "EXCLUDED": 0}

    t0_all = time.time()
    for idx, pe_file in enumerate(pe_candidates, 1):
        rel_path = pe_file.relative_to(REPO_ROOT)
        pe_str = str(pe_file.resolve()).lower()

        try:
            with open(pe_file, "rb") as f:
                content = f.read()
        except Exception as e:
            print(f"[{idx}/{len(pe_candidates)}] Failed to read {rel_path}: {e}")
            provenance_summary["EXCLUDED"] += 1
            results.append({
                "path": str(rel_path),
                "status": "READ_ERROR",
                "error": str(e),
                "provenance_class": "EXCLUDED",
            })
            continue

        sha256 = compute_sha256(content)
        file_size = len(content)
        ext = pe_file.suffix.lower()

        # Check Authenticode and wheel provenance
        auth_info = auth_map.get(pe_str, {})
        auth_status = auth_info.get("Status", "NotChecked")
        signer = auth_info.get("Signer", None)

        record_info = wheel_records.get(pe_str, None)
        package_name = record_info["package"] if record_info else None

        # Determine Category and Provenance Class
        if auth_status == "Valid":
            if "Python Software Foundation" in (signer or ""):
                category = "Python Core Runtime (Signed PSF)"
            elif "Microsoft" in (signer or ""):
                category = "Microsoft CRT / Redistributable DLL (Signed MS)"
            else:
                category = "Signed Third-Party Binary"
            provenance_class = "VERIFIED_LEGITIMATE"
        elif "Scripts" in pe_file.parts and ext == ".exe":
            category = "Python CLI Entry-Point Launcher (Pip/Distlib)"
            provenance_class = "VERIFIED_LEGITIMATE"
        elif record_info is not None:
            if ext == ".pyd":
                category = f"Compiled C-Extension PYD ({package_name})"
            elif ext == ".exe":
                category = f"Build / Launcher Stub EXE ({package_name})"
            elif ext == ".dll":
                category = f"Bundled Library DLL ({package_name})"
            else:
                category = f"Wheel Asset ({package_name})"
            provenance_class = "VERIFIED_LEGITIMATE"
        else:
            category = "Unclassified Local Binary"
            provenance_class = "LIKELY_LEGITIMATE"

        # Static Feature Extraction
        t0_extract = time.perf_counter()
        features = extractor.feature_vector(content)
        t_extract = time.perf_counter() - t0_extract

        if features is None or len(features) != EMBER_V2_TOTAL_DIM or np.isnan(features).any():
            print(f"[{idx}/{len(pe_candidates)}] Feature extraction failed for {rel_path}")
            provenance_summary["EXCLUDED"] += 1
            results.append({
                "path": str(rel_path),
                "sha256": sha256,
                "file_size": file_size,
                "status": "EXTRACTION_FAILED",
                "provenance_class": "EXCLUDED",
            })
            continue

        # Static Model Inference
        features_2d = features.reshape(1, -1)
        proba = float(model.predict_proba(features_2d)[0, 1])

        flagged_05 = bool(proba >= THRESHOLDS["default_05"])
        flagged_1pct = bool(proba >= THRESHOLDS["target_1pct_fpr"])
        flagged_01pct = bool(proba >= THRESHOLDS["target_01pct_fpr"])

        provenance_summary[provenance_class] = provenance_summary.get(provenance_class, 0) + 1
        cat_group = category.split("(")[0].strip()
        category_summary[cat_group] = category_summary.get(cat_group, 0) + 1

        rec = {
            "path": str(rel_path),
            "filename": pe_file.name,
            "sha256": sha256,
            "file_size": file_size,
            "extension": ext,
            "category": category,
            "category_group": cat_group,
            "provenance_class": provenance_class,
            "auth_status": auth_status,
            "signer": signer,
            "package_name": package_name,
            "model_score": proba,
            "flagged_default_05": flagged_05,
            "flagged_1pct_fpr": flagged_1pct,
            "flagged_01pct_fpr": flagged_01pct,
            "extract_time_sec": round(t_extract, 4),
        }
        results.append(rec)

        if idx % 50 == 0 or idx == len(pe_candidates):
            print(f"Progress: [{idx}/{len(pe_candidates)}] Scored {rel_path.name} (score: {proba:.6f})")

    elapsed_total = time.time() - t0_all
    print(f"\nCompleted static scoring of {len(results)} binaries in {elapsed_total:.2f} seconds.")

    # 4. Filter Verified Legitimate Denominator
    verified_results = [r for r in results if r.get("provenance_class") == "VERIFIED_LEGITIMATE" and "model_score" in r]
    scores = np.array([r["model_score"] for r in verified_results], dtype=np.float64)
    n_verified = len(verified_results)

    print("\n" + "=" * 80)
    print("CALIBRATION AUDIT RESULTS (VERIFIED LEGITIMATE DENOMINATOR)")
    print("=" * 80)
    print(f"Total Discovered: {len(pe_candidates)}")
    print(f"Total Scored:     {len(results)}")
    print(f"Verified Benign:  {n_verified}")
    print(f"Excluded:         {provenance_summary['EXCLUDED']}")
    print(f"Unknown:          {provenance_summary.get('UNKNOWN', 0)}")

    # Score Distribution Metrics
    min_score = float(np.min(scores))
    max_score = float(np.max(scores))
    mean_score = float(np.mean(scores))
    median_score = float(np.median(scores))
    std_score = float(np.std(scores))
    p25 = float(np.percentile(scores, 25))
    p75 = float(np.percentile(scores, 75))
    p90 = float(np.percentile(scores, 90))
    p95 = float(np.percentile(scores, 95))
    p99 = float(np.percentile(scores, 99))

    print(f"\nScore Distribution:")
    print(f"  Min:    {min_score:.6f}")
    print(f"  P25:    {p25:.6f}")
    print(f"  Median: {median_score:.6f}")
    print(f"  Mean:   {mean_score:.6f} +/- {std_score:.6f}")
    print(f"  P75:    {p75:.6f}")
    print(f"  P90:    {p90:.6f}")
    print(f"  P95:    {p95:.6f}")
    print(f"  P99:    {p99:.6f}")
    print(f"  Max:    {max_score:.6f}")

    # False Positive Rates at Documented Thresholds
    fp_metrics = {}
    for th_name, th_val in THRESHOLDS.items():
        fp_count = int(np.sum(scores >= th_val))
        fp_rate = fp_count / n_verified if n_verified > 0 else 0.0
        ci_low, ci_high = wilson_score_interval(fp_count, n_verified)
        fp_metrics[th_name] = {
            "threshold": th_val,
            "fp_count": fp_count,
            "denominator": n_verified,
            "fp_rate": fp_rate,
            "fp_rate_pct": fp_rate * 100.0,
            "ci_95_low": ci_low,
            "ci_95_high": ci_high,
            "ci_95_low_pct": ci_low * 100.0,
            "ci_95_high_pct": ci_high * 100.0,
        }
        print(f"\nThreshold: {th_name} (tau = {th_val:.6f})")
        print(f"  False Positives: {fp_count} / {n_verified} ({fp_rate * 100.0:.3f}%)")
        print(f"  Wilson 95% CI:   [{ci_low * 100.0:.3f}%, {ci_high * 100.0:.3f}%]")

    # Identify any False Positives
    fps_at_05 = [r for r in verified_results if r["flagged_default_05"]]
    fps_at_1pct = [r for r in verified_results if r["flagged_1pct_fpr"]]
    fps_at_01pct = [r for r in verified_results if r["flagged_01pct_fpr"]]

    print(f"\nFalse Positive Detections:")
    print(f"  At tau = 0.500000: {len(fps_at_05)}")
    print(f"  At tau = 0.800395: {len(fps_at_1pct)}")
    print(f"  At tau = 0.966365: {len(fps_at_01pct)}")

    if fps_at_05:
        print("\nFlagged at tau >= 0.500000:")
        for r in sorted(fps_at_05, key=lambda x: x["model_score"], reverse=True):
            print(f"  Score: {r['model_score']:.6f} | Path: {r['path']} | Category: {r['category']}")

    # Breakdown by Category Group
    category_breakdown = {}
    for cat_name in sorted(category_summary.keys()):
        cat_items = [r for r in verified_results if r["category_group"] == cat_name]
        cat_scores = [r["model_score"] for r in cat_items]
        cat_n = len(cat_items)
        cat_fp_05 = sum(1 for s in cat_scores if s >= THRESHOLDS["default_05"])
        cat_fp_1pct = sum(1 for s in cat_scores if s >= THRESHOLDS["target_1pct_fpr"])
        cat_fp_01pct = sum(1 for s in cat_scores if s >= THRESHOLDS["target_01pct_fpr"])
        category_breakdown[cat_name] = {
            "count": cat_n,
            "mean_score": float(np.mean(cat_scores)) if cat_n else 0.0,
            "max_score": float(np.max(cat_scores)) if cat_n else 0.0,
            "fp_count_05": cat_fp_05,
            "fp_count_1pct": cat_fp_1pct,
            "fp_count_01pct": cat_fp_01pct,
        }

    # Save Complete Audit Artifact
    audit_artifact = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "milestone": "ML-12A",
            "model_name": "ember-v2-baseline-hgb-subset80k",
            "model_path": str(MODEL_PATH),
            "model_sha256": computed_model_sha,
            "feature_dim": EMBER_V2_TOTAL_DIM,
            "feature_extractor": "EMBERFeatureExtractor(feature_version=2)",
            "execution_duration_sec": round(elapsed_total, 2),
        },
        "corpus_summary": {
            "total_discovered": len(pe_candidates),
            "total_scored": len(results),
            "verified_benign_denominator": n_verified,
            "excluded_count": provenance_summary["EXCLUDED"],
            "unknown_count": provenance_summary.get("UNKNOWN", 0),
            "provenance_classes": provenance_summary,
            "category_counts": category_summary,
        },
        "score_distribution": {
            "min": min_score,
            "p25": p25,
            "median": median_score,
            "mean": mean_score,
            "std": std_score,
            "p75": p75,
            "p90": p90,
            "p95": p95,
            "p99": p99,
            "max": max_score,
        },
        "threshold_evaluations": fp_metrics,
        "category_breakdown": category_breakdown,
        "false_positive_details": {
            "fps_at_05": fps_at_05,
            "fps_at_1pct": fps_at_1pct,
            "fps_at_01pct": fps_at_01pct,
        },
        "per_sample_results": results,
    }

    out_json = REPO_ROOT / "scratch" / "ml12a_local_benign_audit.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(audit_artifact, f, indent=2)
    print(f"\nAudit results successfully saved to: {out_json}")


if __name__ == "__main__":
    main()
