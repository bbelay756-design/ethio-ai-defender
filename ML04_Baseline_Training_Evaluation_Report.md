# ETHIO-AI Defender -- ML-04 Baseline Training and Evaluation Report

**Document Version:** 1.0  
**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`  
**Date:** 2026-10-28  
**Experiment Status:** **COMPLETE -- SUCCESS**  
**Classification:** Research Baseline Artifact (Not Approved for Production Deployment)

---

## 1. Executive Summary

Milestone **ML-04** has executed the first reproducible EMBER 2018 Feature Version 2 baseline experiment using a memory-safe, balanced stratified subset of **80,000 samples** (40,000 benign, 40,000 malicious) with scikit-learn's `HistGradientBoostingClassifier`.

Key empirical findings:
1. **Preflight Resource Verification:**
   - Prior to execution: 3.49 GB available physical RAM (77% load) and 18.61 GB free on D: drive.
   - Peak physical RAM during fit was bounded to **~1.78 GiB**, leaving >1.6 GB of unallocated physical RAM headroom.
2. **Dataset Integrity & Leakage Controls:**
   - Unlabeled records (`-1`) were strictly excluded from supervised fitting.
   - Supervised subset fingerprint: `b236bf53c97cb614597ae388cd2b52de68aa559408c54c4f6c05a3836f0819c6`.
   - Cross-split leakage between Train, Validation, and Test partitions was verified at **0 overlapping hashes**.
3. **Validation & Test Discriminative Performance:**
   - **Validation ROC-AUC:** `0.9946` | **PR-AUC:** `0.9935`
   - **Held-Out Test ROC-AUC:** `0.9801` | **PR-AUC:** `0.9813`
4. **Operational Detection Rates (Fixed False Positive Rates):**
   - At target **1.0% FPR** (calibrated threshold $\tau_{1\%}^* = 0.80040$):
     - Validation Detection Rate: `91.41%` (Validation FPR: `1.00%`)
     - Held-Out Test Detection Rate: `85.53%` (Test FPR: `2.23%`)
   - At target **0.1% FPR** (calibrated threshold $\tau_{0.1\%}^* = 0.96636$):
     - Validation Detection Rate: `76.60%` (Validation FPR: `0.10%`)
     - Held-Out Test Detection Rate: `54.67%` (Test FPR: `0.20%`)
5. **Artifact Verification:**
   - Model serialized to `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib` (1.54 MB).
   - Cryptographic SHA-256: `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684`.
   - Model reload test passed with exact numerical parity on real validation records.

---

## 2. Dataset & Sampling Configuration

| Parameter | Specification | Empirical Value |
|---|---|---|
| **Feature Contract** | EMBER Feature Version 2 | 2,381 dimensions, float32 |
| **Available Supervised Training Pool** | Combined Partitions 0, 1, 3 | 260,364 samples (149,342 benign, 111,022 malicious) |
| **Excluded Unlabeled Samples** | Records with `label == -1` | **76,989 samples strictly excluded** |
| **Full Training Split Pool** | 80% Stratified Pool | 208,291 samples (`X_train.mmap`) |
| **Full Validation Split** | 20% Stratified Holdout | 52,073 samples (`X_val.mmap`) |
| **Held-Out Test Set** | Official EMBER 2018 Test | 200,000 samples (`test_features.jsonl`) |
| **Training Sampling Mode** | Balanced Stratified Subset | **80,000 samples** (40,000 benign / 40,000 malicious) |
| **Sampling Seed** | Deterministic PRNG | `seed=42` |
| **Selection Fingerprint** | SHA-256 of sorted indices | `b236bf53c97cb614597ae388cd2b52de68aa559408c54c4f6c05a3836f0819c6` |

*Documentation Transparency:* This model was trained on an 80,000-sample balanced stratified subset of the extracted training partitions. It does NOT represent training on the full 1-million sample EMBER corpus.

---

## 3. Estimator Configuration & Training Performance

```python
# HistGradientBoostingClassifier Configuration
estimator = HistGradientBoostingClassifier(
    loss="log_loss",
    learning_rate=0.05,
    max_iter=300,
    max_leaf_nodes=63,
    min_samples_leaf=50,
    l2_regularization=0.1,
    early_stopping=True,
    n_iter_no_change=15,
    validation_fraction=0.1,
    random_state=42,
)
```

- **Training Duration:** 750.80 seconds (12.51 minutes).
- **Iterations Completed:** 300 iterations before early stopping.
- **Peak Training RAM:** ~1.78 GiB (comfortably bounded below the 3.49 GB available physical RAM).
- **Training Warnings:** Zero warnings encountered.

---

## 4. Evaluation Results

### 4.1 Threshold Calibration on Full Validation Set (N = 52,073)

Thresholds were calibrated exclusively using the validation benign score distribution ($N_{\text{benign}} = 29,869$):
- **Default ($\tau = 0.50000$):** Detection Rate = `96.62%`, FPR = `3.55%`
- **Target 1.0% FPR ($\tau_{1\%}^* = 0.80040$):** Detection Rate = `91.41%`, FPR = `1.00%`
- **Target 0.1% FPR ($\tau_{0.1\%}^* = 0.96636$):** Detection Rate = `76.60%`, FPR = `0.10%`

*Statistical Support Note:* At 1.0% FPR, threshold calibration is anchored by `298` empirical false positive events. At 0.1% FPR, only `29` events occur, giving wider confidence bounds.

### 4.2 Frozen Held-Out Test Evaluation (N = 200,000)

Evaluated on `test_features.jsonl` (100,000 benign, 100,000 malicious) with all parameters and thresholds frozen:

| Operating Threshold | Target Purpose | Test Detection Rate (TPR) | Test False Alarm Rate (FPR) | Test F1-Score | Confusion Matrix [TN, FP, FN, TP] |
|---|---|---|---|---|---|
| **$\tau = 0.50000$** | Default Balanced | **94.15%** | **7.09%** | **0.9357** | `[92907, 7093, 5851, 94149]` |
| **$\tau_{1\%}^* = 0.80040$** | Enterprise SOC (1.0% FPR) | **85.53%** | **2.23%** | **0.9110** | `[97765, 2235, 14469, 85531]` |
| **$\tau_{0.1\%}^* = 0.96636$** | High-Confidence Block (0.1% FPR) | **54.67%** | **0.20%** | **0.7061** | `[99802, 198, 45325, 54675]` |

- **Summary ROC-AUC on Held-Out Test Set:** `0.9801`
- **Summary PR-AUC on Held-Out Test Set:** `0.9813`

---

## 5. Artifact Verification & Checksum

- **Model Path:** `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib`
- **Model Size:** 1,609,815 bytes (1.54 MB)
- **SHA-256 Checksum:** `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684`
- **Metadata Path:** `D:\ethio_ai_defender_artifacts\ember_baseline_v1\metadata.json`
- **Reload Parity Test:** Verified 10 / 10 sample predictions match within $10^{-5}$ absolute tolerance.

---

## 6. Milestone Acceptance Decision

| Requirement | Measured Evidence | Gate Result |
|---|---|---|
| Memory Safety Under 3.5 GB | Bounded to ~1.78 GiB; zero OOM errors | **PASS** |
| Label Exclusion Integrity | 76,989 unlabeled (-1) samples excluded | **PASS** |
| Data Leakage Isolation | 0 overlapping hashes across Train, Val, Test | **PASS** |
| Test Set Holdout Isolation | Test set evaluated only after freezing model/thresholds | **PASS** |
| Discriminative Performance | Test ROC-AUC = 0.9801 | **PASS** |
| Artifact Serialization | Model saved with SHA-256 sidecar and metadata contract | **PASS** |
| Reload Parity | Reloaded model outputs match exactly | **PASS** |

**Final ML-04 Status:** **PASS (EXPERIMENT COMPLETE)**  
*Next Phase:* Milestone ML-05 Re-Audit and ML-06 Controlled Integration Planning.
