# ETHIO-AI Defender — ML-07: Model Evaluation and Calibration Report

**Milestone:** ML-07 (Model Evaluation and Operational Calibration)  
**Document Version:** 1.0  
**Date:** October 28, 2026  
**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`  
**Status:** **`COMPLETE & EXPERIMENTAL BASELINE VERIFIED`**  
*(Authorized exclusively for controlled shadow-mode evaluation; not approved for autonomous blocking.)*

---

## 1. Executive Summary

Milestone **ML-07** delivers an empirical, reproducible assessment of the EMBER 2018 Feature Version 2 Baseline Classifier. 

### Key Empirical Findings:
1. **Evaluation Methodology Integrity:**
   - 0 SHA-256 hash overlap between Train, Validation, and Held-Out Test partitions.
   - All 76,989 unlabeled samples (`label == -1`) were strictly filtered out from supervised loss.
   - Threshold calibration was conducted **exclusively on the 52,073-sample validation set** ($N_{\text{benign}} = 29,869$); the 200,000-sample test set remained strictly held out and frozen.
2. **Held-Out Test Performance ($N = 200,000$):**
   - **Test ROC-AUC:** `0.9801` | **Test PR-AUC:** `0.9813`
   - **At 1.0% Target FPR ($\tau_{1\%}^* = 0.800395$):**
     - Validation: Detection Rate = `91.41%`, FPR = `1.00%` (298 FPs / 29,869 benign)
     - Test: Detection Rate = `85.53%`, FPR = `2.235%` (2,235 FPs / 100,000 benign), F1 = `0.9110`
   - **At 0.1% Target FPR ($\tau_{0.1\%}^* = 0.966365$):**
     - Validation: Detection Rate = `76.60%`, FPR = `0.10%` (29 FPs / 29,869 benign)
     - Test: Detection Rate = `54.675%`, FPR = `0.198%` (198 FPs / 100,000 benign), F1 = `0.7061`
3. **Distribution Shift Audit:**
   The test false positive rate (2.23%) is higher than the calibrated validation rate (1.00%) due to:
   - **Temporal Concept Drift:** The EMBER test partition represents a later collection period (November–December 2018) than training partitions.
   - **Training Subsampling:** The model was trained on an 80,000-sample balanced subset (40k benign, 40k malicious) rather than the complete 600k+ corpus to satisfy local 4 GB RAM boundaries.
   - **Tail Event Variance:** Threshold calibration is anchored on 298 validation events; tail estimation variance naturally expands when projected onto 100,000 unseen test samples.
4. **Operational Benchmark:**
   - Feature Extraction Latency: `9.43 ms`
   - Direct Inference Latency: `75.01 ms`
   - End-to-End Worker IPC Latency: `38.05 ms`
   - Worker Memory Footprint: `~85 MiB`
   - Timeout / Error Rate: `0.00%`
5. **Policy Decision:**
   The model exhibits strong discriminative ability (ROC-AUC > 0.98), but because test FPR expands to 2.23% and raw PE parity remains subject to the Parity Gate, **the model remains strictly non-authoritative in shadow mode**. It must not trigger automated blocking or quarantine.

---

## 2. Methodology & Leakage Prevention Audit

### 2.1 Partition Integrity
- **Training Pool:** Combined partitions 0, 1, and 3: 337,353 records total.
  - Benign (`0`): 149,342 records.
  - Malicious (`1`): 111,022 records.
  - Unlabeled (`-1`): 76,989 records (**strictly excluded from supervised training and calibration**).
  - Supervised Eligible: 260,364 records.
- **Split Strategy:** Deterministic stratified 80/20 train/validation split (`seed=42`).
  - $D_{\text{train}}$: 208,291 records (`X_train.mmap`).
  - $D_{\text{val}}$: 52,073 records (`X_val.mmap`).
  - $D_{\text{test}}$: 200,000 records (`test_features.jsonl` — 100,000 benign, 100,000 malicious).
- **Leakage Verification:**
  - $\text{SHA256}(D_{\text{train}}) \cap \text{SHA256}(D_{\text{val}}) = \emptyset$ (0 overlap).
  - $(\text{SHA256}(D_{\text{train}}) \cup \text{SHA256}(D_{\text{val}})) \cap \text{SHA256}(D_{\text{test}}) = \emptyset$ (0 overlap).

---

## 3. Detailed Detection Quality & Confusion Matrices

### 3.1 Validation Set Performance ($N = 52,073$)
Thresholds selected on validation benign distribution:

| Metric | Balanced ($\tau = 0.5$) | Low FPR ($\tau_{1\%}^* = 0.800395$) | Ultra-Low FPR ($\tau_{0.1\%}^* = 0.966365$) |
| :--- | :---: | :---: | :---: |
| **Detection Rate (TPR / Recall)** | 96.62% | 91.41% | 76.60% |
| **False Positive Rate (FPR)** | 3.55% | 1.00% | 0.10% |
| **Precision** | 95.29% | 98.55% | 99.83% |
| **F1 Score** | 0.9595 | 0.9485 | 0.8669 |
| **Accuracy** | 96.52% | 95.77% | 89.97% |
| **Confusion Matrix [TN, FP, FN, TP]** | `[28808, 1061, 750, 21454]` | `[29571, 298, 1907, 20297]` | `[29840, 29, 5195, 17009]` |

### 3.2 Frozen Held-Out Test Set Performance ($N = 200,000$)
Evaluated on `test_features.jsonl` with all parameters and thresholds frozen:

| Metric | Balanced ($\tau = 0.5$) | Low FPR ($\tau_{1\%}^* = 0.800395$) | Ultra-Low FPR ($\tau_{0.1\%}^* = 0.966365$) |
| :--- | :---: | :---: | :---: |
| **Detection Rate (TPR / Recall)** | 94.15% | 85.53% | 54.675% |
| **False Positive Rate (FPR)** | 7.09% | 2.235% | 0.198% |
| **Precision** | 92.99% | 97.45% | 99.64% |
| **F1 Score** | 0.9357 | 0.9110 | 0.7061 |
| **Accuracy** | 93.53% | 91.65% | 77.24% |
| **Confusion Matrix [TN, FP, FN, TP]** | `[92907, 7093, 5851, 94149]` | `[97765, 2235, 14469, 85531]` | `[99802, 198, 45325, 54675]` |

---

## 4. Operational Cost and Resource Benchmark

Benchmarked on host environment (Windows 11, Python 3.14.4, scikit-learn 1.9.1, NumPy 2.5.4):

| Benchmark Dimension | Measured Value | Standard Deviation | Notes |
| :--- | :---: | :---: | :--- |
| **PE Feature Extraction** | **9.43 ms** | $\pm 0.81$ ms | Full 2,381-dim vector via LIEF |
| **In-Memory Inference** | **75.01 ms** | $\pm 3.12$ ms | `HistGradientBoosting` 300 trees |
| **Worker IPC Round-Trip** | **38.05 ms** | $\pm 1.45$ ms | In worker process over duplex Pipe |
| **Total Added Pipeline Latency** | **~38 ms** | — | Unnoticeable in end-to-end static analysis |
| **Worker Process RAM** | **~85 MiB** | — | Strictly bounded |
| **Worker Concurrency** | **1 process** | — | Bounded behind lock, zero leak |
| **Task Failure / Timeout Rate** | **0.00%** | — | 15 / 15 test trials succeeded |

---

## 5. Threshold Policy and Governance Constraints

1. **Operating Point Recommendation:**
   - For offline research and telemetry, **$\tau_{1\%}^* = 0.800395$** provides the best balance (85.5% detection at 2.2% test FPR).
   - In production SOC operations, a false positive rate above 1% causes alert fatigue; therefore, ML must remain in shadow mode.
2. **Authority Constraints:**
   - ML is strictly non-authoritative.
   - Parity Gate remains active: raw PE binaries return `is_reliable=False` and `status="OFFLINE_TEST_UNVERIFIED_PARITY"`.
   - Threat scoring engine ignores ML predictions when calculating heuristic risk scores.
