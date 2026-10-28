# ETHIO-AI Defender — ML-10: Independent Baseline Evaluation and Data Leakage Audit

**Milestone:** ML-10 (Independent Baseline Evaluation and Data Leakage Audit)  
**Date:** October 28, 2026  
**Auditor / Agent:** Antigravity Autonomous Security Engineer  
**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`  
**Model Under Audit:** `ember-v2-baseline-hgb-subset80k`  
**Artifact Directory:** `D:\ethio_ai_defender_artifacts\ember_baseline_v1`  
**Final Classification:** **`EVALUATION REPRODUCED (WITH DOCUMENTED OPERATIONAL CALIBRATION DRIFT)`**

---

## 1. Executive Summary

Milestone **ML-10** provides a rigorous, independent audit of the reported EMBER v2 baseline model artifact and its associated ML-09 evaluation claims. The audit verified the model's cryptographic provenance, performed line-by-line reconciliation of the 5.5 GB EMBER dataset, analyzed data leakage and cross-split contamination, evaluated the mathematical methodology, and independently reproduced the entire 200,000-sample test evaluation from scratch.

### Summary of Verified Outcomes:
1. **Provenance Authenticated:** The model artifact `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib` (1,609,815 bytes) was verified against its SHA-256 checksum **`f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684`**. The hash covers strictly the single `model.joblib` binary. Internal estimator telemetry (`classes_=[0, 1]`, `n_features_in_=2381`, `n_iter_=300`, 301 log-loss loss histories) and matching staged memory-mapped matrices (`X_train.mmap`, `X_val.mmap` in `D:\ethio_ai_defender_artifacts\staged`) prove the model was genuinely trained by the project pipeline and not loaded from an opaque pre-existing third-party binary.
2. **Dataset Reconciled (537,353 Total Records):** Full streaming reconciliation across all four `.jsonl` files confirmed:
   - `train_features_0.jsonl`: 50,000 records (50,000 benign)
   - `train_features_1.jsonl`: 158,158 records (52,338 benign, 63,713 malicious, 42,107 unlabeled)
   - `train_features_3.jsonl`: 129,195 records (47,004 benign, 47,309 malicious, 34,882 unlabeled)
   - `test_features.jsonl`: 200,000 records (100,000 benign, 100,000 malicious)
   - **Zero malformed lines, zero missing labels, zero intra-file duplicate hashes**.
3. **Data Leakage Disproven at Hash Level:** Cross-split duplicate hash analysis between all 337,353 training records and all 200,000 test records yielded **exactly 0 overlapping SHA-256 hashes**.
4. **Temporal Partitioning Established:** The dataset enforces a true temporal split. Training partition samples appeared between December 2006 and June 2018 (`2018-06`). Test samples appeared exclusively in November and December 2018 (`2018-11`: 100k, `2018-12`: 100k), presenting a realistic 5-month temporal gap.
5. **Malware Family Overlap Identified:** While hash overlap is 0, AVClass family analysis revealed that **668 malware families** appear in both train and test partitions. This reflects real-world malware lineage and signature evolution rather than synthetic data leakage.
6. **100% Mathematical Reproduction of ML-09 Test Evaluation:**
   - Evaluated 200,000 test samples in streaming memory-safe batches (445.76s).
   - **Test ROC-AUC:** `0.98012230` (Reported: `0.98012230` — bit-for-bit exact).
   - **Test PR-AUC:** `0.98125902` (Reported: `0.98125902` — bit-for-bit exact).
   - **Confusion Matrices at all operational points matched down to the single sample**.
7. **Key Vulnerability Uncovered (Calibration Drift / Generalization Gap):**
   - The threshold calibrated on the validation set for **1.0% target FPR** ($\tau = 0.800395$) produces **2.235% FPR** (2,235 false positives out of 100,000 benign files) on unseen test data.
   - The threshold calibrated for **0.1% target FPR** ($\tau = 0.966365$) produces **0.198% FPR** (198 false positives out of 100,000 benign files) on unseen test data.
   - **Recommendation:** Do not market or rely on validation-calibrated thresholds as production SLA guarantees. Operational thresholds must be continually re-calibrated on live telemetry with active human-in-the-loop review.

---

## 2. Phase A: Verified Model Provenance

### 2.1 Artifact Inventory and Cryptographic Integrity
The model artifact directory [`D:\ethio_ai_defender_artifacts\ember_baseline_v1`](file:///D:/ethio_ai_defender_artifacts/ember_baseline_v1) was inspected and verified using PowerShell `Get-FileHash`:

| File Name | Size (Bytes) | Cryptographic SHA-256 Digest | Scope of Checksum |
| :--- | :---: | :--- | :--- |
| **`model.joblib`** | 1,609,815 | `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684` | **Target binary** |
| **`model.joblib.sha256`** | 80 | `961517f0898a8ff45dee38ada39732b339b909dd39905dce18156d96ad0c09ab` | Sidecar text file |
| **`metadata.json`** | 5,871 | `d362f804aaf1fe52530955e5c34f8e2b8ef93f57998a065227e0ef97befba1a3` | Provenance metadata |
| **`evaluation_results.json`** | 3,803 | `8bb55e27a8f2a3d625da1f9d81b500f0df27817c8923f9488a323b009cb4dedd` | Recorded metrics |

> [!IMPORTANT]
> The recorded SHA-256 digest `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684` covers **strictly the single `model.joblib` file**, not a multi-file manifest. The sidecar file content is formatted as standard coreutils syntax:
> `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684  model.joblib`.

### 2.2 Estimator Architecture and Training Hyperparameters
The deserialized model object is an instance of scikit-learn's `HistGradientBoostingClassifier`:
- **Model Name:** `ember-v2-baseline-hgb-subset80k`
- **Class Mapping:** `classes_ = array([0, 1])`
  - Negative Class (`0`): Benign PE executable
  - Positive Class (`1`): Malicious PE executable
- **Input Dimension:** `n_features_in_ = 2381` (exact EMBER v2 feature vector length)
- **Hyperparameters:**
  ```python
  HistGradientBoostingClassifier(
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
- **Training Iterations:** Exactly 300 iterations were completed (`n_iter_ = 300`).
- **Internal Optimization Progression:**
  - `train_score_` contains 301 evaluations progressing monotonically from `-0.6931` to `-0.04163456`.
  - `validation_score_` contains 301 evaluations progressing from `-0.6931` to `-0.09316075`.
- **Staged Dataset Footprint:** Staged training memory-mapped arrays located at [`D:\ethio_ai_defender_artifacts\staged`](file:///D:/ethio_ai_defender_artifacts/staged) verify direct local lineage:
  - `X_train.mmap`: 1,983,763,484 bytes (208,291 rows $\times$ 2,381 float32)
  - `y_train.mmap`: 208,291 bytes (208,291 rows int8)
  - `X_val.mmap`: 495,943,252 bytes (52,073 rows $\times$ 2,381 float32)
  - `y_val.mmap`: 52,073 bytes (52,073 rows int8)

### 2.3 Subsampling Methodology
- Full supervised pool in training partitions: 260,364 samples.
- Stratified 80/20 train/validation split:
  - 80% Training Pool: 208,291 samples
  - 20% Validation Pool: 52,073 samples
- To respect physical RAM constraints (<3.5 GB physical memory budget), a balanced stratified subset of **80,000 samples** (40,000 benign, 40,000 malicious) was sampled from the 208,291 training pool with deterministic PRNG `seed=42`.
- Selection Fingerprint: SHA-256 of sorted sample row indices = **`b236bf53c97cb614597ae388cd2b52de68aa559408c54c4f6c05a3836f0819c6`**.
- *Provenance Verdict:* The model was genuinely fitted by the local pipeline using the documented memory-safe subset procedure.

---

## 3. Phase B: Reconciled Dataset Audit

Full streaming reconciliation of all four `.jsonl` files in [`storage/ember2018`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/ember2018) was executed via independent regex- and parser-based verification:

### 3.1 Partition Verification Table

| File Name | File Size (Bytes) | Exact Line Count | Benign (`0`) | Malicious (`1`) | Unlabeled (`-1`) | Malformed Lines | Missing Labels | Intra-File Duplicate Hashes | Schema Check |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`train_features_0.jsonl`** | 566,173,907 | 50,000 | 50,000 | 0 | 0 | 0 | 0 | 0 | **PASS (v2)** |
| **`train_features_1.jsonl`** | 1,659,892,947 | 158,158 | 52,338 | 63,713 | 42,107 | 0 | 0 | 0 | **PASS (v2)** |
| **`train_features_3.jsonl`** | 1,376,529,640 | 129,195 | 47,004 | 47,309 | 34,882 | 0 | 0 | 0 | **PASS (v2)** |
| **`test_features.jsonl`** | 1,869,447,260 | 200,000 | 100,000 | 100,000 | 0 | 0 | 0 | 0 | **PASS (v2)** |
| **Total Corpus** | **5,472,043,754** | **537,353** | **249,342** | **211,022** | **76,989** | **0** | **0** | **0** | **PASS** |

### 3.2 Feature Schema Compatibility
Every examined record contains all 12 mandatory EMBER v2 keys:
`sha256`, `appeared`, `label`, `histogram` (256), `byteentropy` (256), `strings` (104), `general` (10), `header` (62), `section` (255), `imports` (1280), `exports` (128), and `datadirectories` (30). The total feature dimension is verified at 2,381.

### 3.3 Data Leakage and Overlap Audit
1. **Hash Overlap:**
   - Unique hashes in training partitions: **337,353**
   - Unique hashes in test partition: **200,000**
   - Total unique SHA-256 hashes across entire dataset: **537,353**
   - **Cross-Split Hash Duplicates ($\text{Train} \cap \text{Test}$): 0**. No PE sample hash appears in both training and test partitions.
2. **Temporal Split Verification (`appeared` field):**
   - Training partitions: samples appeared between December 2006 (`2006-12`) and June 2018 (`2018-06`).
   - Test partition: exactly 100,000 samples appeared in November 2018 (`2018-11`) and exactly 100,000 samples appeared in December 2018 (`2018-12`).
   - The test partition is a true, forward-looking temporal holdout with a 5-month temporal gap (July–October 2018).
3. **Malware Family Overlap (`avclass` metadata):**
   - Training partitions contain 2,066 unique labeled malware families.
   - Test partition contains 916 unique labeled malware families.
   - **668 families appear in both partitions** (e.g., `installmonster`, `zusy`, `fareit`, `adposhel`, `emotet`, `upatre`, `razy`).
   - *Audit Assessment:* This family-level co-occurrence represents legitimate temporal evolution of existing malware campaigns; it is not sample-level data leakage.

---

## 4. Phase C: Evaluation Methodology Audit

### 4.1 Metric Definitions & Computation
- **Probability Prediction:** $p(x) = P(y = 1 \mid x)$ generated by `clf.predict_proba(X)[:, 1]`.
- **Binary Decision:** $\hat{y} = \mathbb{I}(p(x) \ge \tau)$ where $\tau \in [0, 1]$.
- **ROC-AUC:** Area under the Receiver Operating Characteristic curve computed by `sklearn.metrics.roc_auc_score(y_true, y_prob)`.
- **PR-AUC:** Average Precision computed by `sklearn.metrics.average_precision_score(y_true, y_prob)`.
- **Confusion Matrix:**
  - True Negative ($TN$): $y = 0, \hat{y} = 0$
  - False Positive ($FP$): $y = 0, \hat{y} = 1$
  - False Negative ($FN$): $y = 1, \hat{y} = 0$
  - True Positive ($TP$): $y = 1, \hat{y} = 1$
- **Rates:**
  - $\text{FPR} = \frac{FP}{TN + FP} = \frac{FP}{N_{\text{benign}}}$
  - $\text{TPR} = \frac{TP}{TP + FN} = \frac{TP}{N_{\text{malicious}}}$ (Recall)
  - $\text{Precision} = \frac{TP}{TP + FP}$
  - $\text{F1} = \frac{2 \cdot \text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$

### 4.2 Threshold Selection and Leakage Verification
- The threshold selection policy implemented in [`app/ml/evaluator.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/evaluator.py#L63) is:
  $$\tau^* = \operatorname{argmax}_{\tau} \{ \text{TPR}(\tau) \mid \text{FPR}_{\text{val}}(\tau) \le \text{target\_fpr} \}$$
- Thresholds were calibrated exclusively using the 52,073 validation samples (`X_val.mmap`, `y_val.mmap`), of which $N_{\text{benign}} = 29,869$.
- **Verification:** The test set was **NEVER** accessed, consulted, or sampled during threshold selection or feature scaling. There was zero test-set leakage into threshold selection.

### 4.3 The Calibration Drift / Generalization Gap
While the threshold calibration was methodologically pure (leakage-free), evaluating the validation-calibrated thresholds on the future test set revealed substantial calibration drift:

1. **Target 1.0% FPR Operating Point:**
   - Selected Threshold: $\tau_{1\%}^* = 0.8003951606744594$
   - Validation Performance: $\text{FPR} = \frac{298}{29,869} = 0.998\% \approx 1.00\%$
   - Unseen Test Performance: $\text{FPR} = \frac{2,235}{100,000} = \mathbf{2.235\%}$ (**2.24x higher than target**)
2. **Target 0.1% FPR Operating Point:**
   - Selected Threshold: $\tau_{0.1\%}^* = 0.9663647691558608$
   - Validation Performance: $\text{FPR} = \frac{29}{29,869} = 0.097\% \approx 0.10\%$
   - Unseen Test Performance: $\text{FPR} = \frac{198}{100,000} = \mathbf{0.198\%}$ (**1.98x higher than target**)

> [!WARNING]
> **Operational Risk:** In a production endpoint or perimeter environment inspecting 100,000 benign files daily, deploying $\tau = 0.8004$ under the assumption of a "1% FPR" would result in **2,235 false alerts per day** rather than 1,000. Operating threshold labels must be documented as design-time calibration targets, not production SLAs.

---

## 5. Phase D: Independent Reproduction Results

The model was loaded from [`D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib`](file:///D:/ethio_ai_defender_artifacts/ember_baseline_v1/model.joblib) and evaluated against both the 52,073 validation records and the 200,000 test records.

### 5.1 Validation Set Reproduction ($N = 52,073$)
Execution time: 6.14 seconds.

| Metric / Threshold | Reported (ML-09) | Independently Computed (ML-10) | Exact Match |
| :--- | :---: | :---: | :---: |
| **Validation ROC-AUC** | `0.99457882` | `0.99457882` | **YES** |
| **Validation PR-AUC** | `0.99346892` | `0.99346892` | **YES** |
| **$\tau = 0.5$ Confusion Matrix** | `[28808, 1061, 750, 21454]` | `[28808, 1061, 750, 21454]` | **YES** |
| $\tau = 0.5$ TPR / Recall | 96.622% | 96.622% | **YES** |
| $\tau = 0.5$ FPR | 3.552% | 3.552% | **YES** |
| **$\tau = 0.800395$ Confusion Matrix** | `[29571, 298, 1907, 20297]` | `[29571, 298, 1907, 20297]` | **YES** |
| $\tau = 0.800395$ TPR / Recall | 91.411% | 91.411% | **YES** |
| $\tau = 0.800395$ FPR | 0.998% | 0.998% | **YES** |
| **$\tau = 0.966365$ Confusion Matrix** | `[29840, 29, 5195, 17009]` | `[29840, 29, 5195, 17009]` | **YES** |
| $\tau = 0.966365$ TPR / Recall | 76.603% | 76.603% | **YES** |
| $\tau = 0.966365$ FPR | 0.097% | 0.097% | **YES** |

### 5.2 Held-Out Test Set Reproduction ($N = 200,000$)
Evaluated across all 200,000 lines of [`storage/ember2018/test_features.jsonl`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/ember2018/test_features.jsonl) in 445.76 seconds (449 samples/s):

- **Test Sample Size:** 200,000 (100,000 Benign, 100,000 Malicious)
- **Test ROC-AUC:** **`0.98012230`** (Reported: `0.98012230` — Bitwise exact)
- **Test PR-AUC:** **`0.98125902`** (Reported: `0.98125902` — Bitwise exact)

#### Detailed Per-Threshold Performance on Test Set:

| Metric | Threshold $\tau = 0.500000$ (Default) | Threshold $\tau = 0.800395$ (Target 1.0% FPR) | Threshold $\tau = 0.966365$ (Target 0.1% FPR) |
| :--- | :---: | :---: | :---: |
| **True Negatives ($TN$)** | 92,907 | 97,765 | 99,802 |
| **False Positives ($FP$)** | 7,093 | 2,235 | 198 |
| **False Negatives ($FN$)** | 5,851 | 14,469 | 45,325 |
| **True Positives ($TP$)** | 94,149 | 85,531 | 54,675 |
| **Negative Denominator ($N_{\text{benign}}$)** | 100,000 | 100,000 | 100,000 |
| **Positive Denominator ($N_{\text{malicious}}$)**| 100,000 | 100,000 | 100,000 |
| **False Positive Rate ($\text{FPR}$)** | **7.093%** | **2.235%** | **0.198%** |
| *FPR 95% Wilson Confidence Interval* | `[6.936%, 7.254%]` | `[2.145%, 2.328%]` | `[0.172%, 0.228%]` |
| **Detection Rate / Recall ($\text{TPR}$)** | **94.149%** | **85.531%** | **54.675%** |
| *TPR 95% Wilson Confidence Interval* | `[94.002%, 94.293%]` | `[85.312%, 85.748%]` | `[54.366%, 54.983%]` |
| **Precision** | 92.994% | 97.453% | 99.639% |
| **F1-Score** | 0.935679 | 0.911038 | 0.706062 |
| **Accuracy** | 93.528% | 91.648% | 77.239% |
| **Matches ML-09 Report Exactly** | **YES (100%)** | **YES (100%)** | **YES (100%)** |

---

## 6. Phase E: Recommendations and Acceptance Gate

### 6.1 Formal Model Classification

**Classification:** **`EVALUATION REPRODUCED`**

**Audit Determination Justification:**
1. **Provenance Defensible:** The model was genuinely trained using verified code on documented data subsets.
2. **Leakage Disproven:** Zero hash overlap between train and test partitions; strict forward-looking temporal separation (2006–June 2018 vs Nov–Dec 2018).
3. **Reproducibility Complete:** Both validation and test metrics were replicated with 100% exact numerical agreement across all metrics and sample counts.
4. **Generalization Limitation Documented:** The observed 2.235% test FPR at the 1.0% calibration target is an expected consequence of real-world temporal shift, not evaluation fraud or methodological error.

### 6.2 Production Safety and Isolation Guarantees
- **Zero Production Mutation:** No heuristic scoring algorithms, database tables, or decision thresholds in [`ThreatScoringEngine`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/threat_scoring.py) were modified.
- **Model Gating Maintained:** The Parity Gate in [`MLAnalyzer`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ml_analyzer.py) remains active (`is_reliable=False`), preventing raw PE analysis from driving blocking actions.
- **No Training or Deployment:** No models were retrained, calibrated, replaced, or deployed to active production.
- **Environment Untouched:** Zero Python packages were installed, updated, or removed.

### 6.3 Test Suite Verification
Existing automated tests verifying model and evaluator contracts were executed without modifications:
- `pytest tests/ml/test_baseline_model.py tests/ml/test_evaluator.py tests/ml/test_inference_parity.py tests/ml/test_feature_parity.py -v`
- **Result:** **21 passed in 9.46 seconds (Exit Code: 0)**. Zero failures, zero skips.

### 6.4 Strategic Next Steps
1. **Operational Base Rate Adjustment:** In production environments where malware prevalence is $\le 1\%$ (rather than the 50% balanced test set), precision at $\tau = 0.8004$ will drop substantially due to base-rate fallacy. Future milestones must model operational precision across variable class-imbalance scenarios (1:100 and 1:1,000).
2. **Dynamic Calibration Monitoring:** Implement telemetry logging to detect distribution shift on PE features over time.
3. **Maintain Conservative Gating:** Keep ML predictions restricted strictly to telemetry and shadow mode until operational FPR is validated on live benign Ethiopian software corpora.
