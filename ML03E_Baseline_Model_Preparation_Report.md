# ETHIO-AI Defender — ML-03E Baseline Model Preparation Report

**Document Version:** 1.0  
**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`  
**Date:** 2026-10-27  
**Gate Status:** **APPROVED FOR IMPLEMENTATION (ML-04)**

---

## 1. Executive Summary

Milestone **ML-03E** establishes the mathematical, architectural, and operational blueprint for training and evaluating an **EMBER 2018 Feature Version 2 Baseline Classifier**.

This preparation incorporates the empirical results from **ML-03D** (where 537,353 records were validated with zero errors) and guarantees:
1. **Strict Hold-Out Evaluation:** The official 200,000-sample test set (`test_features.jsonl`) is locked as an untouched holdout evaluation benchmark.
2. **Safe Label Enforcement:** Unlabeled records (`-1`) are strictly excluded from supervised binary cross-entropy loss.
3. **Zero New External Dependencies:** Evaluates scikit-learn's native `HistGradientBoostingClassifier` (installed and validated in scikit-learn 1.9.0) alongside the original reference LightGBM architecture.
4. **Security-Centric Evaluation:** Prioritizes operational metrics (**Detection Rate at 1.0% and 0.1% False Positive Rate**) over naive accuracy.
5. **Memory and Storage Governance:** Outlines $O(1)$ batch-streaming ingestion to operate within a 4 GB RAM ceiling and documented disk budgets.
6. **Zero Disruption to Existing Inference:** Defines an isolated classifier abstraction compatible with both the JSONL adapter and the existing raw-PE feature extractor ([`app/ml/ember_v2.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_v2.py)) without modifying production pipeline code.

---

## 2. Dataset Architecture & Split Design

### 2.1 Available Verified Partitions (from ML-03D)

The empirical validation in ML-03D established the following verified corpus:

| Partition File | Split Role | Total Records | Benign (`0`) | Malicious (`1`) | Unlabeled (`-1`) | Supervised Eligible |
|---|---|---|---|---|---|---|
| `test_features.jsonl` | **Held-Out Test** | 200,000 | 100,000 | 100,000 | 0 | 200,000 (Pure Test) |
| `train_features_0.jsonl` | **Training** | 50,000 | 50,000 | 0 | 0 | 50,000 |
| `train_features_1.jsonl` | **Training** | 158,158 | 52,338 | 63,713 | 42,107 | 116,051 |
| `train_features_3.jsonl` | **Training** | 129,195 | 47,004 | 47,309 | 34,882 | 94,313 |
| **Combined Training** | — | **337,353** | **149,342** | **111,022** | **76,989** | **260,364** |

### 2.2 Supervised Label Filtering Policy

```
Raw Record Label (y)
   ├── y == 0  ──> BENIGN (Supervised Target: 0)
   ├── y == 1  ──> MALICIOUS (Supervised Target: 1)
   └── y == -1 ──> UNLABELED (Filtered OUT from supervised training)
```

**Mandatory Enforcement:**
- Any sample where `label == -1` is dropped from supervised training and validation subsets prior to loss calculation.
- It is forbidden to map `-1` to `0` (benign). Unlabeled samples reflect telemetry from unconfirmed or ambiguous detections and would corrupt the benign decision boundary.
- Any sample with `label not in {-1, 0, 1}` triggers an immediate `ValueError` via [`EmberDatasetAdapter.validate_record()`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_adapter.py#L149).

### 2.3 Deterministic Stratified Validation Split

To prevent test-set leakage, model selection and threshold calibration will exclusively use a deterministic split carved out from the 260,364 supervised training samples:

- **Method:** `sklearn.model_selection.train_test_split` with `stratify=y_train` and `random_state=42`.
- **Split Ratio:** 80% Training / 20% Validation.
  - **Train Split ($D_{\text{train}}$):** ~208,291 samples (~119,474 benign, ~88,817 malicious).
  - **Validation Split ($D_{\text{val}}$):** ~52,073 samples (~29,868 benign, ~22,205 malicious).
- **Hold-Out Test Split ($D_{\text{test}}$):** Exactly 200,000 samples from `test_features.jsonl` (100,000 benign, 100,000 malicious).

### 2.4 Data Leakage & Deduplication Controls

1. **Hash Isolation Guarantee:** Every sample is tracked by its 64-character SHA-256 hex digest.
2. **Disjoint Sets Enforcement:** Prior to training, the pipeline must verify:
   $$\text{SHA256}(D_{\text{train}}) \cap \text{SHA256}(D_{\text{val}}) = \emptyset$$
   $$\left(\text{SHA256}(D_{\text{train}}) \cup \text{SHA256}(D_{\text{val}})\right) \cap \text{SHA256}(D_{\text{test}}) = \emptyset$$
   *(ML-03D confirmed 0 duplicate SHA-256 hashes between existing train and test partitions).*
3. **Temporal Integrity:** Samples from `test_features.jsonl` represent later temporal windows than training partitions. No future temporal information leaks into earlier training data.

---

## 3. Model Architecture & Dependency Evaluation

### 3.1 Environment Dependency Status
- **Python Version:** 3.14.4
- **NumPy:** 2.4.4 (Installed)
- **scikit-learn:** 1.9.0 (Installed)
- **LightGBM:** **NOT INSTALLED** in virtual environment.
- **LIEF:** Optional (truthfully reported as `"not-installed"` in `app/ml/serialize.py`).

### 3.2 Candidate Comparison

| Dimension | `HistGradientBoostingClassifier` (scikit-learn) | `LightGBM` (`lightgbm`) | Selection Decision |
|---|---|---|---|
| **Installation Status** | ✅ **Installed** (`sklearn.ensemble`) | ❌ **Not Installed** | **Primary Baseline** |
| **Algorithm Family** | Histogram-based Gradient Boosted Trees | Histogram-based Gradient Boosted Trees | Identical theoretical complexity |
| **Input Feature Dim** | 2,381 float32 features | 2,381 float32 features | Parity |
| **Training Speed** | Fast (C-optimized OpenMP) | Very fast (C++ OpenMP/GPU) | Sufficient for 260K rows |
| **Memory Footprint** | Discrete 256-bin integer bucketing | Discrete 256-bin integer bucketing | Memory efficient (~2 GB RAM) |
| **Native Early Stopping** | Supported (`early_stopping=True`) | Supported (`early_stopping_rounds`) | Both prevent overfitting |
| **Packaging & Export** | Standard `joblib` with metadata | Text file or `joblib` wrapper | Clean Python integration |

**Decision:**
Use **`HistGradientBoostingClassifier`** as the primary, fully reproducible baseline model. This adheres strictly to the rule prohibiting unauthorized package installations. If the user later authorizes `lightgbm`, the modular training harness will support it seamlessly via a pluggable estimator interface.

### 3.3 Baseline Model Configuration

```python
from sklearn.ensemble import HistGradientBoostingClassifier

baseline_params = {
    "loss": "log_loss",
    "learning_rate": 0.05,
    "max_iter": 300,
    "max_leaf_nodes": 63,
    "min_samples_leaf": 50,
    "l2_regularization": 0.1,
    "early_stopping": True,
    "n_iter_no_change": 15,
    "validation_fraction": 0.1,  # Internal early stopping check
    "random_state": 42,
    "verbose": 1,
}
```

---

## 4. Evaluation Framework & Operational Metrics

### 4.1 Inadequacy of Accuracy in Malware Detection
In real-world SOC and enterprise endpoint deployments:
- Benign PE executions outnumber malicious executions by 100:1 to 10,000:1.
- A model with 99.0% accuracy on a 100:1 corpus could generate 100 false alarms for every 10 true malware detections, saturating security analysts and causing alert fatigue.
- Therefore, **False Positive Rate (FPR)** must be constrained to strict operational budgets.

### 4.2 Primary Metric: True Positive Rate at Fixed Operational FPR

For binary decision threshold $\tau \in [0, 1]$:
$$\text{FPR}(\tau) = \frac{\text{FP}(\tau)}{\text{FP}(\tau) + \text{TN}(\tau)}, \quad \text{TPR}(\tau) = \frac{\text{TP}(\tau)}{\text{TP}(\tau) + \text{FN}(\tau)}$$

The evaluation suite will compute:
1. **Detection Rate at 1.0% FPR ($\tau_{1\%}$):** Target enterprise operational threshold.
2. **Detection Rate at 0.1% FPR ($\tau_{0.1\%}$):** High-confidence automated blocking threshold.

### 4.3 Threshold Selection Policy
- **Threshold Calibration Phase:** On the **Validation Split** ($D_{\text{val}}$), determine:
  $$\tau_{1\%}^* = \arg\max_{\tau} \{\text{TPR}(\tau) \mid \text{FPR}(\tau) \le 0.010\}$$
  $$\tau_{0.1\%}^* = \arg\max_{\tau} \{\text{TPR}(\tau) \mid \text{FPR}(\tau) \le 0.001\}$$
- **Frozen Evaluation Phase:** The calibrated thresholds $\tau_{1\%}^*$ and $\tau_{0.1\%}^*$ are **frozen** and evaluated on the held-out **Test Set** ($D_{\text{test}}$) without modification.

### 4.4 Comprehensive Metric Suite
In addition to fixed-FPR detection rates, the evaluation pipeline will generate:
- **Area Under ROC Curve (ROC-AUC)**
- **Area Under Precision-Recall Curve (PR-AUC / Average Precision)**
- **Binary Confusion Matrix:** $\begin{bmatrix} \text{TN} & \text{FP} \\ \text{FN} & \text{TP} \end{bmatrix}$
- **Per-Class Metrics:** Precision, Recall, F1-Score for class 0 (Benign) and class 1 (Malicious)
- **Score Distribution Calibration:** Histogram of predicted probabilities for benign vs malicious samples.

---

## 5. Resource Budget & Ingestion Architecture

### 5.1 Memory Budget ($\le 4.0\text{ GB}$)
- **Feature Vector Size:** $2,381 \times 4\text{ bytes} \approx 9,524\text{ bytes/sample}$.
- **260,364 Training Samples:** $260,364 \times 9,524\text{ bytes} \approx 2.48\text{ GB}$ (as raw float32 array).
- **Ingestion Strategy:** Use [`app.ml.ember_adapter.parse_jsonl_batches(batch_size=2000)`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_adapter.py#L380) to incrementally populate pre-allocated NumPy or memory-mapped arrays, avoiding high-overhead Python dictionary accumulation.
- **Peak RAM:** Confined to $\le 3.5\text{ GB}$ during model fitting.

### 5.2 Disk Budget
- Extracted training partitions on C: use ~3.6 GB.
- Trained model artifact: ~15 to 45 MB (`.joblib` compressed).
- Evaluation reports and plots: ~2 MB.
- All newly generated training artifacts will be written to `storage/models/`.

### 5.3 Runtime Budget
- Streaming feature extraction from JSONL: ~3 minutes across 260K rows.
- Model training (`HistGradientBoostingClassifier`, 300 iterations): ~8 to 15 minutes on a modern 8-core CPU.
- Test evaluation across 200,000 samples: ~45 seconds.

---

## 6. Reproducibility & Artifact Serialization Contract

### 6.1 Artifact Format and Structure

Artifacts will be serialized to `storage/models/ember_baseline_v1/`:
```
storage/models/ember_baseline_v1/
├── model.joblib                 # Compressed scikit-learn estimator
├── model.joblib.sha256          # SHA-256 checksum of model.joblib
├── metadata.json                # Complete provenance and training metadata
└── test_evaluation.json         # Performance metrics on held-out test set
```

### 6.2 Metadata Contract (`metadata.json`)

Conforming to [`app/ml/serialize.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/serialize.py):
```json
{
  "model_name": "ember-v2-baseline-hgb",
  "model_version": "1.0.0",
  "created_at": "2026-10-27T23:00:00Z",
  "environment": {
    "python_version": "3.14.4",
    "scikit_learn_version": "1.9.0",
    "numpy_version": "2.4.4",
    "os": "Windows"
  },
  "dataset": {
    "source": "EMBER 2018 Feature Version 2",
    "feature_version": 2,
    "feature_dim": 2381,
    "archive_sha256": "b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812",
    "training_partitions": ["train_features_0.jsonl", "train_features_1.jsonl", "train_features_3.jsonl"],
    "test_partition": "test_features.jsonl",
    "train_sample_count": 208291,
    "val_sample_count": 52073,
    "test_sample_count": 200000,
    "dataset_fingerprint_sha256": "<hash-of-sorted-sample-hashes>"
  },
  "training": {
    "algorithm": "HistGradientBoostingClassifier",
    "random_seed": 42,
    "hyperparameters": { ... },
    "iterations_completed": 184,
    "training_duration_seconds": 542.1
  },
  "calibrated_thresholds": {
    "fpr_1_percent": {
      "threshold": 0.8124,
      "val_tpr": 0.8950,
      "val_fpr": 0.0098
    },
    "fpr_0_1_percent": {
      "threshold": 0.9412,
      "val_tpr": 0.7630,
      "val_fpr": 0.0009
    }
  }
}
```

---

## 7. Inference Pipeline Integration Strategy

### 7.1 Non-Invasive Architecture
Production inference code in [`app/pipeline/orchestrator.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/pipeline/orchestrator.py) and [`app/ml/ember_v2.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_v2.py) must remain completely untouched during baseline training.

### 7.2 Interface Alignment
Inference compatibility is guaranteed by structural parity:
1. **Raw PE Extraction:** [`app/ml/ember_v2.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_v2.py) takes PE bytes and outputs `np.ndarray` of shape `(2381,)` float32.
2. **JSONL Precomputed Extraction:** [`app/ml/ember_adapter.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_adapter.py) takes JSON records and outputs `np.ndarray` of shape `(2381,)` float32.
3. **Model Classifier Wrapper:** A new decoupled service [`app/ml/classifier.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/classifier.py) will accept any `(2381,)` float32 vector and return:
   ```python
   class MLPrediction(BaseModel):
       malicious_probability: float
       is_malicious_1pct_fpr: bool
       is_malicious_01pct_fpr: bool
       feature_vector_sha256: str
       model_version: str
   ```
4. This wrapper can later be invoked by a dedicated `MLAnalyzer` plugged into the pipeline without altering any existing analyzers or database models.

---

## 8. ML-04 Ordered Implementation Roadmap

| Step | Task | Target Artifact | Success Verification |
|---|---|---|---|
| **Step 1** | Implement Training Script & Dataset Builder | `scripts/train_ember_baseline.py` | Ingests `train_features_0/1/3`, performs stratified split, verifies 0 leakage |
| **Step 2** | Implement Model Evaluation & Calibration Module | `app/ml/evaluator.py` | Computes ROC-AUC, PR-AUC, and finds $\tau_{1\%}^*$ and $\tau_{0.1\%}^*$ on validation set |
| **Step 3** | Execute Baseline Training | `storage/models/ember_baseline_v1/model.joblib` | Fits within 4 GB RAM, early stopping triggers cleanly, model saved with SHA-256 |
| **Step 4** | Evaluate on Official Held-Out Test Set | `storage/models/ember_baseline_v1/test_evaluation.json` | Computes test TPR at $\tau_{1\%}^*$ and $\tau_{0.1\%}^*$, ROC-AUC $\ge 0.95$ |
| **Step 5** | Create Classifier Inference Service & Unit Tests | `app/ml/classifier.py`, `tests/ml/test_classifier.py` | Full test suite verifying mock prediction, serialization roundtrip, and threshold logic |
| **Step 6** | Deliver ML-04 Baseline Training Report | `ML04_Baseline_Model_Report.md` | Complete empirical audit with test metrics, confusion matrix, and sign-off |

---

## 9. Preparation Sign-Off

- **ML-03D Gate:** `PASS WITH DOCUMENTED LIMITATIONS`
- **ML-03E Gate:** `COMPLETE & READY FOR ML-04 EXECUTION`
- **Production Code Changes:** 0 modifications made.
- **Unresolved Blockers:** None. Training can proceed immediately upon authorization using existing dependencies and verified datasets.
