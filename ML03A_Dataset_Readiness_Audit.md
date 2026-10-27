# ML-03A Dataset Readiness Audit

**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`
**Report generated:** 2026-10-27
**Auditor:** Senior ML Infrastructure Engineer / Application-Security Auditor
**Status:** Audit and planning milestone only — no dataset downloaded, no code modified, no training performed

---

## 1. Executive Summary

This report audits dataset readiness for ML-03 (Train/Validation/Test Split and Leakage Prevention). The authorized EMBER 2018 feature-v2 dataset is **absent** from the repository. No EMBER archive, extracted data, or precomputed feature vectors exist locally. All real-data validation gates remain **BLOCKED**.

**Key findings:**
- No `data/` directory exists in the repository
- No `ember_dataset_2018_2.tar.bz2` archive found on the local filesystem
- No extracted JSONL files or feature vectors found
- Available disk space: ~13 GB (compressed archive ~4 GB, uncompressed ~8-10 GB — may be tight)
- LIEF is not installed (required for feature extraction from raw PE binaries)
- scikit-learn 1.9.0 and NumPy 2.5.2 are installed
- LightGBM and XGBoost are not installed (no model training framework available)
- The existing ML pipeline consists only of feature extraction (`app/ml/ember_v2.py`) and serialization (`app/ml/serialize.py`) — no dataset loading, splitting, training, or evaluation code exists

**Final decision: `BLOCKED`** — Dataset acquisition and authorization required before ML-03 can proceed.

---

## 2. Repository Baseline and Preservation Notes

| Item | Value |
|---|---|
| **Branch** | `main` |
| **HEAD commit** | `822b2d35e0be0e10530d9d295c7a892ec2aa3cea` |
| **Tracked modifications** | `app/db/models.py`, `app/db/schemas.py`, `app/db/session.py` (pre-existing user work, preserved) |
| **Untracked ML files** | `app/ml/ember_v2.py`, `app/ml/serialize.py`, `tests/ml/test_ember_v2.py`, `tests/ml/test_serialization.py` |
| **Untracked reports** | `C5C8_Evidence_Audit_Report.md`, `C5C8_Remediation_Report.md`, `ML03_READINESS_REAUDIT_REPORT.md`, and others |
| **Safety** | No `git clean`, `git reset --hard`, or destructive commands executed. No files modified during this audit. |

---

## 3. Dataset Availability and Provenance Status

### 3.1 Archive Availability

| Check | Result |
|---|---|
| `ember_dataset_2018_2.tar.bz2` exists locally | ❌ NOT FOUND |
| Extracted dataset directory exists | ❌ NOT FOUND (`data/` directory does not exist) |
| Precomputed feature vectors (`.npz`, `.npy`, `.jsonl`) | ❌ NOT FOUND |
| Any EMBER-related files outside repository | ❌ NOT FOUND (searched common locations) |

### 3.2 Proposed Official Source

| Attribute | Value |
|---|---|
| **Archive filename** | `ember_dataset_2018_2.tar.bz2` |
| **Download URL** | `https://ember.elastic.co/ember_dataset_2018_2.tar.bz2` |
| **Published SHA-256** | `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812` |
| **Content type** | `application/x-bzip2` |
| **Compressed size** | ~4 GB |
| **Uncompressed size** | ~8-10 GB |
| **License (data)** | MIT License |
| **License (source code)** | AGPL-v3 |
| **Original publisher** | Elastic (formerly Endgame, Inc.) |
| **Original authors** | Hyrum S. Anderson, Phil Roth |
| **Original repository** | `https://github.com/elastic/ember` (archived Apr 13, 2026) |
| **Original paper** | Anderson & Roth, "EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models", arXiv:1804.04637v2 |

### 3.3 Provenance Verification Procedure (Proposed)

```bash
# 1. Download (requires authorization)
curl -L -o ember_dataset_2018_2.tar.bz2 https://ember.elastic.co/ember_dataset_2018_2.tar.bz2

# 2. Verify checksum
sha256sum ember_dataset_2018_2.tar.bz2
# Expected: b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812

# 3. Extract
tar -xjf ember_dataset_2018_2.tar.bz2
# Creates ember2018/ directory with train_features.jsonl, test_features.jsonl, metadata.jsonl
```

**Note:** The expected hash is NOT verified locally. No archive exists to hash.

### 3.4 Licensing Conditions

- **Data license:** MIT License — permits use, modification, distribution
- **Source code license:** AGPL-v3 — requires source disclosure for network services
- **Redistribution:** Must comply with MIT terms for data; AGPL-v3 for any derivative source code
- **Malware samples:** The dataset contains features extracted from malware; the repository must NOT contain raw malware binaries

---

## 4. Existing ML Pipeline Inventory

### 4.1 Feature Extraction

| Component | File | Function | Status |
|---|---|---|---|
| EMBER v2 feature extractor | `app/ml/ember_v2.py` | `EMBERFeatureExtractor` | ✅ VERIFIED (C5 PARTIAL) |
| Feature dimension | `app/ml/ember_v2.py` | `EMBER_V2_TOTAL_DIM = 2381` | ✅ VERIFIED |
| Feature groups | `app/ml/ember_v2.py` | `EMBER_V2_FEATURE_GROUPS` (9 groups) | ✅ VERIFIED |
| Feature hashing | `app/ml/ember_v2.py` | 13 `FeatureHasher` instances, `alternate_sign=True` | ✅ ALIGNED |
| LIEF integration | `app/ml/ember_v2.py` | `lief` (optional import) | ⚠️ NOT INSTALLED locally |

### 4.2 Serialization

| Component | File | Function | Status |
|---|---|---|---|
| Feature serializer | `app/ml/serialize.py` | `FeatureVectorSerializer` | ✅ VERIFIED (C8 VERIFIED) |
| Metadata creation | `app/ml/serialize.py` | `create_ember_v2_metadata()` | ✅ VERIFIED (runtime versions) |
| Runtime version discovery | `app/ml/serialize.py` | `get_serialize_metadata()` | ✅ VERIFIED |
| Serialization helpers | `app/ml/serialize.py` | `serialize_features()`, `deserialize_features()`, `serialize_batch()` | ✅ VERIFIED |

### 4.3 Dataset Loading and Parsing

| Component | Status | Notes |
|---|---|---|
| Dataset loader | ❌ MISSING | No code exists to load EMBER JSONL files |
| JSONL parser | ❌ MISSING | No code exists to parse `train_features.jsonl` / `test_features.jsonl` |
| Feature vector extraction from raw features | ❌ MISSING | No code converts EMBER raw JSON features to 2,381-dim vectors |
| Label loading | ❌ MISSING | No code exists to read labels from dataset |

### 4.4 Train/Validation/Test Splitting

| Component | Status | Notes |
|---|---|---|
| Split strategy | ❌ MISSING | No split logic exists |
| Temporal split | ❌ MISSING | EMBER 2017 uses temporal split (train: before 2017-11, test: 2017-11 to 2017-12); 2018 split details unpublished |
| Leakage prevention | ❌ MISSING | No duplicate SHA-256 or temporal leakage checks |
| Stratified sampling | ❌ MISSING | No class-balanced sampling logic |

### 4.5 Model Training

| Component | Status | Notes |
|---|---|---|
| Model trainer | ❌ MISSING | No training code exists |
| Baseline model | ❌ MISSING | No model selection or baseline defined |
| LightGBM integration | ❌ MISSING | `lightgbm` not installed |
| XGBoost integration | ❌ MISSING | `xgboost` not installed |
| scikit-learn models | ⚠️ PARTIAL | scikit-learn 1.9.0 installed but no training pipeline |

### 4.6 Model Serialization and Inference

| Component | Status | Notes |
|---|---|---|
| Model serializer | ❌ MISSING | No model saving/loading code |
| Model metadata | ❌ MISSING | No model metadata schema |
| Inference pipeline | ❌ MISSING | No inference code for trained models |
| Model compatibility check | ❌ MISSING | No version compatibility verification |

### 4.7 Metrics and Evaluation

| Component | Status | Notes |
|---|---|---|
| Evaluation metrics | ❌ MISSING | No precision/recall/F1/FPR/confusion matrix code |
| Cross-validation | ❌ MISSING | No CV logic |
| Reproducibility controls | ❌ MISSING | No random seed management, no experiment tracking |

### 4.8 Dataset Schema Validation

| Component | File | Status |
|---|---|---|
| Schema validator | `scripts/validate_dataset_schema.py` | ✅ EXISTS (27/27 tests pass in synthetic mode) |
| Schema documentation | `docs/data/DATASET_SCHEMA.md` | ✅ EXISTS |
| Provenance record | `docs/data/PROVENANCE.md` | ✅ EXISTS |

---

## 5. Dataset Compatibility Analysis

### 5.1 Expected Input Schema

The existing pipeline (`app/ml/ember_v2.py`) expects:
- **Raw PE bytes** (`bytes`) as input
- Produces **2,381-dimensional float32 feature vectors**
- Uses LIEF for PE parsing (optional — returns zeros if unavailable)

### 5.2 Official EMBER Dataset Format

The EMBER 2018 dataset provides:
- **Precomputed raw features** as JSON Lines (`train_features.jsonl`, `test_features.jsonl`)
- Each record contains: `sha256`, `appeared`, `label`, `general`, `header`, `imports`, `exports`, `section`, `histogram`, `byteentropy`, `strings`
- Labels: 0 (benign), 1 (malicious), -1 (unlabeled)
- No raw PE binaries included — only extracted features

### 5.3 Compatibility Gap

| Aspect | Existing Pipeline | EMBER Dataset | Gap |
|---|---|---|---|
| Input type | Raw PE bytes | Precomputed JSON features | **MISMATCH** — pipeline expects raw bytes, dataset provides JSON |
| Feature extraction | `EMBERFeatureExtractor.feature_vector(bytez)` | Features already extracted in JSON | **MISMATCH** — need adapter to convert JSON → vector |
| Labels | Not handled | `label` field (0/1/-1) | **MISSING** — no label loading code |
| Splits | Not handled | `train_features.jsonl` / `test_features.jsonl` | **MISSING** — no split logic |
| Vectorization | `process_raw_features(raw_obj)` | Raw features in JSON | **PARTIAL** — `process_raw_features` exists but expects internal format, not EMBER JSON |

### 5.4 Required Schema Conversion

To use the EMBER dataset with the existing pipeline, the following conversion is needed:

1. **Parse EMBER JSONL records** → extract raw feature fields
2. **Map EMBER field names to internal format** (e.g., `general.file_size` → `general.size`)
3. **Call `process_raw_features()`** with converted raw features
4. **Extract and store labels** (0/1 for supervised, -1 for unlabeled)
5. **Apply train/test split** from EMBER's provided splits

**Note:** This conversion is NOT implemented. It must be designed and implemented before ML-03.

---

## 6. Proposed Real-Data Validation Gates

### Gate 1: Dataset Provenance and SHA-256 Verification
- [ ] Download `ember_dataset_2018_2.tar.bz2` from official URL
- [ ] Verify SHA-256 = `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812`
- [ ] Document download date, source URL, and verified hash

### Gate 2: Archive Integrity and Safe Extraction
- [ ] Verify archive is valid bzip2 (`tar -tjf` or `bz2` module)
- [ ] Extract to isolated directory (not inside repository)
- [ ] Verify expected files exist: `train_features.jsonl`, `test_features.jsonl`, `metadata.jsonl`
- [ ] Check file sizes and record counts

### Gate 3: Label and Schema Validation
- [ ] Run `scripts/validate_dataset_schema.py --data-dir /path/to/ember2018`
- [ ] Verify all records have required top-level fields
- [ ] Verify label values are in {-1, 0, 1}
- [ ] Verify feature dimensions match contract (2,381)
- [ ] Check for missing or malformed fields

### Gate 4: Duplicate and Leakage Checks
- [ ] Check for duplicate SHA-256 values across train/test splits
- [ ] Verify no SHA-256 appears in both train and test with different labels
- [ ] Check for temporal leakage (if temporal split applies)
- [ ] Verify unlabeled samples (-1) are excluded from supervised evaluation

### Gate 5: Reproducible Train/Validation/Test Splitting
- [ ] Document split strategy (EMBER provides train/test; validation split TBD)
- [ ] Set and record random seed for reproducibility
- [ ] Implement stratified sampling for class balance
- [ ] Verify split ratios and class distributions

### Gate 6: Class Distribution Reporting
- [ ] Count benign (0), malicious (1), unlabeled (-1) in train and test
- [ ] Report class imbalance ratio
- [ ] Document any sampling or weighting strategy

### Gate 7: Baseline Model Selection
- [ ] Define baseline model (e.g., LightGBM, as used in EMBER paper)
- [ ] Install required ML framework (LightGBM or scikit-learn)
- [ ] Document hyperparameters and training configuration

### Gate 8: Metrics for Imbalanced Malware Classification
- [ ] Precision, Recall, F1 (per-class and macro)
- [ ] False Positive Rate (FPR)
- [ ] Confusion matrix
- [ ] ROC-AUC and PR-AUC
- [ ] Threshold selection methodology (on validation set only, not test)

### Gate 9: Feature-Pipeline and Model-Metadata Compatibility
- [ ] Verify feature extractor produces identical vectors for EMBER raw features
- [ ] Verify serialized metadata matches trained model expectations
- [ ] Document feature version and LIEF version used for training

### Gate 10: Saved Model Reproducibility and Inference Smoke Tests
- [ ] Save trained model with metadata
- [ ] Verify model loads and produces predictions
- [ ] Run inference smoke test on held-out samples
- [ ] Verify reproducibility (re-train with same seed → same model)

**Critical constraint:** Test data must NOT be used for model selection or threshold tuning. All model selection and hyperparameter tuning must use training/validation data only.

---

## 7. Resource and Safety Assessment

### 7.1 Disk Space

| Resource | Estimate | Status |
|---|---|---|
| Compressed archive | ~4 GB | Required |
| Uncompressed dataset | ~8-10 GB | Required |
| Feature vectors (if generated) | UNKNOWN | Depends on vectorization strategy |
| Trained models | UNKNOWN | Depends on model type and hyperparameters |
| **Available disk space** | **~13 GB free** | ⚠️ MAY BE INSUFFICIENT for full uncompressed dataset + feature vectors + models |

**Recommendation:** Measure actual disk usage after extraction. Consider extracting to a non-repository location.

### 7.2 Memory

| Resource | Estimate | Status |
|---|---|---|
| Dataset loading (1M records) | UNKNOWN | Depends on loading strategy (streaming vs. in-memory) |
| Feature vector matrix (1M × 2381 float32) | ~9.5 GB | If loaded entirely into memory |
| Model training | UNKNOWN | Depends on framework and hyperparameters |

**Recommendation:** Use streaming/chunked loading to avoid loading entire dataset into memory. Measure actual memory usage during validation.

### 7.3 Python Package Versions

| Package | Version | Status |
|---|---|---|
| Python | 3.14.4 | ✅ Installed |
| scikit-learn | 1.9.0 | ✅ Installed |
| NumPy | 2.5.2 | ✅ Installed |
| LIEF | NOT INSTALLED | ❌ Required for feature extraction from raw PE |
| LightGBM | NOT INSTALLED | ❌ Required for baseline model (EMBER standard) |
| XGBoost | NOT INSTALLED | ❌ Not installed |
| joblib | 1.5.3 | ✅ Installed (model serialization) |

### 7.4 Safety Considerations

- **No raw malware binaries** will be introduced into the repository
- **No PE file execution** — only feature extraction from bytes
- **Dataset stored outside repository** — recommended to avoid bloating git
- **No network access** during audit — no downloads performed
- **No dependency installation** without authorization

---

## 8. Exact Files Inspected or Changed

### Files Inspected (read-only)
| File | Purpose |
|---|---|
| `app/ml/ember_v2.py` | Feature extractor implementation |
| `app/ml/serialize.py` | Serialization module |
| `tests/ml/test_ember_v2.py` | Extractor tests |
| `tests/ml/test_serialization.py` | Serialization tests |
| `scripts/validate_dataset_schema.py` | Dataset schema validator |
| `scripts/test_validate_dataset_schema.py` | Validator tests |
| `docs/data/DATASET_SCHEMA.md` | Dataset schema documentation |
| `docs/data/PROVENANCE.md` | Provenance record |
| `docs/ml/EMBER_V2_FEATURE_CONTRACT.md` | Feature contract |
| `ML03_READINESS_REAUDIT_REPORT.md` | ML-03 readiness report |

### Files Changed
| File | Change |
|---|---|
| `ML03A_Dataset_Readiness_Audit.md` | Created (this report) |

**No production code modified.** No tests modified. No dependencies installed.

---

## 9. Commands and Test Results

| Command | Result |
|---|---|
| `git rev-parse --abbrev-ref HEAD` | `main` |
| `git rev-parse HEAD` | `822b2d35e0be0e10530d9d295c7a892ec2aa3cea` |
| `git status --short` | 60 lines (tracked mods + untracked files) |
| `python -m pytest tests/ml -q` | **75 passed**, 35 warnings, exit code 0 |
| Disk space check | ~13 GB free on C: |
| Package version check | sklearn 1.9.0, numpy 2.5.2, lief NOT INSTALLED, lightgbm NOT INSTALLED |

---

## 10. Clear Blockers and Recommended Next Action

### Blockers

| # | Blocker | Severity | Resolution |
|---|---|---|---|
| 1 | **Dataset absent** | CRITICAL | Acquire `ember_dataset_2018_2.tar.bz2` from official source with authorization |
| 2 | **LIEF not installed** | HIGH | Install LIEF 0.9.0 (reference version) or document 1.0.0 compatibility |
| 3 | **No model training framework** | HIGH | Install LightGBM or scikit-learn ensemble |
| 4 | **No dataset loading code** | HIGH | Implement JSONL parser and feature vector converter |
| 5 | **No split logic** | HIGH | Implement train/validation/test splitting |
| 6 | **No evaluation metrics** | MEDIUM | Implement precision/recall/F1/FPR/confusion matrix |
| 7 | **Limited disk space** | MEDIUM | ~13 GB free; dataset needs ~4 GB compressed + ~8-10 GB uncompressed |

### Recommended Next Action

1. **Authorize dataset acquisition** — download `ember_dataset_2018_2.tar.bz2` and verify SHA-256
2. **Install LIEF 0.9.0** (reference version) in isolated environment
3. **Implement dataset loader** — parse JSONL, convert to feature vectors, extract labels
4. **Implement split logic** — use EMBER's provided train/test splits; create validation split
5. **Implement evaluation metrics** — precision, recall, F1, FPR, confusion matrix
6. **Run Gate 1-10 validation** — verify all gates pass before ML-03

**ML-03 remains BLOCKED** until the dataset is acquired and all real-data validation gates are satisfied.

---

### Final Status

| Workstream | Status | Evidence |
|---|---|---|
| **C5** | **PARTIAL** | Source-level comparison: 8/9 MATCH, 1 confirmed mismatch (empty input, intentional). Full parity unverified. |
| **C8** | **VERIFIED** | Runtime version discovery; 7 new tests; all 75 tests pass |
| **C3** | **VERIFIED** | AC-05 evidence documented; no regression |
| **ML-03** | **BLOCKED** | Dataset absent; no real-data gates run |
| **ML-03A** | **COMPLETE** | Dataset readiness audit completed; all blockers documented |

**No commits made.** All changes remain uncommitted.