# ML-03B Schema Adapter and Resource Plan

**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`
**Report generated:** 2026-10-27
**Status:** Planning and read-only inspection only — no code modified, no dataset acquired, no training performed

---

## 1. Verified Official Schema Details

### 1.1 Dataset Identity

| Attribute | Value | Source |
|---|---|---|
| **Dataset name** | EMBER 2018 (Feature Version 2) | `docs/data/DATASET_SCHEMA.md` §1 |
| **Source repository** | `elastic/ember` (GitHub, archived Apr 13, 2026) | `docs/data/DATASET_SCHEMA.md` §1 |
| **Archive file** | `ember_dataset_2018_2.tar.bz2` | `docs/data/DATASET_SCHEMA.md` §1, PROVENANCE.md §2.1 |
| **Download URL** | `https://ember.elastic.co/ember_dataset_2018_2.tar.bz2` | `docs/data/DATASET_SCHEMA.md` §1 |
| **SHA-256** | `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812` | `docs/data/DATASET_SCHEMA.md` §1 |
| **License (data)** | MIT License | `docs/data/DATASET_SCHEMA.md` §1 |
| **License (source code)** | AGPL-v3 | `docs/data/DATASET_SCHEMA.md` §1 |
| **Feature version** | 2 (LIEF 0.9.0) | `docs/data/DATASET_SCHEMA.md` §1 |
| **Original paper** | Anderson & Roth, arXiv:1804.04637v2 | `docs/data/DATASET_SCHEMA.md` §1 |

### 1.2 Record Format

Each line in `train_features.jsonl` / `test_features.jsonl` is a JSON object with these top-level fields:

| Field | Type | Description |
|---|---|---|
| `sha256` | string (64 hex chars) | SHA-256 of the PE file |
| `appeared` | string (YYYY-MM) | Month the file appeared |
| `label` | integer (-1, 0, 1) | -1 = unlabeled, 0 = benign, 1 = malicious |
| `general` | object | General file information (10 fields) |
| `header` | object | COFF + optional header fields |
| `imports` | object (dict) | DLL name → array of function names |
| `exports` | array[string] | Exported function names |
| `section` | object | Section info (entry + sections array) |
| `histogram` | array[256 integers] | Raw byte value counts |
| `byteentropy` | array[256 integers] | Joint entropy/byte histogram (16×16) |
| `strings` | object | String statistics (9 fields) |

**Source:** `docs/data/DATASET_SCHEMA.md` §3

### 1.3 Label Definitions

| Value | Meaning | Usage |
|---|---|---|
| 0 | Benign | Training & Test |
| 1 | Malicious | Training & Test |
| -1 | Unlabeled | Training only (300K samples) |

**Critical:** Unlabeled samples (label == -1) must NOT be treated as benign. They are explicitly unlabeled for semi-supervised research.

**Source:** `docs/data/DATASET_SCHEMA.md` §4, PROVENANCE.md §3.1

### 1.4 Feature Groups and Dimensions

The EMBER library converts raw features to a **2,381-dimensional float32 vector** (Feature Version 2):

| Feature Group | Bins | Notes |
|---|---|---|
| General + Header (hashed) | ~512 | Categorical via hashing trick |
| Imports (libraries) | 256 | Feature hashing |
| Imports (functions) | 1024 | library:function pairs |
| Exports | 128 | Feature hashing |
| Section (size/entropy/vsize) | 150 | 50 bins each |
| Section characteristics | 50 | Entry point section |
| Byte histogram | 256 | Normalized to distribution |
| Byte-entropy histogram | 256 | 16×16 normalized |
| String statistics | ~50 | Statistics + printable distribution |
| **Total** | **2,381** | Fixed per feature version 2 |

**Source:** `docs/data/DATASET_SCHEMA.md` §5

### 1.5 Available Splits

| Split | Description | Source |
|---|---|---|
| `train_features.jsonl` | Training samples | `docs/data/DATASET_SCHEMA.md` §2 |
| `test_features.jsonl` | Test samples | `docs/data/DATASET_SCHEMA.md` §2 |
| `metadata.jsonl` | Sample metadata | `docs/data/DATASET_SCHEMA.md` §2 |

**Note:** The README states EMBER 2018 contains "features from 1 million PE files scanned in or before 2018." Exact per-split counts for 2018 are not published in the original paper; the 900K train / 200K test figures originate from the EMBER 2017 release. EMBER 2018's collection boundaries are described in the CAMMLIS 2019 talk (Roth).

**Source:** `docs/data/DATASET_SCHEMA.md` §2, PROVENANCE.md §3.1, README.md

### 1.6 Archive Contents

The archive contains **precomputed raw features** (JSON), NOT raw PE binaries:

| Content | Included? | Notes |
|---|---|---|
| Raw PE binaries | ❌ No | Only extracted features |
| Precomputed features (JSONL) | ✅ Yes | `train_features.jsonl`, `test_features.jsonl` |
| Metadata | ✅ Yes | `metadata.jsonl` |
| Vectorized features | ❌ No | Generated at training time using `ember` library |
| Trained models | ❌ No | Must be trained by user |

**Source:** `docs/data/DATASET_SCHEMA.md` §1, README.md ("Raw features are extracted to JSON format")

---

## 2. Local Compatibility Findings

### 2.1 Current Pipeline Components

| Component | File | Status |
|---|---|---|
| Feature extractor | `app/ml/ember_v2.py` (`EMBERFeatureExtractor`) | ✅ EXISTS — processes raw PE bytes → 2,381-dim vector |
| Serializer | `app/ml/serialize.py` (`FeatureVectorSerializer`) | ✅ EXISTS — NPZ serialization with metadata |
| Dataset loader | — | ❌ MISSING |
| Label handler | — | ❌ MISSING |
| Split logic | — | ❌ MISSING |
| Model trainer | — | ❌ MISSING |
| Evaluation metrics | — | ❌ MISSING |

### 2.2 Compatibility Analysis

| Aspect | Existing Pipeline | EMBER Dataset | Gap |
|---|---|---|---|
| Input type | Raw PE bytes (`bytes`) | Precomputed JSON features | **MISMATCH** |
| Feature extraction | `EMBERFeatureExtractor.feature_vector(bytez)` | Features already extracted in JSON | **MISMATCH** |
| Labels | Not handled | `label` field (-1/0/1) | **MISSING** |
| Splits | Not handled | `train_features.jsonl` / `test_features.jsonl` | **MISSING** |
| Vectorization | `process_raw_features(raw_obj)` | Raw features in JSON | **PARTIAL** — function exists but expects internal format |

### 2.3 Recommended Architecture: **Option 2 — Separate Official-EMBER Training Representation**

**Recommendation:** Introduce a separate official-EMBER training representation while preserving the existing raw-PE feature pipeline.

**Rationale:**
1. The existing `EMBERFeatureExtractor` processes **raw PE bytes** → 2,381-dim vectors. This is used by the analysis pipeline (`app/pipeline/orchestrator.py`) for real-time PE analysis.
2. The EMBER dataset provides **precomputed raw features** (JSON). These need to be converted to 2,381-dim vectors using the same feature hashing logic.
3. The `process_raw_features()` method already accepts a `raw_obj` dict with the same field structure as EMBER's JSON records (with minor field name differences).
4. Creating a separate training representation allows:
   - Training models on EMBER's precomputed features without modifying the raw-PE pipeline
   - Preserving the raw-PE analysis pipeline for inference on new samples
   - Clear separation between training-time and inference-time feature paths

**Implementation approach:**
- Create an adapter module (`app/ml/ember_adapter.py`) that:
  1. Parses EMBER JSONL records
  2. Maps EMBER field names to internal format (e.g., `general.file_size` → `general.size`)
  3. Calls `EMBERFeatureExtractor.process_raw_features()` to produce 2,381-dim vectors
  4. Extracts and returns labels
- The existing `EMBERFeatureExtractor` and `FeatureVectorSerializer` remain unchanged
- Training code uses the adapter to convert EMBER records to vectors
- Inference code continues to use `EMBERFeatureExtractor.feature_vector(bytez)` for raw PE

**Compatibility implications:**
- ✅ Existing raw-PE pipeline preserved (no changes to `ember_v2.py`)
- ✅ Existing serialization preserved (no changes to `serialize.py`)
- ✅ Training and inference use the same feature hashing logic (via `process_raw_features`)
- ⚠️ Field name mapping required (EMBER uses `file_size`, internal uses `size`)
- ⚠️ LIEF not needed during training (precomputed features used)
- ⚠️ Feature version must match (EMBER v2 = local v2)

---

## 3. Adapter Contract and Acceptance Tests

### 3.1 Adapter Interface (Proposed)

```python
class EmberDatasetAdapter:
    """Converts EMBER 2018 JSON records to internal feature vectors."""

    def parse_record(self, record: dict) -> tuple[np.ndarray, int]:
        """Parse a single EMBER record.
        Returns: (feature_vector: np.ndarray[2381], label: int)
        Raises: ValueError on malformed record
        """

    def parse_jsonl(self, path: Path, split: str) -> Iterator[tuple[np.ndarray, int, str]]:
        """Stream-parse a JSONL file.
        Yields: (feature_vector, label, sha256)
        """

    def validate_record(self, record: dict) -> list[str]:
        """Validate record schema. Returns list of errors (empty = valid)."""
```

### 3.2 Proposed Acceptance Tests

| Test ID | Description | Expected Outcome |
|---|---|---|
| T1 | Valid EMBER record with all required fields | Returns 2,381-dim float32 vector and correct label |
| T2 | Record missing required top-level field (e.g., `histogram`) | Raises `ValueError` with field name |
| T3 | Record with wrong type for `histogram` (string instead of array) | Raises `ValueError` with type mismatch |
| T4 | Record with wrong histogram length (255 instead of 256) | Raises `ValueError` with dimension mismatch |
| T5 | Record with label = -1 (unlabeled) | Returns vector and label -1; excluded from supervised metrics |
| T6 | Record with label = 0 (benign) | Returns vector and label 0 |
| T7 | Record with label = 1 (malicious) | Returns vector and label 1 |
| T8 | Record with label = 2 (invalid) | Raises `ValueError` with invalid label |
| T9 | Record with NaN in histogram | Raises `ValueError` or produces non-finite vector (reject) |
| T10 | Record with Inf in byteentropy | Raises `ValueError` or produces non-finite vector (reject) |
| T11 | Record with missing `imports` (empty dict) | Returns valid vector (all zeros for imports) |
| T12 | Record with extra unknown fields | Accepted (ignored) or rejected (strict mode) |
| T13 | Deterministic parsing: same record → same vector | Vectors exactly equal across calls |
| T14 | Serialization roundtrip: parse → serialize → deserialize → compare | Vectors and metadata preserved |
| T15 | Inference consistency: adapter-produced vector matches `feature_vector()` for equivalent raw PE | Vectors exactly equal (if raw PE available) |
| T16 | Incompatible schema (e.g., EMBER 2017 v1) | Rejected with clear error message |
| T17 | Empty JSONL file | Returns empty iterator, no crash |
| T18 | Malformed JSON line | Raises `JSONDecodeError` or skips with warning |

**Note:** These tests are PROPOSED. They have NOT been implemented or executed. No test results to report.

---

## 4. Resource Feasibility

### 4.1 Disk Space

| Resource | Estimate | Status | Notes |
|---|---|---|---|
| Compressed archive | ~4 GB | Required | `ember_dataset_2018_2.tar.bz2` |
| Uncompressed dataset | ~8-10 GB | Required | ~1.1M JSONL lines |
| Vectorized features (if generated) | ~2-3 GB | Optional | 1.1M × 2381 × 4 bytes ≈ 10 GB (float32) |
| Trained models | UNKNOWN | Depends on model type | LightGBM model ~10-50 MB |
| **Available disk space** | **~13 GB free** | ⚠️ MAY BE TIGHT | Extract to non-repository location |

**Recommendation:** Extract to a non-repository directory (e.g., `C:\data\ember2018\`). Measure actual usage after extraction. If insufficient, consider streaming extraction (process records without full extraction).

### 4.2 Memory

| Resource | Estimate | Status | Notes |
|---|---|---|---|
| Full dataset in memory (1M records) | ~8-10 GB | If loaded entirely | NOT RECOMMENDED |
| Streaming/chunked loading | ~100-500 MB per chunk | RECOMMENDED | Process in batches of 10K-50K records |
| Feature vector matrix (1M × 2381 float32) | ~9.5 GB | If loaded entirely | NOT RECOMMENDED |
| Model training | UNKNOWN | Depends on framework | LightGBM handles large datasets via binning |

**Recommendation:** Use streaming/chunked loading (10K-50K records per batch). Do not load entire dataset into memory.

### 4.3 Package Versions

| Package | Version | Status | Needed For |
|---|---|---|---|
| Python | 3.14.4 | ✅ Installed | All |
| scikit-learn | 1.9.0 | ✅ Installed | Model training, metrics |
| NumPy | 2.5.2 | ✅ Installed | Feature vectors |
| LIEF | NOT INSTALLED | ⚠️ Not needed for training (precomputed features) | Only needed for raw PE inference |
| LightGBM | NOT INSTALLED | ❌ Required for baseline model | Must be installed with authorization |
| XGBoost | NOT INSTALLED | Optional | Alternative model |
| joblib | 1.5.3 | ✅ Installed | Model serialization |

**Key insight:** Precomputed features **avoid the need for LIEF during training**. LIEF is only needed for raw-PE inference (existing pipeline). This reduces training-time dependencies.

### 4.4 Measured vs. Estimated

| Value | Type | How to Measure |
|---|---|---|
| Disk space (13 GB free) | MEASURED | `shutil.disk_usage()` |
| Package versions | MEASURED | `importlib.metadata.version()` |
| Archive size (~4 GB) | ESTIMATED (from documentation) | Verify after download |
| Uncompressed size (~8-10 GB) | ESTIMATED (from documentation) | Measure after extraction |
| Memory per chunk | ESTIMATED | Measure during implementation |
| Training memory | UNKNOWN | Measure during training |

---

## 5. Training and Evaluation Contract

### 5.1 Baseline Model

**Recommended:** LightGBM (as used in official EMBER paper)
- **Rationale:** EMBER's reference implementation uses LightGBM. Provides comparable baseline. Handles large datasets efficiently via binning. Native support for imbalanced data via `scale_pos_weight`.
- **Alternative:** scikit-learn `HistGradientBoostingClassifier` (if LightGBM installation not authorized)

### 5.2 Reproducible Split Strategy

| Aspect | Recommendation |
|---|---|
| **Train/test split** | Use EMBER's provided `train_features.jsonl` / `test_features.jsonl` |
| **Validation split** | Stratified split from training set (e.g., 10% of train, or temporal holdout) |
| **Random seed** | Fixed seed (e.g., 42) recorded in model metadata |
| **Leakage prevention** | SHA-256 deduplication across splits; temporal ordering if applicable |
| **Unlabeled handling** | Exclude from supervised training; optionally use for semi-supervised |

### 5.3 Policy for Duplicates and Unlabeled Records

| Record Type | Policy |
|---|---|
| Duplicate SHA-256 (same label) | Deduplicate (keep first occurrence) |
| Duplicate SHA-256 (different labels) | Flag as conflict; investigate |
| Unlabeled (label = -1) | Exclude from supervised training; optionally use for semi-supervised research |
| Benign (label = 0) | Include in training |
| Malicious (label = 1) | Include in training |

### 5.4 Metrics

| Metric | Purpose | When to Report |
|---|---|---|
| Precision | False positive control | Train, validation, test |
| Recall | Detection rate | Train, validation, test |
| F1 (per-class and macro) | Balanced performance | Train, validation, test |
| False Positive Rate (FPR) | Operational cost | Validation, test |
| Confusion matrix | Error breakdown | Validation, test |
| ROC-AUC | Ranking quality | Validation, test |
| PR-AUC | Imbalanced performance | Validation, test |

**Critical:** Test metrics reported ONCE after all model selection and threshold tuning is complete on validation data.

### 5.5 Model Metadata Schema (Proposed)

```python
@dataclass
class ModelMetadata:
    model_type: str  # "lightgbm", "hist_gradient_boosting", etc.
    model_version: str  # semantic version
    feature_schema_version: str  # "ember-v2" (must match FeatureMetadata)
    feature_dim: int  # 2381
    dataset_name: str  # "ember2018"
    dataset_sha256: str  # archive hash
    dataset_split: str  # "train", "validation"
    training_seed: int
    training_date: str  # ISO 8601
    sklearn_version: str
    numpy_version: str
    lief_version: str  # "not-installed" if not used
    model_hyperparameters: dict
    validation_metrics: dict
    test_metrics: dict  # populated after final evaluation
```

### 5.6 Acceptance Criteria for First Real-Data Experiment

1. ✅ Dataset acquired and SHA-256 verified
2. ✅ Schema validation passes (all records valid)
3. ✅ No duplicate SHA-256 across splits
4. ✅ No temporal leakage
5. ✅ Class distributions reported
6. ✅ Baseline model trained with fixed seed
7. ✅ Validation metrics computed (precision, recall, F1, FPR, confusion matrix)
8. ✅ Test metrics computed ONCE (no threshold tuning on test)
9. ✅ Model saved with full metadata
10. ✅ Inference smoke test passes on held-out samples
11. ✅ Reproducibility verified (re-train with same seed → same model)

---

## 6. Proposed Implementation Steps

| Step | Description | Estimated Effort | Dependencies |
|---|---|---|---|
| 1 | Acquire and verify dataset (Gate 1) | 1-2 hours | Authorization |
| 2 | Implement `EmberDatasetAdapter` (JSONL → vectors) | 2-4 hours | Step 1 |
| 3 | Implement adapter tests (T1-T18) | 2-3 hours | Step 2 |
| 4 | Implement split logic and leakage checks | 1-2 hours | Step 2 |
| 5 | Install LightGBM (with authorization) | 15 min | Authorization |
| 6 | Implement baseline model training | 2-4 hours | Steps 4, 5 |
| 7 | Implement evaluation metrics | 1-2 hours | Step 6 |
| 8 | Implement model serialization and metadata | 1-2 hours | Step 6 |
| 9 | Run Gates 1-10 validation | 2-4 hours | Steps 1-8 |
| 10 | Document results and update reports | 1-2 hours | Step 9 |

**Total estimated effort:** 14-26 hours (excluding dataset download time)

---

## 7. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| Disk space insufficient | MEDIUM | Extract to non-repo location; measure actual usage |
| LIEF version mismatch affects features | MEDIUM | Document LIEF version used; verify feature parity |
| Dataset schema changes between versions | LOW | Use `validate_dataset_schema.py` for validation |
| Model overfitting to test set | HIGH | Strict protocol: no test-set tuning |
| Unlabeled samples misused | MEDIUM | Explicit exclusion from supervised metrics |
| Temporal leakage | HIGH | Verify SHA-256 uniqueness across splits |
| Dependency installation blocked | MEDIUM | Use scikit-learn as fallback baseline |

---

## 8. Exact Files Inspected or Changed

### Files Inspected (read-only)
| File | Purpose |
|---|---|
| `app/ml/ember_v2.py` | Feature extractor implementation |
| `app/ml/serialize.py` | Serialization module |
| `app/pipeline/orchestrator.py` | Pipeline orchestrator |
| `tests/ml/test_ember_v2.py` | Extractor tests |
| `tests/ml/test_serialization.py` | Serialization tests |
| `scripts/validate_dataset_schema.py` | Dataset schema validator |
| `docs/data/DATASET_SCHEMA.md` | Dataset schema documentation |
| `docs/data/PROVENANCE.md` | Provenance record |
| `docs/ml/EMBER_V2_FEATURE_CONTRACT.md` | Feature contract |
| `ML03_READINESS_REAUDIT_REPORT.md` | ML-03 readiness report |
| `ML03A_Dataset_Readiness_Audit.md` | ML-03A readiness audit |

### Files Changed
| File | Change |
|---|---|
| `ML03B_Schema_Adapter_Implementation_Plan.md` | Created (this report) |

**No production code modified.** No tests modified. No dependencies installed.

---

## 9. Unresolved Questions

1. **EMBER 2018 split details:** Exact train/test counts and temporal boundaries are not published. Must be measured empirically after download.
2. **Validation split strategy:** EMBER provides train/test only. Validation split must be created from training data. Stratified vs. temporal holdout TBD.
3. **LIEF version for training:** Should training use LIEF 0.9.0 (reference) or 1.0.0 (installed)? Feature values may differ. Must be documented.
4. **Unlabeled sample usage:** Should unlabeled samples (-1) be used for semi-supervised learning or discarded? Depends on research goals.
5. **Model framework authorization:** LightGBM installation requires authorization. scikit-learn `HistGradientBoostingClassifier` available as fallback.

---

## 10. Next Authorization Needed

Before ML-03 can proceed, the following authorizations are required:

1. **Dataset acquisition authorization** — download `ember_dataset_2018_2.tar.bz2` (~4 GB)
2. **Dependency installation authorization** — install LIEF 0.9.0 and LightGBM (or approve scikit-learn fallback)
3. **Storage authorization** — confirm extraction location and disk space allocation
4. **Implementation authorization** — approve adapter, split logic, and training code implementation

**ML-03 remains BLOCKED** until these authorizations are granted and the dataset is acquired.

---

### Final Status

| Workstream | Status | Evidence |
|---|---|---|
| **C5** | PARTIAL | Source-level comparison: 8/9 MATCH, 1 confirmed mismatch (empty input, intentional). Full parity unverified. |
| **C8** | VERIFIED | Runtime version discovery; 7 new tests; all 75 tests pass |
| **C3** | VERIFIED | AC-05 evidence documented; no regression |
| **ML-03** | BLOCKED | Dataset absent; no real-data gates run |
| **ML-03A** | COMPLETE | Dataset readiness audit delivered |
| **ML-03B** | COMPLETE | Schema adapter implementation plan delivered |

**No commits made.** All changes remain uncommitted.