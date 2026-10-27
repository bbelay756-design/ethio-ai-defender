# ETHIO-AI Defender — ML-06 Controlled Offline Integration Report

**Milestone:** ML-06 (Controlled Offline Integration)  
**Document Version:** 1.0  
**Date:** 2026-10-28  
**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`  
**Branch:** `main` (Ahead of `origin/main` by 3 commits)  
**Execution Environment:** Python 3.14.4 (win32), scikit-learn 1.9.1, NumPy 2.5.4, LIEF 1.0.0-d05b3499b  
**Final Milestone Status:** **IMPLEMENTED WITH LIMITATIONS**  
*(Authorized exclusively for controlled offline testing. Not approved for production blocking or autonomous verdict assignment.)*

---

## 1. Executive Summary

Milestone **ML-06** has successfully implemented a decoupled, fail-closed machine learning classifier service (`EmberModelClassifier`) and an isolated static analysis component (`MLAnalyzer`) for the EMBER 2018 Feature Version 2 baseline model. 

All mandatory starting gates, security boundaries, and architectural isolation requirements were strictly observed:
1. **Pre-flight Integrity Verification:** The model artifact (`D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib`) was verified byte-for-byte against its trusted cryptographic SHA-256 digest (`f2fd3ed4...`). Deserialization is protected by fail-closed digest enforcement.
2. **Path Confinement & Upload Protection:** Model loading is restricted to approved local directories. Direct loading from user uploads, quarantine, or arbitrary user paths is blocked and tested.
3. **Dynamic Malicious Class Indexing:** Malicious-class probabilities are resolved dynamically via `estimator.classes_` rather than hardcoding column index 1.
4. **Input Guardrails & Bounded Work:** Non-finite values (NaN, +Inf, -Inf), malformed feature dimensions, and batches exceeding 1,000 samples are strictly rejected.
5. **Parity Gate & Safe Degradation:** A critical runtime defect in raw-PE feature extraction was discovered and resolved. Because bitwise feature parity between the local LIEF 1.0 extractor and the 2018 training set remains unverified on paired binaries, `MLAnalyzer` enforces a strict Parity Gate: predictions on raw PE files are flagged as `UNVERIFIED_RAW_PE_PARITY` with `is_reliable=False`, preventing automated blocking.
6. **Zero Production Mutation:** Deterministic analyzers (PE, Hashes, YARA, Strings, Threat Scoring) and the database schema remain untouched and bitwise deterministic.
7. **Comprehensive Test Validation:** 136 / 136 ML tests and 106 / 106 core regression tests passed cleanly (Exit code 0).

---

## 2. Inventory of Files Changed & Created

| File Path | Action | Description & Purpose |
|---|---|---|
| `ML06_Implementation_Plan.md` | **Created** | Comprehensive architectural plan covering integration interfaces, schemas, validation, and test design. |
| `app/ml/classifier.py` | **Modified** | Re-implemented `EmberModelClassifier` with path allowlisting, trusted digest authority, dynamic `classes_` resolution, input validation, and typed `ClassifierPredictionResult`. |
| `app/ml/ember_v2.py` | **Modified** | Fixed line 404 syntax bug (`self._hashers["entry_name"].transform([[entry_name]])`) allowing PE binaries to extract section features without throwing `ValueError`. |
| `app/analyzers/ml_analyzer.py` | **Created** | Implemented `MLAnalyzer` service with result schema `MLAnalysisResult`, explicit parity gate, error sanitization, and resource limits. |
| `app/analyzers/__init__.py` | **Modified** | Exported `MLAnalyzer`, `MLAnalysisResult`, and `ml_analyzer_service` in package interface. |
| `tests/ml/test_classifier.py` | **Modified** | Expanded unit test suite covering tamper rejection, upload path blocking, class mapping, batch size bounding, and real artifact reloading (11 tests). |
| `tests/ml/test_ml_analyzer.py` | **Created** | Test suite covering explicit ML-unavailable states, parity gate behavior, failure isolation, resource boundaries, and deterministic analyzer non-interference (8 tests). |
| `ML06_Implementation_Report.md` | **Created** | Final milestone verification and technical audit report. |

*Note on Git Integrity:* Existing unstaged modifications in `app/analyzers/yara_analyzer.py`, `app/db/`, `app/main.py`, and `app/pipeline/orchestrator.py` were preserved without modification, reset, or commit.

---

## 3. Cryptographic Checksum & Artifact Verification

Prior to unpickling, the model artifact was subjected to independent cryptographic audit:

| Verification Parameter | Recorded Trusted Value | Locally Computed Value | Status |
|---|---|---|---|
| **Model Path** | `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib` | `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib` | **FOUND** |
| **File Size** | 1,609,815 bytes (1.54 MB) | 1,609,815 bytes | **EXACT MATCH** |
| **Model SHA-256** | `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684` | `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684` | **BITWISE MATCH** |
| **Sidecar File** | `model.joblib.sha256` | Contains matching SHA-256 string | **VERIFIED** |
| **Estimator Type** | `sklearn.ensemble.HistGradientBoostingClassifier` | `HistGradientBoostingClassifier` (300 iterations) | **VERIFIED** |
| **Estimator Classes** | `[0, 1]` | `array([0, 1])` (Malicious class index = 1) | **VERIFIED** |
| **Calibrated Thresholds** | 1.0% FPR $\tau^* = 0.800395$ \| 0.1% FPR $\tau^* = 0.966365$ | Parsed from `metadata.json` | **VERIFIED** |

### Expected Digest Protection Strategy

As mandated by Requirement 3:
1. `EmberModelClassifier` does **not** rely on the `.sha256` file in the artifact directory as the sole integrity authority.
2. The expected digest is hardcoded in `TRUSTED_BASELINE_MODEL_SHA256` and can be overridden via the protected environment variable `ETHIO_ML_TRUSTED_MODEL_SHA256`.
3. If an artifact directory contains a `.sha256` sidecar that disagrees with the trusted configured digest, loading is aborted immediately with an explicit tampering error.

---

## 4. Feature Parity Evidence & Remaining Gaps

### 4.1 Defect Discovery in `app/ml/ember_v2.py`

During Starting Gate verification of `app/ml/ember_v2.py` against `app/ml/ember_adapter.py`, a critical runtime defect was uncovered:
```python
# Before (app/ml/ember_v2.py line 404):
entry_hashed = self._hashers["entry_name"].transform([entry_name]).toarray()[0]
```
`FeatureHasher(input_type="string")` expects an iterable over iterables of strings (`[[entry_name]]`). Passing a 1D list of strings `[entry_name]` caused scikit-learn to throw:
`ValueError: Samples can not be a single string. The input must be an iterable over iterables of strings.`

This bug had remained dormant because prior tests only passed empty bytes `b""` or truncated headers, where LIEF returned `None` and bypassed section parsing. When tested against real PE binaries (`sys.executable`), feature extraction crashed 100% of the time.

The issue was resolved by replacing line 404 with `[[entry_name]]`, matching the syntax in `app/ml/ember_adapter.py:542`.

### 4.2 Structural Comparison Across All 9 Feature Groups

| Group | Dimensions | Local Extractor (`ember_v2.py`) | Training Adapter (`ember_adapter.py`) | Structural Parity |
|---|---|---|---|---|
| **Histogram** | 256 | L1 normalized `np.bincount` | L1 normalized list input | **MATCH** |
| **ByteEntropy** | 256 | L1 normalized rolling 16x16 joint entropy | L1 normalized 256 list | **MATCH** |
| **Strings** | 104 | 96-dim printable dist + 8 scalars | 96-dim printable dist + 8 scalars | **MATCH** |
| **General** | 10 | 10 PE metadata scalars via LIEF | 10 PE metadata scalars from JSON | **MATCH** |
| **Header** | 62 | COFF timestamp, 5 categorical (10 ea), 11 optional | COFF timestamp, 5 categorical (10 ea), 11 optional | **MATCH** |
| **Section** | 255 | 5 stats, 3 hashed pairs (50 ea), entry (50), chars (50) | 5 stats, 3 hashed pairs (50 ea), entry (50), chars (50) | **MATCH** |
| **Imports** | 1280 | Libs (256 hashed), `lib:func` (1024 hashed) | Libs (256 hashed), `lib:func` (1024 hashed) | **MATCH** |
| **Exports** | 128 | Export symbols (128 hashed) | Export symbols (128 hashed) | **MATCH** |
| **DataDirectories**| 30 | First 15 data directories [size, rva] | First 15 data directories [size, rva] | **MATCH** |

### 4.3 Remaining Feature Parity Gaps & Parity Gate

While structural feature definitions match, the following empirical gaps remain:
1. **LIEF Version Differences:** The EMBER 2018 dataset was generated with `lief 0.9.0`. The current environment runs `lief 1.0.0-d05b3499b`. LIEF version increments alter section characteristics parsing and export parsing on edge-case binaries.
2. **Missing Ground-Truth Paired Fixtures:** The repository does not contain paired `(PE binary, JSONL record)` sample pairs from the official 2018 acquisition to numerically verify bitwise parity across all 2,381 features.

**Parity Gate Implementation:**
- Pre-extracted feature vectors evaluated via `analyze_feature_vector()` return `feature_parity_status="VERIFIED_FEATURE_VECTOR"`, `is_reliable=True`, and `status="SUCCESS"`.
- Raw PE binaries evaluated via `analyze_pe_bytes()` return `feature_parity_status="UNVERIFIED_RAW_PE_PARITY"`, `is_reliable=False`, and `status="OFFLINE_TEST_UNVERIFIED_PARITY"`.
- Automated blocking or malware verdicts driven by raw PE inference are explicitly prohibited until empirical bitwise parity is demonstrated.

### 4.4 Recommended Parity-Test Suite Design

To close the parity gap in future milestones:
1. Acquire a paired verification set of 1,000 diverse PE binaries corresponding to known SHA-256 records in `test_features.jsonl`.
2. Execute `EMBERFeatureExtractor.feature_vector()` on the binaries.
3. Compare against `EmberDatasetAdapter.parse_record()` on the paired JSONL records.
4. Parity acceptance criteria: Absolute tolerance $\epsilon \le 10^{-5}$ across continuous features and 100% exact match across all categorical hashed slices.

---

## 5. Failure-Path & Security Test Evidence

Controlled failure tests were executed to verify system containment under adversarial and corrupted conditions:

| Test ID | Condition | Injected Fault | Measured System Behavior | Result |
|---|---|---|---|---|
| **F-01** | Artifact Tampering | Bit-flip in `model.joblib.sha256` | Pre-unpickle check raised `EmberModelError("Sidecar checksum tampering detected")` | **PASS** |
| **F-02** | Upload Infiltration | Loading attempted from `storage/uploads` | Path validation raised `EmberModelError("Loading models from 'uploads' directory is prohibited")` | **PASS** |
| **F-03** | Quarantine Infiltration| Loading attempted from `storage/quarantine` | Path validation raised `EmberModelError("Loading models from 'quarantine' directory is prohibited")` | **PASS** |
| **F-04** | Metadata Schema Drift | `feature_dim = 999` in metadata | Metadata validation raised `EmberModelError("Incompatible feature_dim 999")` | **PASS** |
| **F-05** | Malformed Input Dims | Array with shape `(1, 500)` supplied | Feature validator raised `EmberModelError("Feature vector dimension mismatch")` | **PASS** |
| **F-06** | Non-Finite Values | Injected `NaN`, `+Inf`, and `-Inf` | Feature validator raised `EmberModelError("Feature vector contains non-finite values")` | **PASS** |
| **F-07** | Inverted Class Labels | Estimator fitted with `classes_ = [1, 0]` | Service dynamically mapped malicious index to 0; probabilities remained valid | **PASS** |
| **F-08** | Batch Resource Exhaustion | Injected batch of 1,001 feature vectors | Feature validator raised `EmberModelError("Batch size exceeds maximum limit of 1000")` | **PASS** |
| **F-09** | Uninitialized Pipeline | ML analyzer invoked without loaded model | Returned `available=False`, `status="UNAVAILABLE"`; never defaulted to benign | **PASS** |
| **F-10** | Path Information Leak | Analysis requested on non-existent file | Error sanitized to `Target file does not exist`; zero filesystem paths leaked | **PASS** |
| **F-11** | Deterministic Isolation | ML analyzer failed on synthetic binary | PE header analysis and file hashes remained bitwise identical before and after | **PASS** |

---

## 6. Test Suite Execution & Exit Codes

### 6.1 ML Subsystem Test Suite (`tests/ml/`)

**Command:**
```powershell
$env:PYTHONPATH="."; pytest tests/ml/ -v
```
**Exit Code:** `0`  
**Duration:** `22.79s`  
**Results:** **136 passed**, 0 failed, 36 warnings (cosmetic deprecation warnings in `serialize.py`).

Breakdown:
- `tests/ml/test_baseline_model.py`: 4 passed (real artifact reload and contract verification)
- `tests/ml/test_classifier.py`: 11 passed (classifier integrity, security, class mapping, dimensions)
- `tests/ml/test_ml_analyzer.py`: 8 passed (analyzer interface, parity gate, failure paths, isolation)
- `tests/ml/test_ember_adapter.py`: 34 passed (JSONL schema adapter verification)
- `tests/ml/test_ember_v2.py`: 45 passed (feature extractor and serialization)
- `tests/ml/test_evaluator.py`: 4 passed (evaluation metrics and threshold calibration)
- `tests/ml/test_serialization.py`: 30 passed (NPZ feature vector serialization)

### 6.2 Deterministic Static Analyzer Regression Suite

**Command:**
```powershell
$env:PYTHONPATH="."; pytest tests/test_pe_analyzer.py tests/test_hash_analyzer.py tests/test_section_analyzer.py tests/test_entropy_analyzer.py tests/test_string_analyzer.py tests/test_import_analyzer.py tests/test_threat_scoring.py tests/test_file_intake.py
```
**Exit Code:** `0`  
**Duration:** `8.72s`  
**Results:** **82 passed**, 0 failed. Zero regressions across static analysis modules.

### 6.3 Security, Attack Simulation, and Audit Regression Suite

**Command:**
```powershell
$env:PYTHONPATH="."; pytest tests/test_auth_security.py tests/test_module_18_security_attacks.py tests/test_audit_logger.py
```
**Exit Code:** `0`  
**Duration:** `19.88s`  
**Results:** **24 passed**, 0 failed. Perimeter validation, auth lockout, and security attack shields intact.

**Total Verified Tests:** **242 / 242 passing (100%)**.

---

## 7. Result Schema & API Changes

### 7.1 New `ClassifierPredictionResult` Contract (`app/ml/classifier.py`)

```python
@dataclass(frozen=True)
class ClassifierPredictionResult:
    malicious_score: float
    is_malicious: bool
    is_malicious_1pct_fpr: bool
    is_malicious_01pct_fpr: bool
    active_threshold: float
    thresholds: Dict[str, float]
    model_name: str
    model_version: str
    model_sha256: str
    feature_dim: int
```

### 7.2 New `MLAnalysisResult` Contract (`app/analyzers/ml_analyzer.py`)

```python
@dataclass
class MLAnalysisResult:
    available: bool = False
    status: str = "UNAVAILABLE"
    message: str = ""
    malicious_score: Optional[float] = None
    is_malicious: Optional[bool] = None
    is_malicious_1pct_fpr: Optional[bool] = None
    is_malicious_01pct_fpr: Optional[bool] = None
    active_threshold: Optional[float] = None
    thresholds: Dict[str, float] = field(default_factory=dict)
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    model_sha256: Optional[str] = None
    feature_dim: int = 2381
    feature_parity_status: str = "UNVERIFIED"
    is_reliable: bool = False
    execution_time_ms: float = 0.0
    error: Optional[str] = None
```

*Zero Database / Pipeline Mutations:* No changes were made to SQLAlchemy models (`app/db/models.py`), Pydantic schemas (`app/db/schemas.py`), or `app/pipeline/orchestrator.py`. The ML analyzer is purely decoupled.

---

## 8. Known Limitations & Remediation Plan

1. **Raw-PE Reference Parity Limitation:**  
   *Finding:* The local feature extractor (`app/ml/ember_v2.py`) has not been numerically verified against ground-truth PE binaries from the 2018 reference dataset.  
   *Remediation:* Implement the parity test harness described in Section 4.4 before authorizing ML predictions for operational blocking.
2. **Subsampled Training Dataset:**  
   *Finding:* The baseline model was trained on an 80,000-sample balanced stratified subset rather than the full 1-million sample EMBER corpus.  
   *Remediation:* Re-train on an expanded partition when physical memory (> 8 GB) and disk storage (> 30 GB) are allocated.
3. **Deprecation Warnings in `serialize.py`:**  
   *Finding:* `datetime.datetime.utcnow()` generates cosmetic deprecation warnings.  
   *Remediation:* Update to `datetime.datetime.now(timezone.utc)` in next maintenance cycle.

---

## 9. Final Milestone Acceptance Status

```
================================================================================
MILESTONE ML-06 STATUS: IMPLEMENTED WITH LIMITATIONS
================================================================================
Evaluation Evidence:
  1. EmberModelClassifier fully decoupled with cryptographic checksum validation.
  2. Fail-closed error handling: zero silent benign conversions.
  3. Dynamic class mapping via estimator.classes_ verified.
  4. Path allowlisting prevents model loading from uploads or quarantine.
  5. MLAnalyzer isolated from production blocking; Parity Gate enforced.
  6. 242 / 242 tests passed across ML subsystem and core analyzer test suites.
  7. Zero mutations to existing production database models or deterministic policies.

Documented Limitations:
  - Authorized exclusively for controlled offline testing.
  - Raw PE inference is flagged as UNVERIFIED_RAW_PE_PARITY (is_reliable=False).
  - Production deployment or ML-based blocking is strictly prohibited in this phase.
================================================================================
```
