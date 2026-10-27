# ETHIO-AI Defender — ML-07 Feature Parity and Controlled Integration Validation Implementation Plan

**Milestone:** ML-07  
**Document Version:** 1.0  
**Date:** 2026-10-28  
**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`  
**Classification:** Internal Technical Architecture & Validation Plan  
**Target Status:** READY FOR VALIDATION  

---

## 1. Executive Summary & Pre-Implementation Audit

Milestone **ML-07** defines the empirical validation protocol for feature parity, inference correctness, and pipeline non-interference of the EMBER 2018 Feature Version 2 baseline machine learning model.

### 1.1 Audit of Existing Artifacts & Codebase State

| Component | Current State / Documented Version | Audit Finding |
|---|---|---|
| **Git Working Tree** | Branch `main` (ahead of origin by 3 commits) | Clean unstaged state preserved; all prior files intact |
| **Model Artifact** | `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib` | 1,609,815 bytes; SHA-256 `f2fd3ed4...` verified byte-for-byte |
| **Metadata Contract** | `metadata.json` (ember-v2-baseline-hgb-subset80k) | 2,381 dims, float32, calibrated thresholds (0.800395 @ 1% FPR) |
| **Raw PE Extractor** | `app/ml/ember_v2.py` | LIEF-based extractor; line 404 syntax fix verified |
| **Training Adapter** | `app/ml/ember_adapter.py` | Validated JSONL streaming parser for official 2018 dataset |
| **Classifier Service**| `app/ml/classifier.py` | Decoupled `EmberModelClassifier`; path security, dynamic classes_ mapping |
| **Pipeline Analyzer** | `app/analyzers/ml_analyzer.py` | `MLAnalyzer` with result schema `MLAnalysisResult` and Parity Gate |
| **Test Suite** | `tests/ml/` (136 tests passing) | Full ML test coverage achieved in ML-06 |

---

## 2. Reference Implementation & Version Identification

### 2.1 The Official EMBER 2018 Reference Specification

The reference standard for EMBER Feature Version 2 is defined in the official `elastic/ember` repository (`ember/features.py`, release 2018.2):
- **Package:** `ember` (v0.1.0)
- **Reference LIEF Version:** `0.9.0`
- **Reference Scikit-Learn:** `0.20.x` / `0.21.x`
- **Reference Feature Groups (9 total, 2,381 dims):**
  1. `ByteHistogram`: 256 unnormalized counts $\to$ L1 normalized.
  2. `ByteEntropyHistogram`: 256 unnormalized counts (16x16 joint entropy) $\to$ L1 normalized.
  3. `StringExtractor`: 104 dims (numstrings, avlength, printables, 96-dim printable distribution, entropy, paths, urls, registry, MZ).
  4. `GeneralFileInfo`: 10 dims (size, vsize, has_debug, exports, imports, has_relocations, has_resources, has_signature, has_tls, symbols).
  5. `HeaderFileInfo`: 62 dims (coff timestamp, 5 categorical hashed slices of 10 dims each, 11 optional header scalars).
  6. `SectionInfo`: 255 dims (5 section general stats, 3 hashed pairs of 50 dims each, entry name 50 dims, chars 50 dims).
  7. `ImportsInfo`: 1,280 dims (unique libraries 256 dims, "lib:func" pairs 1,024 dims).
  8. `ExportsInfo`: 128 dims (exported symbols hashed).
  9. `DataDirectories`: 30 dims (first 15 directories $\times$ [size, virtual_address]).

### 2.2 Environment Dependency Gap Analysis

| Dependency | Reference EMBER Specification | Local Python Environment | Parity Implication / Blocker Status |
|---|---|---|---|
| **Python Package `ember`** | `ember==0.1.0` | **Not Installed** (`ModuleNotFoundError`) | Package installation restricted by project constraints. Direct `import ember` unavailable. |
| **LIEF Engine** | `lief==0.9.0` | `lief==1.0.0-d05b3499b` | Version 1.0.0 API differences in section characteristics and export structures. |
| **Scikit-Learn** | `scikit-learn==0.21.x` | `scikit-learn==1.9.1` | `FeatureHasher(alternate_sign=True)` mathematically stable. |
| **Raw PE Ground-Truth Dataset** | Paired PE binaries matching JSONL | **Not Distributed** | Official EMBER 2018 archive distributes only JSONL feature records due to malware distribution safety. |

### 2.3 Implementation Strategy for Reference Comparison

To evaluate feature parity without violating the "no package installation" constraint:
1. Implement a standalone, self-contained reference extractor module (`tests/ml/reference_ember.py`) transcribing the exact reference logic from `elastic/ember/features.py`.
2. Generate authorized synthetic PE fixtures exercising all 9 feature groups (32-bit GUI, 64-bit GUI, DLL with exports, Driver SYS, benign Python executable).
3. Feed the **identical byte buffers** to both `app/ml/ember_v2.py` and the reference extractor.
4. Evaluate exact match counts and per-slice numerical divergence.

---

## 3. Phase 2: Empirical Feature Parity Design

### 3.1 Authorized PE Test Fixtures

All parity evaluations will be conducted on authorized test fixtures:
1. **`Fixture-A (PE32+ GUI Executable)`**: 64-bit executable with `.text` and `.data` sections, multiple data directories, and ASCII strings.
2. **`Fixture-B (PE32 CUI Executable)`**: 32-bit console executable with relocations, TLS table, and debug directory.
3. **`Fixture-C (PE32+ Dynamic Link Library)`**: 64-bit DLL with exported functions and resources.
4. **`Fixture-D (PE32 System Driver)`**: 32-bit SYS binary with `IMAGE_FILE_SYSTEM` flag.
5. **`Fixture-E (Authorized Real Binary)`**: The authorized local system binary (`sys.executable`, Python 3.14 interpreter).

### 3.2 Parity Measurement Metrics

For each fixture, the 2,381 feature vectors $V_{\text{local}}$ and $V_{\text{ref}}$ will be evaluated:
- **Exact Matches:** Count and percentage where $|V_{\text{local}}[i] - V_{\text{ref}}[i]| = 0$.
- **Close Matches:** Count and percentage where $|V_{\text{local}}[i] - V_{\text{ref}}[i]| \le 10^{-5}$.
- **Mismatches:** Detailed breakdown by feature group.
- **Root Cause Analysis:** Document whether mismatches stem from LIEF 1.0 vs 0.9 differences, hashing conventions, or normalization logic.

---

## 4. Phase 3: Inference Parity Design

### 4.1 Evaluation Against Staged Reference Vectors

Inference parity will be validated using real, trusted feature vectors from `D:\ethio_ai_defender_artifacts\staged\X_val.mmap`:
1. **Direct Estimator Inference:**
   ```python
   raw_clf = joblib.load("model.joblib")
   pos_idx = list(raw_clf.classes_).index(1)
   expected_scores = raw_clf.predict_proba(X_val[:N])[:, pos_idx]
   ```
2. **Adapter Inference:**
   ```python
   classifier = EmberModelClassifier()
   actual_scores = classifier.predict_proba(X_val[:N])
   ```
3. **Parity Tolerance:** Maximum absolute difference $\max |actual - expected| = 0.0$ (exact bitwise parity).

### 4.2 Negative & Boundary Testing
- Reject vectors with non-finite values (`NaN`, `+Inf`, `-Inf`).
- Reject vectors with dimension $\ne 2381$.
- Reject batches exceeding 1,000 samples.
- Reject tampered model files prior to deserialization.
- Reject unapproved / untrusted upload directories.

---

## 5. Phase 4: Pipeline Non-Interference Design

### 5.1 Deterministic Analyzer Invariance

Execute deterministic static analyzers before and after invoking `MLAnalyzer` in both success and failure modes:
- `pe_static_analyzer_service`
- `hash_analyzer_service`
- `pe_section_analyzer_service`
- `entropy_analyzer_service`
- `string_analyzer_service`
- `windows_api_import_analyzer_service`
- `threat_scoring_engine_service`

**Assertion:** Output dictionaries from deterministic analyzers must match bitwise before and after ML analysis. Threat scores and risk classifications must not change.

### 5.2 Fault Containment & Parity Gate Verification

1. Simulate missing model $\to$ `MLAnalysisResult(status="UNAVAILABLE", available=False)`.
2. Simulate bad checksum $\to$ `MLAnalysisResult(status="FAILED", available=False)`.
3. Evaluate raw PE binary $\to$ `MLAnalysisResult(status="OFFLINE_TEST_UNVERIFIED_PARITY", feature_parity_status="UNVERIFIED_RAW_PE_PARITY", is_reliable=False)`.
4. Evaluate pre-extracted vector $\to$ `MLAnalysisResult(status="SUCCESS", feature_parity_status="VERIFIED_FEATURE_VECTOR", is_reliable=True)`.

---

## 6. Files Expected to Change / Be Created

1. `tests/ml/reference_ember.py` (New): Standalone transcription of official `elastic/ember/features.py` reference extractor for controlled in-process parity comparison.
2. `tests/ml/test_feature_parity.py` (New): Automated parity test suite running paired comparisons across Fixtures A–E.
3. `tests/ml/test_inference_parity.py` (New): Inference parity test suite verifying `EmberModelClassifier` against raw `model.joblib` on real validation vectors.
4. `ML07_Implementation_Plan.md` (New): This implementation plan.
5. `ML07_Feature_Parity_Validation_Report.md` (New): Final validation evidence and milestone decision report.

---

## 7. Decision Gates & Milestones

The final milestone decision will be selected based on measured evidence:
- **`BLOCKED: REFERENCE OR FIXTURES UNAVAILABLE`**: Selected if reference extraction logic cannot be evaluated or authorized fixtures are absent.
- **`NOT READY: FEATURE PARITY FAILED`**: Selected if significant unexplained divergence ($> 5\%$) occurs across mathematical features (histograms, entropy).
- **`PARTIAL: FEATURE PARITY NOT FULLY ESTABLISHED`**: Selected if reference logic matches mathematically on synthetic fixtures, but empirical bitwise parity on real 2018 binaries remains unproven due to LIEF version gaps and dataset distribution limitations.
- **`PASS FOR CONTROLLED OFFLINE VALIDATION`**: Selected only if 100% bitwise parity is achieved on all test fixtures and reference vectors.
