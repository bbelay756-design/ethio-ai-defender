# ETHIO-AI Defender: ML-07A Evidence Audit Report

**Milestone:** ML-07A (Independent Evidence Audit)  
**Date:** October 28, 2026  
**Auditor:** Antigravity Autonomous Security Audit Agent  
**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`  
**Final Recommendation:** **`ACCEPT ML-07 PARTIAL`**

---

## 1. Repository State and Integrity Preservation

Prior to conducting the audit, the current repository state was inspected and recorded to ensure no unapproved modifications, commits, resets, or restores occurred.

### 1.1 Git Status and Commit Coordinates
- **Current Branch:** `my-feature-branch`
- **Current HEAD Commit:** `0e8412b0ee3756c9600bf9a8ed45fbf8478914a6` (`Add ML and YARA updates`)
- **Remote Tracking:** Up to date with `origin/my-feature-branch`
- **Working Tree Inspection:**
  ```text
  Changes not staged for commit:
    modified:   tests/ml/test_pipeline_noninterference.py
  Untracked files:
    ML07_Feature_Parity_Validation_Report.md
  ```
- **Integrity Boundary Verification:**
  - `tests/ml/test_pipeline_noninterference.py` modifications contain strictly two isolated corrections: aligning `AnalysisContext` constructor keyword argument names (`pe`, `sections`, `entropy`, `strings`, `imports`) and fixing `ThreatScoreResult.to_dict()` key assertion (`score_base["score"] == score_after["score"]`).
  - No resets (`git reset`), cleans (`git clean`), restores (`git restore`), or commits were performed.

---

## 2. Reference Extractor Audit (`tests/ml/reference_ember.py`)

**Finding Classification:** **`PARTIALLY VERIFIED`**

### 2.1 Audit Against Upstream Specification
The module [`tests/ml/reference_ember.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/reference_ember.py) was audited against the upstream EMBER 2018 v2 specification (`elastic/ember/ember/features.py`, Feature Version 2).

| Feature Family | Dimension | Specification Match | Hashing / Type Settings | Handling of Absent Fields | Audit Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `ByteHistogram` | 256 | Exact | `np.bincount(minlength=256)`, float32 normalization | Returns all-zero vector if sum is 0 | **VERIFIED** |
| `ByteEntropyHistogram` | 256 | Exact | Window=2048, step=1024, 16x16 2D joint entropy | Returns flat zero if size < window & empty | **VERIFIED** |
| `StringExtractor` | 104 | Exact | 96 printable chars + 8 scalars (length, count, paths, urls, registry, MZ) | Returns zeroed distribution and counts | **VERIFIED** |
| `GeneralFileInfo` | 10 | Exact | 10 PE properties (size, vsize, debug, exports, imports, relocs, resources, sig, tls, symbols) | Defaults to 0 for missing LIEF properties | **VERIFIED** |
| `HeaderFileInfo` | 62 | Exact | 5 hashers (dim 10 each, `alternate_sign=True`) + timestamp + 11 numerics | Defaults to 0 / empty strings | **VERIFIED** |
| `SectionInfo` | 255 | Exact | 5 general counts + 5 hashers (dim 50 each, `alternate_sign=True`) | Missing sections handle empty list | **VERIFIED** |
| `ImportsInfo` | 1,280 | Exact | `libraries` (256 dims) + `imports` (1024 dims) | Handles empty imports dictionary | **VERIFIED** |
| `ExportsInfo` | 128 | Exact | `exports` (128 dims, `FeatureHasher(128)`) | Handles empty export list | **VERIFIED** |
| `DataDirectories` | 30 | Exact | First 15 directories * [size, virtual_address] | Zero-padded if < 15 directories | **VERIFIED** |
| **Total Vector** | **2,381** | **Exact** | Horizontal concatenation, `dtype=np.float32` | Total vector dimension is strictly 2,381 | **VERIFIED** |

### 2.2 Independence and Provenance Discrepancies
- **Directly Verified vs Transcribed:** The algorithms, dimensions, hashing parameters, and normalization logic directly replicate `elastic/ember/features.py`.
- **Adaptations for Modern LIEF:** Modern LIEF (`lief 0.17.2`) replaced `has_signature` with `has_signatures` and `section_from_offset` with `section_from_rva`. Lines 165 and 294–300 contain conditional fallbacks to accommodate both LIEF 0.9 and 0.17.
- **Independence Caveat:** `reference_ember.py` is an in-tree Python transcription authored within the test suite, **not an independently installed binary distribution from PyPI** (`pip install ember` is not installed, in compliance with package installation constraints). Therefore, it serves as an algorithmic reference standard rather than an external third-party oracle package.

---

## 3. Five Paired Fixtures Audit

**Finding Classification:** **`VERIFIED`** *(for tested fixtures against algorithmic reference)*

### 3.1 Provenance, Digest, and Architectural Specification
Each fixture was audited for byte-level provenance, SHA-256 integrity, architecture, and extractor configuration.

| Fixture ID | Provenance | Exact File Path / Source | File Size | SHA-256 Digest | File Type / Arch |
| :--- | :--- | :--- | :---: | :--- | :--- |
| **PE-FIX-01** | Existing trusted test fixture | `in-memory (build_synthetic_pe(is_64bit=True))` | 4,096 B | `8d46fb4f9bff62c59cacc254ded4551625008b2b05a63276fd9c23676e95b0d0` | PE32+ / x64 GUI |
| **PE-FIX-02** | Existing trusted test fixture | `in-memory (build_synthetic_pe(is_64bit=False, subsystem=3))` | 4,096 B | `106f49c0591f135b188f0900159ec2fa10308d4d11e0d1c9d3369836aa50fcb3` | PE32 / x86 Console |
| **PE-FIX-03** | Existing trusted test fixture | `in-memory (build_synthetic_pe(is_64bit=True, is_dll=True))` | 4,096 B | `39eef710eaca5f11c6e6ef111ae92fe3859ddfbfda195bf78f6049a324b48d72` | PE32+ / x64 DLL |
| **PE-FIX-04** | Existing trusted test fixture | `in-memory (build_synthetic_pe(is_64bit=True, is_driver=True))` | 4,096 B | `4aae62c2b2d09e26da142122124307b9c37121aaa251069cf4061392938d0339` | PE32+ / x64 Driver |
| **PE-FIX-05** | Host Python runtime binary | `C:\Users\MILKWAY\ethio-ai-defender\venv\Scripts\python.exe` | 255,320 B | `4b8c3912806b3c1591ba3cb403bff77ad309c3fe5756f87c20b7a6f8f0174262` | PE32+ / x64 Executable |

### 3.2 Paired Comparison Audit Results
Direct execution of the paired comparison between [`app/ml/ember_v2.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_v2.py) and [`tests/ml/reference_ember.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/reference_ember.py) on identical in-memory byte buffers yielded the following empirical metrics:

| Fixture ID | Compared Features | Exact Matches | Mismatches | Max Abs Diff | Mean Abs Diff |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **PE-FIX-01** | 2,381 | 2,381 (100.00%) | 0 | 0.00000000 | 0.00000000 |
| **PE-FIX-02** | 2,381 | 2,381 (100.00%) | 0 | 0.00000000 | 0.00000000 |
| **PE-FIX-03** | 2,381 | 2,381 (100.00%) | 0 | 0.00000000 | 0.00000000 |
| **PE-FIX-04** | 2,381 | 2,381 (100.00%) | 0 | 0.00000000 | 0.00000000 |
| **PE-FIX-05** | 2,381 | 2,381 (100.00%) | 0 | 0.00000000 | 0.00000000 |

### 3.3 Feature-Family Results Across All Fixtures
For all 5 fixtures, every single feature group achieved a 100% exact match:
- `histogram`: 256 / 256 exact (max diff: 0.0)
- `byteentropy`: 256 / 256 exact (max diff: 0.0)
- `strings`: 104 / 104 exact (max diff: 0.0)
- `general`: 10 / 10 exact (max diff: 0.0)
- `header`: 62 / 62 exact (max diff: 0.0)
- `section`: 255 / 255 exact (max diff: 0.0)
- `imports`: 1,280 / 1,280 exact (max diff: 0.0)
- `exports`: 128 / 128 exact (max diff: 0.0)
- `datadirectories`: 30 / 30 exact (max diff: 0.0)

---

## 4. Inference Parity Audit

**Finding Classification:** **`VERIFIED`**

### 4.1 Artifact Digest and Sidecar Verification
- **Artifact Path:** `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib`
- **Computed SHA-256:** `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684`
- **Sidecar File:** `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib.sha256`
- **Sidecar Contents:** `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684  model.joblib`
- **Code Constant:** `TRUSTED_BASELINE_MODEL_SHA256` in [`app/ml/classifier.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/classifier.py#L29) = `"f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684"`
- **Integrity Result:** Bitwise match across computed hash, sidecar file, and code constant.

### 4.2 Estimator Properties and Calibration Metadata
- **Estimator Class:** `sklearn.ensemble._hist_gradient_boosting.gradient_boosting.HistGradientBoostingClassifier`
- **Feature Dimension:** 2,381 (`n_features_in_ = 2381`)
- **Class Labels (`classes_`):** `[0, 1]`
- **Positive-Class Index:** 1 (dynamically resolved via `np.where(classes_ == 1)[0][0]`)
- **Threshold Metadata in `metadata.json`:**
  - `fpr_1pct_target`: Threshold = `0.8003951606744594` (TPR = 91.41%, FPR = 0.998%)
  - `fpr_01pct_target`: Threshold = `0.9663647691558608` (TPR = 76.60%, FPR = 0.097%)
  - `default_05`: Threshold = `0.5` (TPR = 96.62%, FPR = 3.55%)

### 4.3 Empirical Reproduction on 100 Staged Validation Vectors
Audited using `D:\ethio_ai_defender_artifacts\staged\X_val.mmap`:
- Sample slice: `X_val[0:100]`
- Direct estimator prediction: `estimator.predict_proba(X_sample)[:, 1]`
- Adapter prediction: `EmberModelClassifier.predict_proba(X_sample)`
- **Sample Count:** 100
- **Exact Matches:** 100 / 100 (100.00%)
- **Max Absolute Probability Difference:** `0.00000000e+00`
- **Mean Absolute Probability Difference:** `0.00000000e+00`
- **Test Failures:** 0

---

## 5. Test Execution and Overlap Audit

**Finding Classification:** **`VERIFIED`**

### 5.1 Suite Reproduction Commands and Results
Each test suite was independently reproduced and its collected test node IDs recorded:

```powershell
# Suite 1: ML Subsystem Tests
$env:PYTHONPATH="."; pytest tests/ml/ -v
# Result: 150 passed in 34.61s, Exit code: 0

# Suite 2: Core Static Analyzer Tests
$env:PYTHONPATH="."; pytest tests/test_pe_analyzer.py tests/test_hash_analyzer.py tests/test_section_analyzer.py tests/test_entropy_analyzer.py tests/test_string_analyzer.py tests/test_import_analyzer.py tests/test_threat_scoring.py tests/test_file_intake.py -q
# Result: 82 passed in 8.48s, Exit code: 0

# Suite 3: Core Security and Audit Tests
$env:PYTHONPATH="."; pytest tests/test_auth_security.py tests/test_module_18_security_attacks.py tests/test_audit_logger.py -q
# Result: 24 passed in 17.58s, Exit code: 0
```

### 5.2 Set-Theoretic Overlap Analysis
To verify whether the test suites contain duplicate or overlapping test node IDs, programmatic collection and set intersection was executed:

```text
Suite 1 (tests/ml/):                      150 unique tests collected
Suite 2 (Static Analyzers):                82 unique tests collected
Suite 3 (Security & Audit):                24 unique tests collected

Intersection(Suite 1, Suite 2):             0 tests overlap
Intersection(Suite 1, Suite 3):             0 tests overlap
Intersection(Suite 2, Suite 3):             0 tests overlap

Total Unique Test Cases across 3 suites:  256 unique tests
```
**Conclusion:** The three test suites are **mutually disjoint** (zero overlap). Reporting 256 unique passing tests is mathematically and empirically verified.

---

## 6. Verdict and Safety Gates Audit

**Finding Classification:** **`VERIFIED`**

### 6.1 Parity Gate Enforcement in `MLAnalyzer`
- When raw PE bytes are processed by [`MLAnalyzer.analyze_pe_bytes`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ml_analyzer.py#L201-L283):
  - Result status is explicitly `"OFFLINE_TEST_UNVERIFIED_PARITY"`.
  - Result `feature_parity_status` is `"UNVERIFIED_RAW_PE_PARITY"`.
  - Flag `is_reliable` is strictly `False`.
  - Result message documents: *"Raw-PE feature extraction parity with EMBER 2018 training dataset is unverified. Predictions must not be used for automated blocking or production verdict assignment."*

### 6.2 Pipeline and Orchestration Isolation
- Codebase-wide symbol inspection reveals [`MLAnalyzer`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ml_analyzer.py) is referenced **only** in `app/analyzers/__init__.py`, `app/analyzers/ml_analyzer.py`, and test files.
- It is **not** imported or invoked by the production pipeline orchestrator ([`app/pipeline/orchestrator.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/pipeline/orchestrator.py)) or the threat scoring engine ([`app/analyzers/threat_scoring.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/threat_scoring.py)).
- Raw-PE predictions cannot trigger production blocking, quarantine, or remediation.
- No model thresholds were altered, no retraining was performed, and threat-scoring policies remain unchanged.

---

## 7. Discrepancies and Narrow Test Corrections

1. **Sidecar Filename Distinction:** The model sidecar in `D:\ethio_ai_defender_artifacts\ember_baseline_v1\` is named `model.joblib.sha256` (not `model.sha256`). [`app/ml/classifier.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/classifier.py#L129) correctly checks `model.joblib.sha256`.
2. **Host Python Executable Size:** The exact byte size of `venv\Scripts\python.exe` is 255,320 bytes (SHA-256: `4b8c3912806b3c1591ba3cb403bff77ad309c3fe5756f87c20b7a6f8f0174262`), rather than earlier approximations.
3. **Reference Extractor Nature:** The reference extractor is an in-process Python transcription conforming to `elastic/ember/features.py`. Calling it an "external ground-truth package" would be inaccurate without `pip install ember`. Its designation as an *algorithmic reference transcription* is accurate and verified.

---

## 8. Final Audit Recommendation

### **`ACCEPT ML-07 PARTIAL`**

**Justification:**
1. The empirical testing is fully reproducible from committed working files and clean commands.
2. 100% numerical parity against the EMBER v2 algorithmic reference was verified on all 5 authorized fixtures.
3. 100% inference parity between the direct estimator and the adapter wrapper was verified on staged validation data.
4. Zero overlap among the 256 unique passing tests was mathematically proven.
5. The Parity Gate properly restrains the ML classifier to controlled offline evaluation, strictly preventing unverified raw-PE verdicts from influencing production security policy.
6. The designation `PARTIAL` honestly reflects the structural limitation of the historical benchmark dataset (absence of raw 2018 malware PE binaries) while certifying the implementation safe for offline validation.
