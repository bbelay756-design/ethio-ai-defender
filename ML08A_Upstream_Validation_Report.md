# ETHIO-AI Defender: ML-08A Upstream Reference Validation Report

**Milestone:** ML-08A (Upstream Reference Acquisition and Empirical Parity Validation)  
**Date:** October 28, 2026  
**Auditor / Agent:** Antigravity Autonomous Security Engineer  
**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`  
**Final Outcome:** **`PASS FOR BROADER CONTROLLED OFFLINE VALIDATION`**

---

## 1. Executive Summary

Milestone **ML-08A** was executed following explicit user authorization to acquire and validate against the canonical, independent Elastic EMBER upstream reference implementation under strict isolation guarantees.

### Key Achievements:
1. **Isolated Upstream Acquisition:** Cloned `https://github.com/elastic/ember.git` into an isolated vendor directory ([`vendor/elastic_ember_upstream`](file:///C:/Users/MILKWAY/ethio-ai-defender/vendor/elastic_ember_upstream)) ignored by Git. Checked out and cryptographically verified canonical commit **`d97a0b523de02f3fe5ea6089d080abacab6ee931`** (`Pin LIEF Version (#90)` by Phil Roth).
2. **Zero Environment Modification:** No packages were installed, upgraded, or removed from the active Python 3.14 virtual environment. The reference code was imported directly via in-memory dynamic module loading ([`importlib.util.spec_from_file_location`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/test_upstream_reference_parity.py#L51)).
3. **100.00% Empirical Parity:** Tested across all 5 authorized PE fixtures (x64 GUI, x86 CUI, DLL, Driver SYS, and host `python.exe`). Across all 2,381 features, **2,381 / 2,381 features achieved parity within machine precision (max diff <= 4.77e-7, 0 mismatches exceeding 1e-5)**.
4. **Exact Feature Agreement:** 2,380 out of 2,381 features (99.96%) matched **identically** (`diff = 0.00000000`). The only non-zero variance occurred at index 611 (`entropy` in `StringExtractor`), where float32 log summation resulted in a negligible rounding delta of `2.38e-7` to `4.77e-7`.
5. **Safety Preserved:** The Parity Gate in [`MLAnalyzer`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ml_analyzer.py) remains safely closed (`is_reliable=False`), production pipeline heuristics are unperturbed, and no model retraining or threshold adjustment was performed.

---

## 2. Upstream Repository Acquisition and Integrity

### 2.1 Clone Coordinates
- **Remote URL:** `https://github.com/elastic/ember.git`
- **Destination Path:** `C:\Users\MILKWAY\ethio-ai-defender\vendor\elastic_ember_upstream`
- **Commit SHA Checked Out:** `d97a0b523de02f3fe5ea6089d080abacab6ee931`
- **Commit Verification Command:** `git rev-parse HEAD` -> `d97a0b523de02f3fe5ea6089d080abacab6ee931`
- **Commit Metadata:**
  - Author: Phil Roth (`mr.phil.roth@gmail.com`, Endgame / Elastic)
  - Date: Tue Aug 23 15:02:38 2022 -0400
  - Subject: `Pin LIEF Version (#90)`
- **Git Ignore Protection:** Added `vendor/` to [`.gitignore`](file:///C:/Users/MILKWAY/ethio-ai-defender/.gitignore#L59) to prevent committing external upstream source trees to the project history.

---

## 3. Environment Isolation and In-Memory Compatibility Protocol

### 3.1 Strict Isolation Boundaries
- **Virtual Environment (`venv`):** Completely untouched. `pip list` remains unchanged.
- **On-Disk Source Code:** All files in `vendor/elastic_ember_upstream/` remain strictly pristine (read-only execution, zero edits on disk).
- **Execution Mechanism:** Upstream `ember/features.py` was loaded directly using `importlib.util.spec_from_file_location("upstream_ember_features", ...)` to bypass `ember/__init__.py` (which requires unavailable training dependencies `tqdm`, `pandas`, and `lightgbm`).

### 3.2 In-Memory Runtime Compatibility Protocol
Historical EMBER 2018 code was authored for Python 3.6, NumPy 1.16, scikit-learn 0.20, and LIEF 0.9.0. To execute it safely under modern Python 3.14.4 without changing packages on disk, three non-destructive in-memory runtime shims were injected strictly in the test process:
1. **NumPy 2.x Deprecated Aliases:** Modern NumPy 2.x removed `np.int` and `np.float`. Injected `np.int = int` and `np.float = float` in-memory.
2. **Modern LIEF Error Attribute Fallbacks:** LIEF 1.0.0 moved error enums into `lief.lief_errors`. Injected fallback mappings for `lief.bad_format`, `lief.bad_file`, `lief.pe_error`, `lief.parser_error`, and `lief.read_out_of_bound`.
3. **Scikit-Learn 1.x `FeatureHasher` Validation:** Modern scikit-learn enforces that inputs to `FeatureHasher.transform()` must be iterables over iterables of strings (`[[entry_name]]`). Injected a wrapper on `FeatureHasher.transform` to accommodate 1D string lists passed by upstream 2018 code.

---

## 4. Empirical Paired Comparison Results

Both the upstream official extractor (`vendor/elastic_ember_upstream/ember/features.py`) and the project's local extractor ([`app/ml/ember_v2.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_v2.py)) were executed on identical in-memory byte buffers for all 5 test fixtures.

### 4.1 Fixture Results Summary

| Fixture ID | Architecture / Description | File Size | SHA-256 Digest | Total Features | Exact Matches (diff == 0.0) | Near Matches (diff <= 1e-5) | Mismatches (> 1e-5) | Max Abs Diff | Mean Abs Diff |
| :--- | :--- | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **PE-FIX-01** | PE32+ / x64 GUI Executable | 4,096 B | `8d46fb4f9bff62c59cacc254ded4551625008b2b05a63276fd9c23676e95b0d0` | 2,381 | 2,380 (99.96%) | **2,381 (100%)** | **0** | `2.38e-7` | `1.00e-10` |
| **PE-FIX-02** | PE32 / x86 Console Executable | 4,096 B | `106f49c0591f135b188f0900159ec2fa10308d4d11e0d1c9d3369836aa50fcb3` | 2,381 | 2,380 (99.96%) | **2,381 (100%)** | **0** | `2.38e-7` | `1.00e-10` |
| **PE-FIX-03** | PE32+ / x64 DLL | 4,096 B | `39eef710eaca5f11c6e6ef111ae92fe3859ddfbfda195bf78f6049a324b48d72` | 2,381 | 2,380 (99.96%) | **2,381 (100%)** | **0** | `2.38e-7` | `1.00e-10` |
| **PE-FIX-04** | PE32+ / x64 SYS Driver | 4,096 B | `4aae62c2b2d09e26da142122124307b9c37121aaa251069cf4061392938d0339` | 2,381 | 2,380 (99.96%) | **2,381 (100%)** | **0** | `2.38e-7` | `1.00e-10` |
| **PE-FIX-05** | PE32+ / x64 Host `python.exe` | 255,320 B | `4b8c3912806b3c1591ba3cb403bff77ad309c3fe5756f87c20b7a6f8f0174262` | 2,381 | 2,380 (99.96%) | **2,381 (100%)** | **0** | `4.77e-7` | `2.00e-10` |

### 4.2 Per-Feature-Family Results Breakdown
Across all 5 fixtures, 8 out of 9 feature families matched with **100% bitwise exactness (`0.00000000` difference)**:

1. `ByteHistogram` [0 : 256]: **256 / 256 exact (100%)** — max diff: `0.00000000`
2. `ByteEntropyHistogram` [256 : 512]: **256 / 256 exact (100%)** — max diff: `0.00000000`
3. `StringExtractor` [512 : 616]: **103 / 104 exact (99.04%)**, 104 / 104 within `4.77e-7` (100%)
   - *Index 611 (`entropy`)*: Upstream = `2.6635327`, Local = `2.6635330`, Delta = `2.38e-7` (single-precision floating point summation rounding delta).
4. `GeneralFileInfo` [616 : 626]: **10 / 10 exact (100%)** — max diff: `0.00000000`
5. `HeaderFileInfo` [626 : 688]: **62 / 62 exact (100%)** — max diff: `0.00000000`
6. `SectionInfo` [688 : 943]: **255 / 255 exact (100%)** — max diff: `0.00000000`
7. `ImportsInfo` [943 : 2223]: **1,280 / 1,280 exact (100%)** — max diff: `0.00000000`
8. `ExportsInfo` [2223 : 2351]: **128 / 128 exact (100%)** — max diff: `0.00000000`
9. `DataDirectories` [2351 : 2381]: **30 / 30 exact (100%)** — max diff: `0.00000000`

---

## 5. Test Suite Verification and Reproducibility

The validation protocol has been codified into a permanent automated test suite: [`tests/ml/test_upstream_reference_parity.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/test_upstream_reference_parity.py).

### Reproduction Commands:
```powershell
# Targeted Upstream Parity Test
$env:PYTHONPATH="."; pytest tests/ml/test_upstream_reference_parity.py -v
# Output: 5 passed in 4.74s (Exit code 0)

# Full ML Subsystem Test Suite
$env:PYTHONPATH="."; pytest tests/ml/ -q
# Output: 160 passed in 30.17s (Exit code 0)
```

---

## 6. Safety and Governance Guarantees

1. **Parity Gate Maintained:** Even with empirical validation established against the official upstream repository on authorized test binaries, the Parity Gate in [`MLAnalyzer`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ml_analyzer.py) remains active:
   - Raw PE binaries evaluated through [`analyze_pe_bytes`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ml_analyzer.py#L201) return `is_reliable=False` and `status="OFFLINE_TEST_UNVERIFIED_PARITY"`.
   - Predictions are recorded strictly for telemetry and shadow evaluation.
2. **Production Pipeline Untouched:** ML results do not alter heuristic threat scores, risk categories, or verdict assignment in [`ThreatScoringEngine`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/threat_scoring.py).
3. **Model & Calibration Untouched:** No retraining, re-calibration, or threshold tuning was performed.

---

## 7. Conclusion

Milestone **ML-08A** successfully achieved genuine independent reference validation. The project's local extractor ([`app/ml/ember_v2.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_v2.py)) exhibits **100.00% empirical mathematical parity** with the official Elastic EMBER reference implementation ([`d97a0b523de02f3fe5ea6089d080abacab6ee931`](https://github.com/elastic/ember/commit/d97a0b523de02f3fe5ea6089d080abacab6ee931)) on all tested PE binary architectures.
