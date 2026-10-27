# ETHIO-AI Defender: ML-07 Feature Parity and Controlled Integration Validation Report

**Milestone:** ML-07  
**Date:** October 28, 2026  
**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`  
**Status:** **`PARTIAL: FEATURE PARITY NOT FULLY ESTABLISHED`**  
*(Authorized for Controlled Offline Testing with Parity Gate Enforced)*

---

## 1. Executive Summary and Verdict

Milestone ML-07 established empirical feature compatibility, verified inference parity between the direct estimator and the decoupled adapter, and confirmed pipeline non-interference and fault isolation for the EMBER 2018 v2 machine learning integration.

### Verdict: `PARTIAL: FEATURE PARITY NOT FULLY ESTABLISHED`

- **Feature Parity on Authorized Binaries:** **100.00% Exact Numerical Parity** (2,381 / 2,381 features, maximum absolute difference = 0.0) was achieved across all 5 authorized PE test fixtures (x64 GUI executable, x86 CUI executable, Dynamic Link Library, Kernel Driver, and the authorized Python runtime binary `sys.executable`) when compared against the upstream EMBER v2 algorithmic reference.
- **Inference Parity:** **100.00% Numerical Parity** (maximum probability difference = 0.0) between the raw LightGBM estimator and [`EmberModelClassifier`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/classifier.py) across 100 staged validation vectors (`X_val.mmap`).
- **Pipeline Non-Interference:** Verified with zero side effects on existing deterministic static analyzers, threat scores, or verdict policies.
- **Reason for `PARTIAL` Status:** The original raw PE binaries from the historical EMBER 2018 benchmark are not distributed in the repository or dataset storage (`storage/ember2018/` contains only pre-extracted `.jsonl` files and the model file). Without the raw 2018 benchmark malware binaries, an end-to-end paired comparison between raw 2018 PE binaries and historical JSONL training vectors cannot be performed. Consequently, per the project safety mandate, **feature parity cannot be declared universally proven for raw PE malware**, and the **Parity Gate in [`MLAnalyzer`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ml_analyzer.py) remains safely closed** (`is_raw_pe_parity_verified = False`).

---

## 2. Reference Implementation and Dependency Versions

### 2.1 Upstream Reference Specification
- **Algorithm Specification:** EMBER 2018 v2 Feature Extractor (`elastic/ember/features.py`), Feature Version 2, encompassing all 9 feature groups (2,381 dimensions).
- **Reference Implementation:** [`tests/ml/reference_ember.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/reference_ember.py) was constructed as an exact, faithful transcription of `elastic/ember/features.py` into an in-process standalone reference module. This avoids unauthorized external package installations (`pip install ember` is prohibited) while guaranteeing algorithmic fidelity.

### 2.2 Local Runtime Dependencies
- **Python:** 3.14.4 (Windows x64)
- **numpy:** 2.3.5
- **scikit-learn:** 1.8.0
- **joblib:** 1.5.3
- **lief:** 0.17.2
- **pefile:** 2024.8.26
- **pytest:** 9.1.1

---

## 3. Test Fixtures and Exact File-Byte Identity Verification

To ensure valid paired empirical comparisons, both feature extractors ([`app/ml/ember_v2.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_v2.py) and [`tests/ml/reference_ember.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/reference_ember.py)) received the exact same in-memory byte arrays (`bytez`).

| Fixture ID | Fixture Description | Size (Bytes) | SHA-256 Digest Verification | Choice Justification |
| :--- | :--- | :--- | :--- | :--- |
| **PE-FIX-01** | Synthetic x64 GUI PE | 4,096 | Computed in-memory | Validates 64-bit headers, section headers, RVA alignment, and GUI subsystem |
| **PE-FIX-02** | Synthetic x86 CUI PE | 4,096 | Computed in-memory | Validates 32-bit headers, console subsystem, and section flags |
| **PE-FIX-03** | Synthetic DLL | 4,096 | Computed in-memory | Validates `IMAGE_FILE_DLL` characteristics, export directory parsing, and export hashing |
| **PE-FIX-04** | Synthetic Kernel SYS Driver | 4,096 | Computed in-memory | Validates native subsystem (`IMAGE_SUBSYSTEM_NATIVE`), system sections, and entrypoints |
| **PE-FIX-05** | Authorized Host Python (`sys.executable`) | 266,744 | Bitwise identical in memory | Real-world, production x64 PE with rich headers, complex import tables, digital certificates, strings, and entropy distribution |

---

## 4. Empirical Feature Parity Results

Each authorized fixture was processed by both extractors. Dimensions, data types, ordering, and feature values were compared across all 2,381 features.

### 4.1 Feature Group Breakdown and Exact Matches

| Feature Group | Dimension Slice | Dimension Count | Exact Matches | Max Absolute Difference | Discrepancies |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `ByteHistogram` | [0 : 256] | 256 | 256 / 256 (100.0%) | 0.00000000 | None |
| `ByteEntropyHistogram` | [256 : 512] | 256 | 256 / 256 (100.0%) | 0.00000000 | None |
| `StringExtractor` | [512 : 616] | 104 | 104 / 104 (100.0%) | 0.00000000 | None |
| `GeneralFileInfo` | [616 : 626] | 10 | 10 / 10 (100.0%) | 0.00000000 | None |
| `HeaderFileInfo` | [626 : 688] | 62 | 62 / 62 (100.0%) | 0.00000000 | None |
| `SectionInfo` | [688 : 943] | 255 | 255 / 255 (100.0%) | 0.00000000 | None |
| `ImportsInfo` | [943 : 2223] | 1,280 | 1,280 / 1,280 (100.0%) | 0.00000000 | None |
| `ExportsInfo` | [2223 : 2351] | 128 | 128 / 128 (100.0%) | 0.00000000 | None |
| `DataDirectories` | [2351 : 2381] | 30 | 30 / 30 (100.0%) | 0.00000000 | None |
| **TOTAL** | **[0 : 2381]** | **2,381** | **2,381 / 2,381 (100.0%)** | **0.00000000** | **0 mismatches** |

### 4.2 Fix Applied During Phase 1 Starting Gate
- **Root Cause Identified:** In [`app/ml/ember_v2.py:404`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_v2.py#L404), `FeatureHasher.transform([entry_name])` was invoked with a 1D list of strings, which scikit-learn rejects with `ValueError: Samples can not be a single string. The likely cause is that an array of strings was passed...`.
- **Resolution:** Modified line 404 to pass `[[entry_name]]`, matching the reference implementation in `elastic/ember/features.py`. Feature parity across all exports was subsequently confirmed.

---

## 5. Inference Parity Results

Using [`tests/ml/test_inference_parity.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/test_inference_parity.py), predictions from the direct baseline estimator (`joblib.load`) were compared against [`EmberModelClassifier`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/classifier.py) on 100 real feature vectors staged in `D:\ethio_ai_defender_artifacts\staged\X_val.mmap`.

### 5.1 Estimator Parity and Class Probability Mapping
- **Model File:** `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib`
- **SHA-256 Digest:** `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684` (Bitwise match with trusted sidecar).
- **Direct Estimator vs Adapter Difference:** Maximum absolute difference across all 100 test samples was **`0.00000000e+00`**.
- **Class Label Resolution:** Tested with both standard `classes_ = [0, 1]` and inverted `classes_ = [1, 0]`. In both cases, the adapter correctly mapped index `np.where(classes_ == 1)[0][0]` to the malicious probability score.
- **Score Bounds & Determinism:** All returned probability scores were strictly finite and bounded within `[0.0, 1.0]`. Identical inputs produced deterministic, bitwise-identical float predictions.

### 5.2 Failure and Edge-Case Handling

| Edge Case / Fault Injected | Expected Behavior | Actual Behavior | Result |
| :--- | :--- | :--- | :---: |
| Dimension Mismatch (e.g., 2,380 dims) | Rejection with controlled `ValueError` | `ValueError` raised: dimension mismatch | **PASS** |
| `NaN` / `+Inf` / `-Inf` in features | Rejection with controlled `ValueError` | `ValueError` raised: non-finite values | **PASS** |
| Oversized Batch Size (> 1,000 samples) | Rejection with controlled `ValueError` | `ValueError` raised: batch exceeds limit | **PASS** |
| Checksum Mismatch (Tampered Model) | Rejection before deserialization | `SecurityError` raised before `joblib.load` | **PASS** |
| Missing Model File / Path | Explicit error, no silent fallback | `FileNotFoundError` raised; no benign prediction | **PASS** |

---

## 6. Pipeline Non-Interference and Safety Verification

Using [`tests/ml/test_pipeline_noninterference.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/test_pipeline_noninterference.py), the decoupled ML subsystem was validated within the broader multi-analyzer ecosystem.

### 6.1 Preservation of Deterministic Analyzers
- Analyzers evaluated:
  - `HashAnalyzer` (`md5`, `sha1`, `sha256`, `ssdeep`, `authentihash`, `imphash`)
  - `PEStaticAnalyzer` (PE header analysis)
  - `PESectionAnalyzer` (section structures)
  - `EntropyAnalyzer` (byte & chunk entropy)
  - `StringAnalyzer` (printable ASCII/Unicode strings)
  - `SuspiciousIndicatorEngine` (Module 08 rules)
  - `ThreatScoringEngine` (Module 09 composite score)
- **Result:** Exact identity before and after executing [`MLAnalyzer.analyze_pe_bytes`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ml_analyzer.py). Threat score and risk level remained completely identical.

### 6.2 Parity Gate Enforcement
- When raw PE bytes are processed by [`MLAnalyzer`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ml_analyzer.py):
  - Returned status is explicitly `"PARITY_UNVERIFIED_FOR_RAW_PE"`.
  - Field `available` is set to `False`.
  - Field `is_malicious` is `None` (no benign or malicious verdict claimed).
  - The deterministic threat scoring engine receives zero ML indicators.

### 6.3 Fault Isolation and Graceful Degradation
- Missing classifier instance -> returns `available=False`, `status="UNAVAILABLE"`.
- Classifier prediction exception -> returns `available=False`, `status="FAILED"`.
- At no point does an internal ML failure cause a pipeline crash or default to a false-negative benign verdict.

### 6.4 Non-Execution Guarantee
- The ML extractor parses file bytes purely as a static buffer (`io.BytesIO` / `lief.PE.parse`).
- No subprocesses, debugging hooks, dynamic loaders, or native execution calls are made.

---

## 7. Commands Executed and Test Summary

| Test Suite | Command | Total Tests | Passed | Failed | Exit Code | Duration |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **ML Subsystem** | `pytest tests/ml/ -v` | 150 | 150 | 0 | 0 | 34.61s |
| **Core Static Analyzers** | `pytest tests/test_pe_analyzer.py tests/test_hash_analyzer.py tests/test_section_analyzer.py tests/test_entropy_analyzer.py tests/test_string_analyzer.py tests/test_import_analyzer.py tests/test_threat_scoring.py tests/test_file_intake.py -q` | 82 | 82 | 0 | 0 | 8.48s |
| **Security & Auditing** | `pytest tests/test_auth_security.py tests/test_module_18_security_attacks.py tests/test_audit_logger.py -q` | 24 | 24 | 0 | 0 | 17.58s |
| **TOTAL** | — | **256** | **256** | **0** | **0** | — |

---

## 8. Unresolved Compatibility and Security Risks

1. **Absence of Ground-Truth 2018 Raw PE Binaries:**
   - The repository's `storage/ember2018/` contains only pre-extracted JSONL files. While mathematical feature extraction on test PEs is 100% identical to the reference algorithm, historical 2018 raw malware binaries are unavailable for direct paired extraction.
   - **Mitigation:** The Parity Gate must remain closed (`is_raw_pe_parity_verified = False`) in production until a vetted raw PE test corpus is incorporated.
2. **High False Positive Rate of Baseline Model:**
   - As documented in ML-05, the baseline model exhibits an 8.63% False Positive Rate at threshold 0.50.
   - **Mitigation:** The ML model must never be used as a primary or blocking verdict authority. Its role is strictly informational and restricted to controlled offline testing.
3. **Dependency Drift:**
   - `lief` 0.17.2 and `scikit-learn` 1.8.0 differ from the original 2018 benchmark versions (`lief` 0.9.0, `scikit-learn` 0.22).
   - **Mitigation:** Strict metadata assertions in [`EmberModelClassifier`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/classifier.py) validate package version compatibility and feature count contracts at load time.

---

## 9. Conclusion and Next Steps

Milestone ML-07 is successfully completed with the verdict **`PARTIAL: FEATURE PARITY NOT FULLY ESTABLISHED`**. All empirical tests confirm 100% parity against the EMBER v2 algorithmic reference on authorized binaries, perfect inference parity on staged vectors, complete fault tolerance, and zero interference with the existing static analysis pipeline. The system is certified safe for controlled offline validation.
