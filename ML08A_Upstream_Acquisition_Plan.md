# ML-08A: Upstream Reference Acquisition Plan

**Milestone:** ML-08A  
**Date:** October 28, 2026  
**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`  
**Author / Agent:** Antigravity Autonomous Security Engineer  
**Status:** **`READY FOR USER APPROVAL`**

---

## 1. Executive Summary

Milestone ML-08A defines a controlled, reproducible, and non-destructive plan to acquire and execute the official Elastic EMBER reference implementation. This plan enables genuine, independent empirical feature parity validation for raw PE binaries without altering or risking corruption of the existing Python runtime environment, production analyzers, model artifacts, or staged datasets.

---

## 2. Upstream Reference Specification and Provenance

### 2.1 Authoritative Repository Details
- **Repository Name:** `elastic/ember` (Elastic Malware Benchmark for Empowering Researchers)
- **Repository URL:** `https://github.com/elastic/ember`
- **Owner / Organization:** Elastic (`elastic`)
- **Repository Status:** Archived (Read-Only)
- **License:** GNU Affero General Public License v3.0 (AGPL-3.0) ([`LICENSE.txt`](https://github.com/elastic/ember/blob/master/LICENSE.txt))

### 2.2 Pinned Revision and Immutable Coordinates
- **Immutable Commit SHA:** **`d97a0b5e98547cb09f6ff5d564efc58e722514e8`**
- **Short Hash:** `d97a0b5`
- **Commit Subject:** `Pin LIEF Version (#90)`
- **Commit Author:** Phil Roth (`mrphilroth`, Endgame / Elastic)
- **Significance:** This represents the final, canonical commit on the `master` branch of the official repository, establishing the exact reference code associated with the EMBER 2018 dataset and LightGBM benchmark.

### 2.3 Feature Contract and Feature Version 2 Support
- **Core File:** `ember/features.py`
- **Class:** `PEFeatureExtractor(feature_version=2)`
- **Total Feature Dimensions:** Exactly 2,381 float32 features across 9 distinct feature groups:
  1. `ByteHistogram`: 256 dimensions
  2. `ByteEntropyHistogram`: 256 dimensions
  3. `StringExtractor`: 104 dimensions
  4. `GeneralFileInfo`: 10 dimensions
  5. `HeaderFileInfo`: 62 dimensions
  6. `SectionInfo`: 255 dimensions
  7. `ImportsInfo`: 1,280 dimensions
  8. `ExportsInfo`: 128 dimensions
  9. `DataDirectories`: 30 dimensions
- **Contract Parity:** `feature_version=2` in upstream `ember/features.py` is the identical schema and ordering targeted by [`app/ml/ember_v2.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_v2.py).

### 2.4 Provenance Comparison: Upstream vs `reference_ember.py`
| Dimension | Upstream `elastic/ember` (`d97a0b5`) | In-Tree `tests/ml/reference_ember.py` |
| :--- | :--- | :--- |
| **Origin** | Authored by Endgame / Elastic team (original benchmark creators) | Authored in-tree as an empirical unit test transcription |
| **Independence** | **100% Genuine External Authority** | Transcribed code inside current repository |
| **LIEF API Adaptation** | Authored for historical `lief==0.9.0` | Contains fallbacks for modern LIEF (`has_signatures`, `section_from_rva`) |
| **Export Hasher Syntax** | Passes raw string lists to `FeatureHasher` (scikit-learn 0.20 style) | Wraps inputs into `[[entry_name]]` (scikit-learn 1.x style) |
| **Audit Credibility** | Authoritative ground truth | Algorithmic parity proxy only |

---

## 3. Dependency and Compatibility Analysis

### 3.1 Upstream Requirements vs Current Environment
The upstream repository `requirements.txt` specifies:
```text
lief==0.9.0
scikit-learn>=0.20.3
numpy>=1.16.3
pandas>=0.24.2
lightgbm>=2.2.3
tqdm>=4.31.0
```

The current active `ethio-ai-defender` environment (`venv`) runs:
- **Python:** 3.14.4
- **lief:** 1.0.0
- **scikit-learn:** 1.9.1
- **numpy:** 2.5.4

### 3.2 Critical Incompatibility and Conflict Risks
1. **LIEF 0.9.0 Binary Incompatibility:** `lief==0.9.0` was compiled and published on PyPI for Python 2.7, 3.5, 3.6, 3.7, and 3.8. There are **no prebuilt wheels for Python 3.14**. Attempting `pip install lief==0.9.0` in the current Python 3.14 virtual environment will fail to build C++ extensions or break with Python 3.14 internal C-API deprecations.
2. **Scikit-learn 1.x API Stricter Validation:** Modern scikit-learn rejects single strings passed to `FeatureHasher.transform([s])` expecting 2D iterables of strings (`[[s]]`).
3. **Environment Pollution Risk:** Running `pip install` or `setup.py install` directly in the active environment could downgrade or corrupt active packages (`numpy`, `scikit-learn`, `lief`), breaking existing static analyzers (`PEStaticAnalyzer`, `YARAAnalyzer`, etc.).

---

## 4. Proposed Isolated Acquisition and Execution Strategy

To completely isolate the reference execution without risking the project's active runtime, **isolated acquisition without package installation** is proposed.

### 4.1 Preferred Acquisition Method: Isolated Source Tree Mount
Clone the upstream source repository at the pinned revision into an isolated external directory **outside** the project workspace (or in a dedicated ignored vendor location), without running `pip install` or registering it into site-packages.

- **Proposed Target Path:** `C:\Users\MILKWAY\ethio-ai-defender\vendor\elastic_ember_upstream`  
  *(Added to `.gitignore` so no external upstream code is committed).*
- **Pinned Git URL:** `https://github.com/elastic/ember.git`
- **Pinned Git Commit:** `d97a0b5e98547cb09f6ff5d564efc58e722514e8`

### 4.2 Exact Commands Requiring User Approval

The following exact sequence is prepared and awaiting explicit user authorization:

```powershell
# Step 1: Clone upstream repository into an isolated vendor directory (network access required)
git clone https://github.com/elastic/ember.git C:\Users\MILKWAY\ethio-ai-defender\vendor\elastic_ember_upstream

# Step 2: Checkout the immutable pinned commit
cd C:\Users\MILKWAY\ethio-ai-defender\vendor\elastic_ember_upstream
git checkout d97a0b5e98547cb09f6ff5d564efc58e722514e8

# Step 3: Verify commit hash and immutable file integrity
git rev-parse HEAD
# Expected output: d97a0b5e98547cb09f6ff5d564efc58e722514e8

# Step 4: Verify expected file presence
Test-Path C:\Users\MILKWAY\ethio-ai-defender\vendor\elastic_ember_upstream\ember\features.py
# Expected output: True
```

### 4.3 Isolated Execution Protocol
1. **Subprocess Isolation:** An independent runner script ([`scripts/run_upstream_parity.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/run_upstream_parity.py)) will execute in a standalone child process.
2. **Selective Import:** The child process dynamically prepends `C:\Users\MILKWAY\ethio-ai-defender\vendor\elastic_ember_upstream` to `sys.path`.
3. **PE Fixture Delivery:** Both extractors receive identical byte arrays for the 5 authorized test fixtures:
   - Synthetic x64 GUI PE
   - Synthetic x86 CUI PE
   - Synthetic DLL
   - Synthetic SYS Driver
   - Host `python.exe` binary
4. **Data Exchange:** Feature vectors are exported to temporary float32 buffers and mathematically compared:
   - Exact-match feature counts
   - Per-family mismatch counts
   - Maximum absolute difference
   - Mean absolute difference
5. **Zero Side Effects:** No files in `storage/`, `D:\ethio_ai_defender_artifacts\`, or `app/` are touched or modified.

---

## 5. Resource and Boundary Impact Analysis

- **Disk Space Requirement:** ~15 MB for the shallow git clone in `vendor/elastic_ember_upstream`.
- **Memory Footprint:** Less than 100 MB during feature extraction subprocess execution.
- **Network Access Requirement:** Single read-only clone from `https://github.com/elastic/ember.git`.
- **Primary Virtual Environment (`venv`):** **Zero changes.** No packages installed, upgraded, or removed.
- **Model Artifacts & Staged Arrays:** **Protected.** Read-only access; no overwrites or deletions.
- **Safety Gates:** **Maintained.** Raw PE inputs to [`MLAnalyzer`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ml_analyzer.py) remain strictly flagged with `is_reliable=False` and `status="OFFLINE_TEST_UNVERIFIED_PARITY"`.

---

## 6. Actionable Approval Request

To proceed with acquiring the official upstream reference at commit `d97a0b5e98547cb09f6ff5d564efc58e722514e8` and executing the isolated paired comparison, the user must provide explicit approval to run the network clone command:

```powershell
git clone https://github.com/elastic/ember.git C:\Users\MILKWAY\ethio-ai-defender\vendor\elastic_ember_upstream
```

Upon receipt of approval, the agent will execute the pinned checkout, verify the commit hash, execute the paired comparison across the 5 fixtures, and produce `ML08B_Independent_Reference_Validation_Report.md`.
