# ML-08 Implementation Plan: Independent Reference Validation

**Milestone:** ML-08  
**Repository:** `C:\Users\MILKWAY\ethio-ai-defender`  
**Date:** October 28, 2026  
**Status:** Planned / Blocker Identification  

---

## 1. Executive Summary and Scope

The objective of Milestone ML-08 is to strengthen empirical evidence for raw-PE feature compatibility by validating the project's feature extractor ([`app/ml/ember_v2.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/ember_v2.py)) against a genuinely independent, version-compatible EMBER v2 reference implementation.

In ML-07, feature extraction parity was verified against [`tests/ml/reference_ember.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/reference_ember.py). However, as confirmed in the ML-07A evidence audit ([`ML07A_Evidence_Audit_Report.md`](file:///C:/Users/MILKWAY/ethio-ai-defender/ML07A_Evidence_Audit_Report.md)), `tests/ml/reference_ember.py` is an in-tree Python transcription of the `elastic/ember` repository rather than an independently installed, third-party oracle package. ML-08 aims to establish true independent reference validation while strictly respecting repository integrity boundaries and dependency management constraints.

---

## 2. Current Repository State and Integrity Preservation

### 2.1 Git Coordinates
- **Branch:** `my-feature-branch`
- **HEAD Commit:** `0e8412b0ee3756c9600bf9a8ed45fbf8478914a6` (`Add ML and YARA updates`)
- **Tracking:** Up to date with `origin/my-feature-branch`

### 2.2 Working Tree Modifications
```text
Changes not staged for commit:
  modified:   app/core/config.py
  modified:   app/pipeline/orchestrator.py
  modified:   tests/ml/test_pipeline_noninterference.py

Untracked files:
  ML07A_Evidence_Audit_Report.md
  ML07_Feature_Parity_Validation_Report.md
  tests/ml/test_shadow_mode_integration.py
```
All existing tracked and untracked modifications are strictly preserved. No reset, clean, restore, or commit operations will be performed.

---

## 3. Local Search and Candidate Reference Discovery

### 3.1 Search Methodology
A thorough, non-destructive audit was performed across the local environment to determine if an official or independently maintained EMBER v2 reference is available:
1. **Virtual Environment (`venv`):** Inspected `pip list` and `sys.modules` for the `ember` package.
2. **Local Repository & Subdirectories:** Scanned `C:\Users\MILKWAY\ethio-ai-defender` for external clones, git submodules, or vendor directories.
3. **Storage Archives:** Inspected `storage/ember_dataset_2018_2.tar.bz2` (1.69 GB) via `tarfile` table-of-contents extraction.
4. **User Workspace:** Inspected `C:\Users\MILKWAY\` for sibling repository clones.
5. **Local Package Caches:** Inspected `C:\Users\MILKWAY\AppData\Local\pip\cache` for pre-cached `.whl` or `.tar.gz` wheels.

### 3.2 Discovery Findings
- `pip list` confirms `ember` is **not installed** in the virtual environment.
- `storage/ember_dataset_2018_2.tar.bz2` contains exclusively dataset JSONL files (`train_features_*.jsonl`, `test_features.jsonl`) and the model definition (`ember_model_2018.txt`); it contains no Python implementation or reference scripts.
- No external `elastic/ember` repository clone exists in `C:\Users\MILKWAY\`.
- No pip wheels for `ember` are present in the local pip cache.
- The only reference code present on disk is `tests/ml/reference_ember.py`, which is the in-tree algorithmic transcription authored during ML-07.

---

## 4. Independence Evaluation and Phase 2 Stopping Gate

### 4.1 Independence Mandate
Per Phase 2 requirements:
- A candidate reference must be **genuinely independent** of `reference_ember.py`.
- Creating a second copy or variation of `reference_ember.py` is explicitly prohibited: *"Do not treat a second copy of the same transcription as independent verification."*
- Installing external packages without authorization is strictly prohibited: *"Do not install, upgrade, or remove dependencies without explicit approval."*

### 4.2 Mandatory Blocker Trigger
Because:
1. An official or third-party independent EMBER v2 package/repository is not present on the local filesystem, AND
2. External package installation (`pip install ember` or `pip install git+https://github.com/elastic/ember.git`) cannot proceed without explicit user approval,
Phase 2 mandates stopping implementation immediately:
> *"If a suitable reference is unavailable, stop and report `BLOCKED: INDEPENDENT REFERENCE UNAVAILABLE`."*

---

## 5. Regression and Pipeline Integrity Protocol

To guarantee that the codebase remains completely stable and regression-free during this blocked audit:
1. **Model Checksum Verification:** Recalculate SHA-256 for `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib` and verify match with `model.joblib.sha256` and `TRUSTED_BASELINE_MODEL_SHA256` (`f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684`).
2. **Targeted Parity Re-Execution:** Execute `tests/ml/test_feature_parity.py`, `tests/ml/test_inference_parity.py`, and `tests/ml/test_pipeline_noninterference.py`.
3. **Shadow-Mode Isolation Re-Execution:** Execute `tests/ml/test_shadow_mode_integration.py` to confirm ML telemetry executes safely without altering threat scores, YARA results, or deterministic analysis verdicts.
4. **Safety Verification:** Confirm that ML predictions remain strictly isolated from production blocking, quarantine, and automatic remediation.

---

## 6. Deliverable and Exit Criteria

Deliverable: [`ML08_Independent_Reference_Validation_Report.md`](file:///C:/Users/MILKWAY/ethio-ai-defender/ML08_Independent_Reference_Validation_Report.md)
Final Status Outcome: **`BLOCKED: INDEPENDENT REFERENCE UNAVAILABLE`**

The report will detail:
- Comprehensive audit trail of local package and filesystem searches.
- Technical rationale why in-tree transcriptions cannot satisfy independent reference criteria.
- Execution log of regression and integrity test suites.
- Clear, actionable unblocking procedures requiring user decision/approval for package installation.
