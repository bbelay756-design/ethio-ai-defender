# ETHIO-AI DEFENDER — ML-12B INDEPENDENT VERIFICATION AND CLOSURE AUDIT

**Audit Type:** Independent Verification (read-only)
**Audit Date:** 2026-10-28
**Branch:** `my-feature-branch`
**Git HEAD:** `fa001120ce6b8b49bedb8ec6055e555731cff12b` (`feat(frontend): display advisory-only disclaimer and closed parity gate status in SOC card`)
**Audit Scope:** ML-12B — Advisory Dashboard Integration for ML Scores (backend contract, orchestrator shadow output, frontend rendering, model/gate integrity, security posture, regression evidence)

---

## 1. Executive Summary

The ML-12B advisory dashboard integration was independently re-verified against the
repository working tree at commit `fa00112` on branch `my-feature-branch`.

**Direct observations supporting closure:**

1. The focused advisory contract test suite passes: **9/9 tests passed** (`tests/ml/test_advisory_dashboard_integration.py`), exit code `0`, duration 41.20s.
2. The full `tests/security` suite passes: **100 passed, 22 subtests passed**, exit code `0`, duration 54.46s.
3. The analysis functional / dashboard UI suites pass: **25 passed**, exit code `0`, duration 40.39s.
4. The frozen model artifact digest verification **EXACTLY MATCHES** the trusted reference:
   - Authoritative artifact `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib`
     → SHA-256 `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684`
     → **EXACT MATCH** with `TRUSTED_BASELINE_MODEL_SHA256` in `app/ml/classifier.py` (line 29); size 1,609,815 bytes.
5. The ML raw-PE reliability gate is **closed** (`is_reliable = False`) on all raw-PE inference paths.

**Direct observations requiring limitation or follow-up:**

1. The **complete ML regression suite** (`tests/ml -q`) did not run to completion in the
   current environment: collection of `tests/ml/test_upstream_reference_parity.py` failed with
   `ModuleNotFoundError: No module named 'lief'` (LIEF is not installed in the current runtime).
2. With that module excluded, the suite produced **7 failures / 175 passes**; all 7 failures are in
   `tests/ml/test_feature_parity.py` (`close_matches != EMBER_V2_TOTAL_DIM` and three-way parity
   mismatches), exit code `1`.
3. The previously delivered milestone report (`docs/ML12B_Advisory_Dashboard_Integration_Report.md`)
   claimed a full ML regression suite result of "78 passed, 0 failed" and a security suite result of
   "11 passed, 0 failed". The independently re-run commands produced materially different counts
   (175 passed / 7 failed for the ML suite excluding the LIEF module; 100 passed for `tests/security`).
   The discrepancy is reported; no conclusion should be drawn from the older report's numbers without
   re-execution.

**Closure decision: PASS WITH LIMITATIONS.**

The ML-12B advisory integration itself is verified, safe, and closed. The broader ML regression
suite is not currently green, so the milestone cannot be recorded as an unconditional PASS. The
limitation is tracked to the pre-existing feature-parity remediation line (ML-07/ML-08) and the
missing local LIEF installation; it does not indicate a defect in the ML-12B advisory code paths
themselves.

---

## 2. Repository Baseline

| Attribute | Value |
|---|---|
| Branch | `my-feature-branch` |
| HEAD | `fa001120ce6b8b49bedb8ec6055e555731cff12b` |
| HEAD subject | `feat(frontend): display advisory-only disclaimer and closed parity gate status in SOC card` |
| Audit date | 2026-10-28 |
| Python runtime | 3.14.4 |
| Platform | Windows-11-10.0.26300 (win32) |

### 2.1 Working Tree (observed at audit start and end)

**Modified tracked files (preserved, not reverted):**

- `frontend/index.html`
- `frontend/static/js/app.js`

**Untracked files (preserved, not cleaned):**

- `RELEASE03_Corrective_Roadmap.md`
- `docs/ML12B_Advisory_Dashboard_Integration_Report.md`
- `scratch/update_app_js.py`
- `tests/ml/test_advisory_dashboard_integration.py`

**Uncommitted diff scope (working tree vs. HEAD):**

```
 frontend/index.html       | 10 +++-
 frontend/static/js/app.js | 105 ++++++++++++++++++++++++++++++++++++++--------
 2 files changed, 97 insertions(+), 18 deletions(-)
```

No commits were created during this verification session. No files were deleted, reset, cleaned, or
restored. No production code was modified during this audit.

---

## 3. Test Execution Evidence (Independent Re-Run)

All commands executed with the project's existing Python environment. No dependencies were installed,
upgraded, or downgraded during this audit.

### 3.1 Focused Advisory Dashboard Integration Tests

| Command | Result | Exit Code |
|---|---|---|
| `python -m pytest tests/ml/test_advisory_dashboard_integration.py -q` | **9 passed, 0 failed, 0 skipped** in 41.20s | 0 |
| `python -m pytest tests/ml/test_advisory_dashboard_integration.py -q -p no:cacheprovider` | **9 passed, 0 failed** (cache-provider workaround; identical count) | 0 |
| `python -m pytest tests/ml/test_advisory_dashboard_integration.py -q --timeout=60` | **ERROR** — unrecognized argument (`--timeout=60`; pytest-timeout plugin not installed) | 2 |

The three tests exercising advisory contract details that could not run under `--timeout=60` completed
successfully under the standard invocation.

### 3.2 Complete ML Regression Suite

| Command | Result | Exit Code |
|---|---|---|
| `python -m pytest tests/ml -q` | **COLLECTION ERROR** — `tests/ml/test_upstream_reference_parity.py` imports `lief`, which is **not installed**; suite did not execute | 2 (collection phase) |
| `python -m pytest tests/ml -q --ignore=tests/ml/test_upstream_reference_parity.py` | **7 failed, 175 passed**, 52,814 warnings, in 140.32s | 1 |

### 3.3 Focused Feature-Parity Failure Detail (within the ML suite)

`python -m pytest tests/ml/test_feature_parity.py -q`:

- **7 failed, 1 passed**, in 34.72s, exit code `1`.
- Failing tests:
  - `TestFeatureParity.test_real_benign_binary_parity`
  - `TestFeatureParity.test_synthetic_dll_parity`
  - `TestFeatureParity.test_synthetic_driver_parity`
  - `TestFeatureParity.test_synthetic_pe_x64_parity`
  - `TestFeatureParity.test_synthetic_pe_x86_parity`
  - `TestFeatureParity.test_three_way_parity_real_binary`
  - `TestFeatureParity.test_three_way_parity_synthetic_pe`
- Failure signature: `AssertionError: 2377 != 2381` on `report["close_matches"]`.
- Three-way parity failures: 4 mismatched elements (indices 627, 647, 667, 843) where local
  extractor output was `0.0` and reference output was `1.0`; max absolute difference `1.0`.

### 3.4 Security Suite

| Command | Result | Exit Code |
|---|---|---|
| `python -m pytest tests/security -q` | **100 passed, 22 subtests passed**, 3,293 warnings, in 54.46s | 0 |

### 3.5 Analysis Functional / Dashboard UI Tests

| Command | Result | Exit Code |
|---|---|---|
| `python -m pytest tests/test_dashboard_ui.py tests/test_ui_dashboard.py tests/test_analysis_overview_functional.py tests/test_end_to_end_analysis_workflow.py -q` | **25 passed, 0 failed**, in 40.39s | 0 |

### 3.6 Cross-Reference: Claims in Delivered Report vs. Independent Re-Run

| Claim (in `docs/ML12B_Advisory_Dashboard_Integration_Report.md`) | Independent Re-Run Finding |
|---|---|
| Full ML regression suite: "78 passed, 0 failed" | Not reproducible as stated. Re-run of `tests/ml -q --ignore=tests/ml/test_upstream_reference_parity.py` → 175 passed / **7 failed**. Full suite without ignore → collection error. |
| API security suite: "11 passed, 0 failed" | Not reproducible as stated. Full `tests/security` run → **100 passed**, 22 subtests. |

---

## 4. API Contract Findings

### 4.1 ML Advisory Payload (`ml_analysis`)

Observed/implemented contract fields (from `app/pipeline/orchestrator.py`, `app/analyzers/ml_analyzer.py`,
`app/api/analyses.py`, `app/api/dashboard.py`):

- `available`: boolean.
- `status`: `SUCCESS`, `DISABLED`, `UNAVAILABLE`, `FAILED`, or `TIMEOUT`.
- `malicious_score`: `Optional[float]`, `null` when unavailable/failed — never fabricated as `0.0`.
- `is_malicious`, `is_malicious_1pct_fpr`, `is_malicious_01pct_fpr`: optional booleans.
- `active_threshold`, `thresholds`: floats/dict.
- `model_name`, `model_version`, `model_sha256`, `feature_dim`.
- `feature_parity_status`: `VERIFIED_FEATURE_VECTOR`, `UNVERIFIED_RAW_PE_PARITY`, or `EXPERIMENTAL_UNVERIFIED_PARITY`.
- `is_reliable`: boolean, default `False`.
- `shadow_mode`, `advisory_only`, `advisory_label`, `review_priority`, `disclaimer`.

### 4.2 Fallback Behavior

- When ML is disabled or inference fails: `status="DISABLED"`/`"UNAVAILABLE"`/`"FAILED"`, `malicious_score: null`, `is_reliable: False`.
- `app/api/analyses.py` (fallback): `status: "UNAVAILABLE"`, `malicious_score: None`, `model_sha256: f2fd3ed4...`, `feature_parity_status: "EXPERIMENTAL_UNVERIFIED_PARITY"`, `is_reliable: False`, `advisory_only: True`, `review_priority: "NOT_EVALUATED"`.

### 4.3 Review Priority Derivation

- `review_priority = "ELEVATED" if malicious_score >= 0.800395 else "NORMAL"` when available and score present; otherwise `"NOT_EVALUATED"`.
- `advisory_only` forced to `True`; `advisory_label = "EXPERIMENTAL_ADVISORY_PRIORITY"`.
- The heuristic threat verdict is independent and not mutated by the ML score.

---

## 5. Heuristic Independence and Enforcement Findings

- The composite risk engine and final classification path do not incorporate ML output as a verdict.
- High ML scores cannot independently trigger blocking/deletion/quarantine; shadow-mode inhibition
  is explicit (`active_blocking_inhibited = True` when `ML_SHADOW_MODE` is false, with policy notice).
- Advisory tests confirmed: high ML score does not alter heuristic verdict; active-mode inhibition
  and zero autonomous blocking hold.

---

## 6. Authorization, RBAC and Frontend Findings

- Security suite (`tests/security`, incl. auth/RBAC, API security, object authorization, info
  disclosure, injection/XSS, frontend render safety) passed: **100 passed, 22 subtests passed**.
- Frontend: `node --check frontend/static/js/app.js` → **exit 0, no syntax errors**.
- Frontend diff adds history ML filter (`#history-filter-ml`) and SOC advisory card content
  (disclaimer, gate status, score/threshold rendering, `N/A (Inference Unavailable)` handling).
- Advisory + functional + security tests covering these behaviors passed.

---

## 7. Model Artifact Integrity

- Trusted digest constant: `app/ml/classifier.py` line 29 → `TRUSTED_BASELINE_MODEL_SHA256 = "f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684"`.
- Authoritative artifact re-computed SHA-256: **`f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684` — EXACT MATCH**, size `1,609,815` bytes.
- In-repo secondary artifact: `storage/models/ember_baseline_v1/model.joblib` → `baf625e1787c6e3b6e2648caea2020435a95f077c53a1d5b52d1087efb25e59b`; sidecar and metadata agree (`baf625e1...`); treated as a distinct secondary artifact (different model identity: `ember-v2-baseline-hgb-subset80k` vs `ember-v2-baseline-hgb`).
- Artifact timestamps (`2026-10-28T01:06:01`) predate the ML-12B commit window (`17:49–17:52` on 2026-10-28) → **no model replacement/retraining observed during the ML-12B verification window**.

---

## 8. Reliability Gate

- `app/analyzers/ml_analyzer.py`: default `is_reliable = False`; all raw-PE paths
  (`analyze_pe_bytes`, incl. process-worker and in-process branches) set
  `is_reliable = False` with parity status `UNVERIFIED_RAW_PE_PARITY` / `EXPERIMENTAL_UNVERIFIED_PARITY`
  / `OFFLINE_TEST_UNVERIFIED_PARITY`.
- Verified feature-vector evaluation paths set `is_reliable = True` (offline dataset evaluation only).
- API surfaces expose `is_reliable: False` (`app/api/analyses.py`, `app/api/dashboard.py`,
  `app/pipeline/orchestrator.py`).

---

## 9. Dependency Environment (measured during audit)

| Component | Version / State |
|---|---|
| Python | 3.14.4 |
| scikit-learn | 1.9.0 |
| NumPy | 2.5.2 |
| joblib | 1.5.3 |
| LIEF | NOT INSTALLED |
| LightGBM | NOT INSTALLED |
| FastAPI | 0.141.1 |
| SQLAlchemy | 2.0.52 |
| Alembic | 1.20.1 |
| pytest | 9.1.1 |
| pefile | 2024.8.26 |
| YARA | NOT INSTALLED |
| Pandas | NOT INSTALLED |

No dependency install/upgrade/downgrade was performed during this audit.

---

## 10. Remaining Defects, Uncertainties, and Unverified Paths

1. **ML regression suite red:** 7 feature-parity failures (close_matches 2377 vs. 2381; three-way
   parity binary-indicator mismatches). Pre-existing relative to the ML-12B advisory changes; tracked
   to the feature-parity remediation line (ML-07/ML-08). Full-suite runability additionally blocked by
   missing local `lief`.
2. **Report discrepancies:** delivered ML-12B report numbers for ML/security suites were not
   reproducible as written.
3. **Dataset hash cross-report discrepancy:** `RELEASE02` lists archive SHA-256
   `b6052eb8c156d98889aa360be1b22e118e9a4f6cfce1d3f96615b3a4a273b063`, while
   `docs/data/DATASET_SCHEMA.md` and `storage/models/ember_baseline_v1/metadata.json` list
   `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812`.
4. **Secondary artifact design:** in-repo secondary model (`baf625e1...`) differs from the
   authoritative artifact (`f2fd3ed4...`); trusted-digest enforcement applies to the authoritative
   artifact.
5. No independent re-run of the EMBER dataset evaluation was performed in this audit (out of scope).

---

## 11. Closure Decision

**Decision: PASS WITH LIMITATIONS.**

- The ML-12B advisory integration — API contract, fallback semantics, orchestrator enrichment,
  frontend rendering, security posture, and model integrity — has been independently verified and
  holds.
- The overall ML regression suite is not green in the current environment (feature-parity failures;
  LIEF-dependent module not collectible).
- ML-03 status remains governed by its own blockers (dataset acquisition/readiness) and is **not**
  re-declared complete here.

---

## 12. Final Working Tree Status

- Branch: `my-feature-branch`
- HEAD: `fa001120ce6b8b49bedb8ec6055e555731cff12b`
- Modified tracked: `frontend/index.html`, `frontend/static/js/app.js`
- Untracked preserved: `RELEASE03_Corrective_Roadmap.md`, `docs/ML12B_Advisory_Dashboard_Integration_Report.md`,
  `scratch/update_app_js.py`, `tests/ml/test_advisory_dashboard_integration.py`, plus this report
  (`docs/ML12B_Independent_Verification_Report.md`)
- No commits made during this audit.

---

*End of ML-12B Independent Verification Report.*
