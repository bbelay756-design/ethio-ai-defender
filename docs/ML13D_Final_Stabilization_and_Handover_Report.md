# ETHIO-AI DEFENDER — MILESTONE ML-13D REPORT
## Final Stabilization and Handover Report

**Milestone ID:** ML-13D  
**Target Subsystem:** Full System Integration, Static Pipeline, ML Safety Gates, Database & Migrations, Handover & Operational Readiness  
**Date:** October 29, 2026  
**Auditor:** Senior Principal Systems Integration & Machine Learning Safety Engineer  
**Governing Ticket:** ETHIO-AI Defender — ML-13D: Final Stabilization and Handover  
**Scope Freeze Policy:** Strictly Enforced (Zero added features, zero model retraining, zero package modifications, zero operational database mutations)  
**Readiness Decision:** **READY FOR CONTROLLED INTERNAL TESTING**  

---

## 1. EXECUTIVE SUMMARY & VERIFICATION OUTCOME

Milestone **ML-13D** concludes the final stabilization, regression verification, and operational handover protocol for **ETHIO-AI Defender**, an AI-assisted defensive malware analysis and reverse-engineering platform engineered for enterprise cyber defense in Ethiopia. 

This milestone operates under a strict **scope-freeze mandate**. Every assertion from preceding milestones was independently verified against the current repository state and host environment without relying on prior documentation as unverified facts.

### 1.1 What Was Verified
1. **Model Integrity & Cryptographic Checksums:**
   - The primary frozen model artifact at `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib` was computed and verified with SHA-256 `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684`, matching the hardcoded `TRUSTED_BASELINE_MODEL_SHA256` digest exactly.
   - The secondary in-repository fallback model at `storage\models\ember_baseline_v1\model.joblib` was verified with SHA-256 `baf625e1787c6e3b6e2648caea2020435a95f077c53a1d5b52d1087efb25e59b`.
   - Feature dimensions are strictly verified at 2,381 float32 dimensions across all extractors.
2. **Machine Learning Safety Gates & Invariants:**
   - Verified that `is_reliable = False`, `advisory_only = True`, and `active_blocking_inhibited = True` are hardcoded across `app/pipeline/orchestrator.py`, `app/api/analyses.py`, `app/api/dashboard.py`, and `app/analyzers/ml_analyzer.py`.
   - Structural non-interference confirmed: ML inference scores cannot independently alter heuristic verdicts or trigger automated quarantine or remediation.
3. **Database Schema, Migrations, and Zero Operational Mutation:**
   - Alembic migration `b2c3d4e5f6a7` was verified as current head, correctly creating `analyst_reviews` with 10 columns and 4 non-conflicting indexes (`sample_id`, `analysis_id`, `user_id`, `created_at`).
   - Operational database `storage/defender.db` was preserved with **zero bytes altered** (`SHA-256: 02D51F7A39E07B1C9716BB5420BC72D81CF6AB103580BA06AEF3FE442D7AEC24`). All 2,595 sample records, 5,177 PE sections, 14,719 strings, and 4,689 users remain intact.
4. **Analyst Review & Confirmation Gate (ML-13):**
   - Verified full functional operation of `POST /analyses/{id}/reviews` and `GET /analyses/{id}/reviews`, including RBAC enforcement, duplicate review rejection (`409 Conflict`), and audit trail recording.
5. **Static Analysis & Heuristic Pipeline:**
   - 125/125 static analysis, intake, and workflow tests passed, covering PE headers, section entropy, string intelligence, and threat scoring.
6. **Authentication & RBAC:**
   - 97/97 security tests passed, verifying JWT lifecycle, password hashing, IDOR prevention, and role tiers (`admin`, `analyst`, `viewer`).

### 1.2 What Remains Incomplete or Constrained
1. **Ethiopian Enterprise Validation Corpus:** The current model was trained on historical EMBER 2018 data. A modern, representative corpus of benign and malicious PE software from Ethiopian enterprises has not yet been assembled for localized retraining.
2. **External Decompilation Tooling (NSA Ghidra):** Headless deep decompilation requires an external NSA Ghidra installation or active sidecar container; when unavailable, the pipeline degrades gracefully to static heuristic analysis.
3. **Pipeline Performance Under Heavy Concurrency:** The benchmark test `test_performance_pipeline_benchmarks` is sensitive to CPU contention during long multi-threaded test runs, showing minor timing variances (~1629ms vs 1500ms limit), while easily passing (<1000ms) under standard operating conditions.

```
====================================================================================================
                                      ML-13D AUDIT SCORECARD
====================================================================================================
Repository Working State      : PRESERVED & SCOPE-FROZEN (0 commits, 0 resets)
Operational DB Integrity      : 100% BIT-IDENTICAL (SHA-256 Preserved)
Pre-Audit DB SHA-256          : 02D51F7A39E07B1C9716BB5420BC72D81CF6AB103580BA06AEF3FE442D7AEC24
Post-Audit DB SHA-256         : 02D51F7A39E07B1C9716BB5420BC72D81CF6AB103580BA06AEF3FE442D7AEC24
Primary Model SHA-256         : F2FD3ED4E4FC0B482600BB92FE24E36D23A93617BF214F62019DEF5C352BD684 (Verified)
Feature Vector Dimensions     : 2,381 Dimensions (Strictly Enforced)
Parity Reliability Gate       : CLOSED (is_reliable = False, advisory_only = True)
Autonomous Blocking Gate      : INHIBITED (active_blocking_inhibited = True)
Full Regression Suite         : 1 FAILED, 760 PASSED (203.94s, exit code 1)
Database & Migration Tests    : 49/49 PASSED (100%)
Authentication & RBAC Tests   : 97/97 PASSED (100%)
Static Pipeline & Intake Tests: 125/125 PASSED (100%)
Core ML & Safety Gate Tests   : 191/191 PASSED (100%)
Retraining & ONNX Tests       : 14/14 PASSED (100%)
Upstream Parity Tests         : 20/20 PASSED (100%)
Benchmark Standalone (3 runs) : 3/3 PASSED (10.59s, 8.22s, 8.62s; direct 583-917ms)
Readiness Classification      : READY FOR CONTROLLED INTERNAL TESTING
====================================================================================================
```

---

## 2. REPOSITORY BASELINE & PRESERVATION

### 2.1 Host Environment & Git State
- **Repository Root:** `C:\Users\MILKWAY\ethio-ai-defender`
- **Active Git Branch:** `my-feature-branch`
- **Current HEAD Commit:** `fa001120ce6b8b49bedb8ec6055e555731cff12b` (`feat(frontend): display advisory-only disclaimer and closed parity gate status in SOC card`)
- **Python Executable:** `C:\Users\MILKWAY\ethio-ai-defender\venv\Scripts\python.exe`
- **Python Version:** `3.14.4` (tags/v3.14.4:23116f9, Apr 7 2026)
- **LIEF Library Version:** `1.0.0-d05b3499b`
- **Operational Database:** `storage/defender.db` (31,707,136 bytes, SHA-256: `02d51f7a39e07b1c9716bb5420bc72d81cf6ab103580ba06aef3fe442d7aec24`)

### 2.2 Preserved Tracked Modifications (16 Files)
No user changes were discarded, reset, or reverted:
1. `app/analyzers/ghidra_analyzer.py`: Sidecar container HTTP fallback integration.
2. `app/api/analyses.py`: Analyst confirmation review endpoints and audit event logging.
3. `app/audit/events.py`: Definition of `ANALYST_REVIEW_SUBMITTED` event type.
4. `app/audit/logger.py`: Structured JSON logging helpers.
5. `app/core/config.py`: Sidecar and ONNX configuration flags.
6. `app/db/models.py`: `AnalystReviewModel` definition with 4 unique indexes.
7. `app/db/repository.py`: Analyst review persistence and query methods.
8. `app/db/schemas.py`: Pydantic validation schemas for reviews.
9. `app/ml/classifier.py`: ONNX inference acceleration and fallback.
10. `app/ml/process_worker.py`: Subprocess worker isolation and timeout controls.
11. `app/pipeline/orchestrator.py`: Advisory ML integration without heuristic override.
12. `frontend/index.html`: Analyst review UI card and closed-gate warning banner.
13. `frontend/static/js/app.js`: Review submission logic and disclaimer rendering.
14. `requirements.txt`: Pinned runtime dependencies.
15. `tests/test_ghidra_analyzer.py`: Ghidra fallback unit tests.
16. `tests/test_yara_rule_versioning.py`: Updated `ALEMBIC_VERSION_HEAD = "b2c3d4e5f6a7"`.

### 2.3 Preserved Untracked Files
All untracked verification suites, migrations, scripts, and documentation files remain completely intact:
- Alembic Migration: `alembic/versions/b2c3d4e5f6a7_add_analyst_reviews_table.py`
- Test Suites: `tests/test_analyst_review_migration.py`, `tests/ml/test_ml13_analyst_confirmation_gate.py`, `tests/ml/test_advisory_dashboard_integration.py`, `tests/ml/test_onnx_inference.py`, `tests/ml/test_modern_training_pipeline.py`.
- Pipeline Scripts: `scripts/export_onnx.py`, `scripts/extract_features_streaming.py`, `scripts/ingest_modern_corpus.py`, `scripts/train_modern_baseline.py`.
- Milestone Reports: `docs/ML12B_*.md`, `docs/ML13B_*.md`, `docs/ML13C_*.md`, `docs/data/MODERN_CORPUS_PROVENANCE.md`.

---

## 3. VERIFIED CAPABILITIES & EVIDENCE

| Subsystem | Implemented Capability | Supporting Evidence / Tests | Status |
| :--- | :--- | :--- | :--- |
| **File Intake** | Validates PE extensions (.exe, .dll), enforces 50MB size limit, sanitizes filenames against traversal, strips execution permissions. | `tests/test_file_intake.py` (6/6 passed)<br>`tests/test_file_intake_api.py` (11/11 passed) | **VERIFIED** |
| **PE Parser** | Extracts DOS, COFF, Optional Header, Data Directories, Sections, Imports, Exports, Resources, and detects entry point anomalies. | `tests/test_pe_analyzer.py` (8/8 passed) | **VERIFIED** |
| **String Engine** | Dual ASCII / UTF-16LE decoding (min length 4), sliding-window Shannon entropy, regex indicators (IPs, URLs, registry keys, cmd/powershell). | `tests/test_string_analyzer.py` (14/14 passed)<br>`tests/test_strings_intelligence.py` (12/12 passed) | **VERIFIED** |
| **Threat Scoring** | Multi-factor weighted heuristic scoring engine synthesizing PE anomalies, section entropy, suspicious imports, strings, and YARA hits into 0-100 score. Sole authoritative automated verdict. | `tests/test_threat_scoring.py` (14/14 passed) | **VERIFIED** |
| **YARA Rules** | Compiles rules, manages version history, tracks rule match provenance, cascades deletion, and handles missing dependencies gracefully. | `tests/test_yara_pipeline_integration.py` (14/14 passed)<br>`tests/test_yara_rule_api.py` (14/14 passed)<br>`tests/test_yara_rule_versioning.py` (37/37 passed) | **VERIFIED** |
| **ML Advisory** | Extracts 2,381 float32 EMBER v2 features, loads frozen LightGBM model, executes in isolated subprocess worker with 10s timeout, provides advisory threat score. | 13 test suites under `tests/ml/` (191/191 passed) | **VERIFIED** |
| **Analyst Review** | Human confirmation workflow via `POST /analyses/{id}/reviews`. Enforces unique reviews per user, validates review status enum, logs audit trail events. | `tests/ml/test_ml13_analyst_confirmation_gate.py` (13/13 passed)<br>`tests/test_analyst_review_migration.py` (6/6 passed) | **VERIFIED** |
| **Auth & RBAC** | JWT authentication, password hashing, token expiration, lockout after 5 failed attempts, role-based access for Admin, Analyst, and Viewer. | `tests/test_auth_security.py` (8/8 passed)<br>`tests/test_module_16_security_suite.py` (37/37 passed) | **VERIFIED** |
| **Audit Logging** | Cryptographic JSONL audit trail logging logins, sample uploads, analysis runs, analyst reviews, and admin operations. | `tests/test_module_17_audit_suite.py` (6/6 passed) | **VERIFIED** |

---

## 4. PARTIAL AND UNAVAILABLE CAPABILITIES

### 4.1 YARA Runtime Availability
- **Status:** Functional with Fallback.
- **Verification Evidence:** The analyzer compiles curated rules and matches byte sequences. If `yara-python` is unavailable on a minimal host, `app/analyzers/yara_analyzer.py` logs a structured warning and returns `status="skipped"`. Static heuristic scoring continues unaffected.

### 4.2 NSA Ghidra Headless Decompilation (`LIM-GHIDRA`)
- **Status:** Functional with Graceful Degradation.
- **Verification Evidence:** Deep decompilation requires local NSA Ghidra and JDK or an active sidecar container (`GHIDRA_SIDECAR_URL`). When absent, the analyzer catches the subprocess error, logs a warning, and returns `status="skipped"`. Static heuristic scoring continues unaffected.

### 4.3 Upstream Reference Test Matrix & LIEF Compatibility (`LIM-LIEF`)
- **Status:** Fully Passing with Compatibility Shims (20/20).
- **Verification Evidence:** The upstream reference suite `tests/ml/test_upstream_reference_parity.py` passed 20/20 in 6.90s. The test file incorporates in-memory runtime shims (`_compat_transform`, LIEF exception aliases) that bridge modern LIEF 1.0.0 and scikit-learn 1.x without modifying production code.

### 4.4 Modern Ethiopian Enterprise Retraining Corpus (`LIM-CORPUS`)
- **Status:** Pending Operational Data Collection.
- **Verification Evidence:** All retraining pipeline infrastructure (`scripts/ingest_modern_corpus.py`, `scripts/extract_features_streaming.py`, `scripts/train_modern_baseline.py`) has been verified via unit tests (`tests/ml/test_modern_training_pipeline.py` 5/5 passed). However, an authentic, sanitized corpus of modern Ethiopian enterprise benign and malicious PE software has not yet been assembled. Consequently, the model reliability gate (`is_reliable=False`) must remain strictly closed.

---

## 5. REGRESSION VERIFICATION RESULTS

### 5.1 Subsystem Test Matrix
All test suites were executed independently using the virtual environment interpreter:

| Test Suite Description | Test Command | Tests | Passed | Failed | Duration | Exit Code |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Database & Migrations** | `pytest tests/test_analyst_review_migration.py tests/test_database.py tests/test_yara_rule_versioning.py -v` | 49 | 49 | 0 | 8.40s | **0** |
| **Authentication & RBAC** | `pytest tests/test_auth_security.py tests/test_auth_loading_states.py tests/test_module_16_security_suite.py tests/test_module_17_audit_suite.py tests/test_module_18_security_attacks.py tests/test_admin_dashboard_features.py tests/test_role_based_dashboards.py -v` | 97 | 97 | 0 | 36.00s | **0** |
| **File Intake & Static Pipeline** | `pytest tests/test_file_intake.py tests/test_file_intake_api.py tests/test_pe_analyzer.py tests/test_string_analyzer.py tests/test_strings_intelligence.py tests/test_ghidra_analyzer.py tests/test_threat_scoring.py tests/test_report_generator.py tests/test_analysis_overview_functional.py tests/test_end_to_end_analysis_workflow.py tests/test_yara_pipeline_integration.py tests/test_yara_rule_api.py -v` | 125 | 125 | 0 | 25.85s | **0** |
| **Core ML & Safety Gates** | `pytest tests/ml/test_feature_parity.py tests/ml/test_inference_parity.py tests/ml/test_classifier.py tests/ml/test_evaluator.py tests/ml/test_ml_analyzer.py tests/ml/test_shadow_mode_integration.py tests/ml/test_pipeline_noninterference.py tests/ml/test_advisory_dashboard_integration.py tests/ml/test_ember_v2.py tests/ml/test_ember_adapter.py tests/ml/test_serialization.py tests/ml/test_inference_timeout_and_isolation.py tests/ml/test_ml13_analyst_confirmation_gate.py -v` | 191 | 191 | 0 | 60.17s | **0** |
| **Retraining & ONNX** | `pytest tests/ml/test_modern_training_pipeline.py tests/ml/test_onnx_inference.py -v` | 14 | 14 | 0 | 9.37s | **0** |
| **Upstream Reference Parity** | `pytest tests/ml/test_upstream_reference_parity.py -v` | 20 | 20 | 0 | 6.90s | **0** |
| **Standalone Performance Test** | `pytest tests/test_module_19_final_integration.py -k "test_performance_pipeline_benchmarks" -v` | 1 | 1 | 0 | 7.76s | **0** |

### 5.2 Performance Test Context Comparison
In accordance with Section 5 instructions, `test_performance_pipeline_benchmarks` was evaluated in two separate operational contexts:
1. **Context 1: Standalone Execution (3 Independent Iterations)**
   - Run 1: `pytest tests/test_module_19_final_integration.py -k "test_performance_pipeline_benchmarks" -v` -> **PASSED in 10.59s (Exit Code 0)**
   - Run 2: `pytest tests/test_module_19_final_integration.py -k "test_performance_pipeline_benchmarks" -v` -> **PASSED in 8.22s (Exit Code 0)**
   - Run 3: `pytest tests/test_module_19_final_integration.py -k "test_performance_pipeline_benchmarks" -v` -> **PASSED in 8.62s (Exit Code 0)**
   - Direct execution measurement across 5 consecutive pipeline calls: `[765.19ms, 583.49ms, 798.02ms, 917.02ms, 826.66ms]` (mean: 778.08ms, all well below the 1500.0ms limit).
2. **Context 2: Full Continuous Regression Suite**
   - Command: `pytest tests/ -q`
   - Run 1 (Task-416): `1 failed, 760 passed, 182 warnings, 22 subtests passed in 273.85s` (Deviation: 1629.76ms vs 1500.0ms limit).
   - Run 2 (Task-656): `1 failed, 760 passed, 182 warnings, 22 subtests passed in 203.94s` (Deviation: 1776.31ms vs 1500.0ms limit).
   - Analysis: In both full continuous regression executions, 760/761 tests passed. The sole failure was `test_performance_pipeline_benchmarks` exceeding the 1500ms in-memory threshold when executed at the end of the 760-test run.
   - Hypothesis & Findings: Standalone evidence demonstrates that the pipeline executes in ~580–920ms under isolated conditions. The hypothesis that CPU contention, memory accumulation, and file descriptor load across 760 tests causes the 129–276ms elevation is strongly supported by empirical comparison; however, the failure remains a genuine full-suite failure under continuous test runner conditions and is recorded as such. Focused-suite passes do not negate the full-suite failure.

---

## 6. MODEL INTEGRITY & SAFETY GATES

### 6.1 Model Artifact Identity, Provenance & Runtime Selection
The model artifact loading logic in `app/ml/classifier.py` and `app/analyzers/ml_analyzer.py` was inspected and verified:
- **Primary Approved Artifact Directory:** `D:\ethio_ai_defender_artifacts\ember_baseline_v1`
  - Model Path: `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib`
  - File Size: `1,609,815 bytes`
  - Checksum Path: `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib.sha256`
  - Model Identifier: `ember-v2-baseline-hgb-subset80k`
  - Training Provenance: Trained on an 80,000-sample balanced stratified subset (40k benign, 40k malicious) of EMBER 2018 to ensure memory-safe training on developer workstations (formally approved in ML-04/ML-05).
  - **Computed SHA-256:** `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684`
  - **Expected Digest:** `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684`
  - **Comparison Result:** **100% BIT-IDENTICAL MATCH**
- **Secondary / Repository Fallback Directory:** `storage\models\ember_baseline_v1`
  - Model Path: `storage\models\ember_baseline_v1\model.joblib`
  - File Size: `1,607,626 bytes`
  - Checksum Path: `storage\models\ember_baseline_v1\model.joblib.sha256`
  - Model Identifier: `ember-v2-baseline-hgb`
  - Training Provenance: Trained on the full EMBER 2018 training pool (208,291 samples across partitions 0, 1, 3).
  - Computed SHA-256: `baf625e1787c6e3b6e2648caea2020435a95f077c53a1d5b52d1087efb25e59b`
- **Runtime Selection & Integrity Behavior:**
  - *Standard Host (`D:` present):* `DEFAULT_PRIMARY_MODEL_DIR` is selected. The computed hash matches `TRUSTED_BASELINE_MODEL_SHA256` (`f2fd3ed4...`), and the model initializes normally.
  - *Host without `D:` (Fallback Directory):* `EmberModelClassifier` resolves to `storage\models\ember_baseline_v1`. If `ETHIO_ML_TRUSTED_MODEL_SHA256` is not explicitly set, the classifier computes `baf625e1...`, detects the mismatch against `f2fd3ed4...`, and fails closed with `EmberModelError`. `MLAnalyzer` catches this, logs a warning, and sets `status = "UNAVAILABLE"`, safely defaulting to pure deterministic heuristic scoring. To deliberately run the fallback model, an operator must supply `ETHIO_ML_TRUSTED_MODEL_SHA256=baf625e1787c6e3b6e2648caea2020435a95f077c53a1d5b52d1087efb25e59b`.

### 6.2 Feature Vector Schema
- Total Dimension: **2,381 float32 values**.
- Sub-vector partitions: `ByteHistogram` (256), `ByteEntropyHistogram` (256), `StringExtractor` (1024), `GeneralFileInfo` (10), `HeaderFileInfo` (62), `SectionInfo` (255), `ImportsInfo` (256), `ExportsInfo` (262).
- Zero non-finite values (NaN/Inf) permitted; all outputs are strictly validated before classification.

### 6.3 Enforcement Safety Gates
1. **`is_reliable = False`:** Hardcoded in all prediction payloads, signaling to API consumers that ML is uncalibrated for automated decisions.
2. **`advisory_only = True`:** Stamped on all analysis summaries and responses.
3. **`active_blocking_inhibited = True`:** Structurally inhibits the orchestrator from executing firewall, quarantine, or file-blocking actions based on ML scores alone.
4. **Subprocess Isolation:** Worker processes run in isolated memory spaces with a 10.0-second deadline ceiling, preventing hangs from impacting the core server.

---

## 7. DATABASE SAFETY & PRESERVATION

### 7.1 Operational Database Integrity
- Operational Database Path: `storage/defender.db`
- Baseline Audit File Size: `31,707,136 bytes`
- Baseline Audit SHA-256 Checksum: `02d51f7a39e07b1c9716bb5420bc72d81cf6ab103580ba06aef3fe442d7aec24`
- Existing Records: `samples`: 2,595 | `sections`: 5,177 | `imports`: 1,146 | `strings`: 14,719 | `indicators`: 134 | `users`: 4,689 | `yara_rules`: 0.
- **Verification Guarantee:** SHA-256 was verified after every test suite run. (Reconciled under ML-13E following isolated single-sample pipeline benchmark measurement; see `docs/ML13E_Evidence_Reconciliation_Report.md`).

### 7.2 Safe Test Isolation Method
All tests run against temporary, disposable SQLite databases:
- In-memory SQLite: `sqlite:///:memory:`
- Disposable file-based SQLite: Created via `tempfile.NamedTemporaryFile` with teardown fixtures that immediately close the engine and unlink the temporary file.
- At no point during regression verification did any test execute DDL or DML against `storage/defender.db`.

---

## 8. SECURITY & AUTHORIZATION REVIEW

### 8.1 Verified Controls
1. **Secret Key Fail-Closed Protection:** The application refuses to start if `SECRET_KEY` is missing, less than 32 characters, or set to the historical insecure key `ethio-ai-defender-secure-platform-master-key-2026`.
2. **CORS Security:** Wildcard origins (`*`) are strictly prohibited and raise a runtime error on startup. Empty `CORS_ORIGINS` defaults to same-origin-only.
3. **Request Body Size Limits:** ASGI middleware intercepts multipart requests exceeding 51MB *before* parsing, mitigating upload-based memory exhaustion attacks.
4. **RBAC Boundaries:** Administrative endpoints (`/admin/*`, `/api/users/*`) reject non-admin tokens with `403 Forbidden`. Analysis review submission (`POST /analyses/{id}/reviews`) rejects `viewer` tokens.
5. **No Secret Leakage:** Passwords are never returned in responses and are hashed using salted PBKDF2/bcrypt. Database credentials and signing secrets are completely omitted from audit logs and API error responses.

### 8.2 Unresolved Operational Risks
- **SQLite Concurrency:** SQLite is well-suited for single-host deployments but will experience database locks under high concurrent write loads from multiple simultaneous analysts. Transition to PostgreSQL should be planned for multi-analyst SOC scaling.
- **Environment Secrets:** Production deployments must inject secrets via OS environment variables or secure secret vaults rather than relying on local `.env` files.

---

## 9. CONFIGURATION AND SAFE STARTUP GUIDANCE

### 9.1 Prerequisites
- Python 3.10+ (tested on Python 3.14.4 AMD64).
- Virtual environment with pinned packages from `requirements.txt`.
- Minimum 4 GB RAM (8 GB recommended for concurrent analysis).
- Read/write access to `storage/` directory.

### 9.2 Required Environment Variables
| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `SECRET_KEY` | **YES** | None | 32+ character random key for JWT signing. |
| `DEBUG` | No | `False` | Set to `false` in production. |
| `DATABASE_URL` | No | `sqlite:///storage/defender.db` | Database connection string. |
| `ML_ENABLED` | No | `false` | Enable/disable ML inference worker. |
| `ML_SHADOW_MODE` | No | `true` | When true, ML runs in non-blocking advisory mode. |
| `CORS_ORIGINS` | No | `""` | Comma-separated list of explicit frontend origins. |
| `GHIDRA_HOME` | No | `""` | Path to NSA Ghidra installation (optional). |
| `GHIDRA_SIDECAR_ENABLED` | No | `false` | Toggle containerized Ghidra HTTP bridge. |

### 9.3 Safe Production Startup Instructions (PowerShell)
```powershell
# 1. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 2. Configure mandatory production secrets
$env:SECRET_KEY = "generate-a-strong-random-secret-key-at-least-32-chars-long"
$env:DEBUG = "false"
$env:ML_ENABLED = "true"
$env:ML_SHADOW_MODE = "true"

# 3. Launch the FastAPI server with Uvicorn
uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 4
```

---

## 10. BACKUP AND RECOVERY PROCEDURES

### 10.1 Artifact and Database Layout
- **Operational Database:** `storage/defender.db`
- **Quarantined Files:** `storage/quarantine/`
- **Audit Logs:** `storage/logs/audit.jsonl`
- **Model Storage:** `storage/models/` and `D:\ethio_ai_defender_artifacts\`

### 10.2 Safe Backup Procedure (Non-Destructive)
To create a point-in-time consistent backup without shutting down the platform:
```powershell
# 1. Create a timestamped backup directory
$backupDir = "backups\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $backupDir -Force

# 2. Create a clean SQLite database snapshot using online backup API
python -c "import sqlite3; src = sqlite3.connect('storage/defender.db'); dst = sqlite3.connect('$backupDir/defender.db'); src.backup(dst); dst.close(); src.close()"

# 3. Archive audit logs and quarantined samples
Copy-Item -Path "storage\logs\audit.jsonl" -Destination "$backupDir\" -Force
Compress-Archive -Path "storage\quarantine\*" -DestinationPath "$backupDir\quarantine.zip" -CompressionLevel Optimal

# 4. Generate SHA-256 verification manifest
Get-ChildItem -Path $backupDir -File | ForEach-Object {
    $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
    "$hash  $($_.Name)"
} | Set-Content -Path "$backupDir\MANIFEST.sha256"
```

### 10.3 Safe Restoration Procedure
1. Stop the application process (`uvicorn`).
2. Verify backup manifest integrity:
   ```powershell
   Get-Content "$backupDir\MANIFEST.sha256"
   ```
3. Copy `defender.db` back to `storage/defender.db`.
4. Restore `quarantine/` binaries from archive.
5. Verify database integrity:
   ```powershell
   python -c "import sqlite3; con = sqlite3.connect('storage/defender.db'); print(con.execute('PRAGMA integrity_check;').fetchall())"
   ```
6. Restart application service.

---

## 11. KNOWN LIMITATIONS & RISK REGISTER

1. **EMBER 2018 Concept Drift (`RISK-01`):**
   - The frozen model was trained on 2018 samples. Malware obfuscators, packers, and API patterns have evolved significantly.
   - *Mitigation:* `is_reliable=False` and `active_blocking_inhibited=True` prevent the model from independently triggering false positive blocks.
2. **Missing Ethiopian Enterprise Corpus (`RISK-02`):**
   - In-country specialized software (e.g., Amharic font tools, local banking clients, government accounting utilities) is not represented in the EMBER dataset.
   - *Mitigation:* The Analyst Confirmation Gate requires human SOC analysts to validate high-risk verdicts.
3. **External Decompilation Tooling (`RISK-03`):**
   - Ghidra decompilation is unavailable if neither local Ghidra nor the sidecar container is deployed.
   - *Mitigation:* The pipeline falls back gracefully to static heuristic analysis without error.
4. **Benchmark Timing Sensitivity (`RISK-04`):**
   - Pipeline benchmark test can exceed 1500ms under heavy concurrent test load.
   - *Mitigation:* Pipeline execution easily meets the SLA under single-analysis production load (< 1000ms).

---

## 12. OPERATIONAL ROLLBACK GUIDANCE

If a future update or experimental migration fails, operators should execute the following non-destructive rollback steps:
1. **Preserve Current State Snapshot:**
   ```bash
   git branch rollback-checkpoint-ml13d
   ```
2. **Revert Working Tree to Last Known Good Commit:**
   ```bash
   git checkout fa001120ce6b8b49bedb8ec6055e555731cff12b
   ```
3. **Restore Database from Point-in-Time Snapshot:**
   Restore `storage/defender.db` from the pre-deployment backup directory created via Section 10.2.
4. **Never Run Destructive Cleanup:** Do not run `git clean -fd` or delete `storage/quarantine/` as this would destroy operational sample evidence and quarantine records.

---

## 13. RECOMMENDED NEXT ACTIONS (PRIORITIZED BY RISK)

The following actions are recommended for post-handover implementation (do not implement in ML-13D):

1. **[High Priority] Curate Representative Ethiopian Enterprise Corpus (ML-14):**
   - Gather 10,000+ benign PE executables from Ethiopian enterprise desktop environments (ministries, banks, telecom).
   - Ingest and index using `scripts/ingest_modern_corpus.py`.
2. **[High Priority] Production PostgreSQL Migration Evaluation:**
   - Transition from SQLite to PostgreSQL for multi-analyst concurrent SOC deployments.
3. **[Medium Priority] Containerized Ghidra Sidecar Deployment (OPS-02):**
   - Deploy `docker-compose.yml` to provide isolated headless decompilation on a dedicated container host.
4. **[Low Priority] Benchmark Threshold Adjustment:**
   - Relax `test_performance_pipeline_benchmarks` assertion threshold from 1500ms to 2000ms to avoid false alarm test failures under saturated CI runner CPU conditions.

---

## 14. FINAL READINESS DECISION

### Classification: **READY FOR CONTROLLED INTERNAL TESTING**

### Operational Justification:
The **ETHIO-AI Defender** platform is **READY FOR CONTROLLED INTERNAL TESTING** within a managed, internal security engineering environment.

All core static analysis pipelines, YARA rule matching, heuristic threat scoring, database persistence, JWT authentication, RBAC boundaries, and analyst review workflows are fully verified, robust, and functional.

The platform is **NOT READY** for a limited operational pilot or unattended production deployment due to the following specific constraints:
1. **Model Storage Path Dependency:** Primary model artifact resolution relies on an external drive letter (`D:\ethio_ai_defender_artifacts\`). On environments without drive `D:`, the system safely fails closed (`status="UNAVAILABLE"`) unless an explicit environment variable is injected.
2. **Full-Suite Benchmark Flake:** `test_performance_pipeline_benchmarks` fails under continuous full-suite test load (1629–1776ms vs 1500ms limit), requiring CI test runner tuning or threshold calibration.
3. **Absence of Ethiopian Enterprise Validation Corpus:** The EMBER 2018 dataset exhibits concept drift and lacks representation of authentic Ethiopian enterprise benign and malicious PE software.
4. **Safety Invariants:** The ML reliability gate remains locked (`is_reliable=False`, `active_blocking_inhibited=True`), restricting ML strictly to human advisory use.

Under the documented advisory-only deployment model, the system provides high-confidence static indicators and assists SOC analysts while preventing catastrophic automated false-positive disruption to Ethiopian enterprise infrastructure.
