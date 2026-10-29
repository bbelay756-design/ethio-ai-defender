# ETHIO-AI Defender — RELEASE-03 Completion Report

**Document Version:** 1.1.0 (Final Acceptance Review)  
**Date:** October 29, 2026  
**Author:** Defensive Malware-Analysis Engineer & Release Verification Lead  
**Scope:** Verification and Acceptance Review of [RELEASE03_Corrective_Roadmap.md](file:///C:/Users/MILKWAY/ethio-ai-defender/RELEASE03_Corrective_Roadmap.md)  
**Classification:** Defensive Security & Quality Assurance Verification  

---

## 1. Executive Status & Release Decision

### Release Decision: **ACCEPT WITH EXPLICIT LIMITATIONS**
*(Deployment Profile: Controlled Analyst-Assisted Evaluation — Non-Authoritative Shadow Telemetry)*

All implementable code, architecture, pipeline integrations, optimizations, and defensive safety controls defined in [RELEASE03_Corrective_Roadmap.md](file:///C:/Users/MILKWAY/ethio-ai-defender/RELEASE03_Corrective_Roadmap.md) have been completed, verified with isolated regression suites, and mathematically validated. However, full production deployment and retraining execution are governed by explicit external blockers and operational limitations:

1. **ML-13 (Analyst-Confirmation Gate):** **`PASS`** (100% Complete & Verified; prevents autonomous ML blocking; human-in-the-loop review enforced).
2. **PERF-01 (ONNX Runtime Model Optimization):** **`PASS`** (100% Complete & Verified; numerical parity $\max |\Delta| = 3.08 \times 10^{-7} \ll 10^{-5}$; ~150x raw model inference latency improvement).
3. **OPS-02 (Containerized Ghidra Sidecar Service):** **`CONTAINER ARTIFACTS & CLIENT CODE PASS`** / **`HOST RUNTIME BLOCKED`** (Container specification, sidecar RPC server, client adapter with resilient fallback, and mock test suite 100% pass; live container execution blocked by absence of Docker runtime on Windows host).
4. **ML-14 (Modern Corpus Retraining Pipeline):** **`PIPELINE & SAFETY CODE PASS`** / **`DATASET BLOCKED`** (Passive ingest validator, mmap streaming feature extractor, isolated candidate trainer, provenance specs, and synthetic PE tests 100% pass; candidate model training blocked due to total absence of 2024–2026 PE malware and Ethiopian benign enterprise corpus).

---

## 2. Complete Milestone Inventory Table

| Milestone | Target Scope | Status | Verified Acceptance Criteria | Unverified Acceptance Criteria | Files Changed / Added |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-13** | Cascaded Analyst-Confirmation Gate for uncorroborated ML findings | **`PASS`** | • ML score $\ge \tau$ without deterministic proof marks `PENDING_REVIEW`<br>• ML cannot autonomously block, quarantine, or set malicious verdict<br>• Dedicated `analyst_reviews` table + Alembic migration `b2c3d4e5f6a7`<br>• Strict RBAC (`analyst`/`admin` write, `viewer` read-only 403)<br>• Review idempotency (409 Conflict on duplicate)<br>• Full audit event emission (`ANALYSIS_CONFIRMED`, `ANALYSIS_REJECTED`)<br>• Rejection preserves original deterministic evidence & telemetry<br>• Modern dashboard UI with badge, rationale modal, review history | *None* (100% verified) | • [`app/pipeline/orchestrator.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/pipeline/orchestrator.py)<br>• [`app/db/models.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/db/models.py)<br>• [`app/db/schemas.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/db/schemas.py)<br>• [`app/db/repository.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/db/repository.py)<br>• [`app/api/analyses.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/api/analyses.py)<br>• [`app/audit/events.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/audit/events.py)<br>• [`frontend/index.html`](file:///C:/Users/MILKWAY/ethio-ai-defender/frontend/index.html)<br>• [`frontend/static/js/app.js`](file:///C:/Users/MILKWAY/ethio-ai-defender/frontend/static/js/app.js)<br>• [`alembic/versions/b2c3d4e5f6a7_add_analyst_reviews_table.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/alembic/versions/b2c3d4e5f6a7_add_analyst_reviews_table.py)<br>• [`tests/ml/test_ml13_analyst_confirmation_gate.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/test_ml13_analyst_confirmation_gate.py) |
| **OPS-02** | Containerized Ghidra Sidecar Isolation Service | **`BLOCKED (Host Runtime)`** / **`PASS (Code & Container)`** | • Hardened Dockerfile with non-root user `ghidra:10001`<br>• Read-only container root (`read_only: true`), `cap_drop: ALL`<br>• Token authentication (`X-Sidecar-Token`)<br>• Zero detonation (Ghidra headless batch scripts strictly parse headers/symbols)<br>• Sample mount `:ro` with ephemeral `/tmp/workspace`<br>• Resilient client HTTP adapter in `GhidraAnalyzer`<br>• Timeout and connection failure gracefully degrade to `available=False, status="UNAVAILABLE"`<br>• 17/17 Ghidra tests pass | • Execution in live container engine (Docker executable not installed on host) | • [`docker/ghidra-sidecar/Dockerfile`](file:///C:/Users/MILKWAY/ethio-ai-defender/docker/ghidra-sidecar/Dockerfile)<br>• [`docker/ghidra-sidecar/sidecar_server.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/docker/ghidra-sidecar/sidecar_server.py)<br>• [`docker-compose.yml`](file:///C:/Users/MILKWAY/ethio-ai-defender/docker-compose.yml)<br>• [`app/core/config.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/core/config.py)<br>• [`app/analyzers/ghidra_analyzer.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ghidra_analyzer.py)<br>• [`tests/test_ghidra_analyzer.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/test_ghidra_analyzer.py) |
| **PERF-01** | ONNX Runtime Export and Optimization | **`PASS`** | • Export script [`scripts/export_onnx.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/export_onnx.py) converts models to ONNX Opset 15<br>• Mathematical parity across 10,000 vectors: $\max \|\Delta\| = 3.078 \times 10^{-7} \ll 10^{-5}$<br>• Isolated model median latency speedup: **~150x** ($0.04-0.08\text{ ms}$ vs $6.05-13.13\text{ ms}$)<br>• SHA-256 cryptographic verification before session initialization<br>• Transparent fallback to scikit-learn `.joblib` on missing or tampered ONNX<br>• Process worker and classifier load ONNX automatically when `ML_ONNX_ENABLED=true` | *None* (100% verified) | • [`scripts/export_onnx.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/export_onnx.py)<br>• [`app/core/config.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/core/config.py)<br>• [`app/ml/classifier.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/classifier.py)<br>• [`app/ml/process_worker.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/process_worker.py)<br>• [`requirements.txt`](file:///C:/Users/MILKWAY/ethio-ai-defender/requirements.txt)<br>• [`tests/ml/test_onnx_inference.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/test_onnx_inference.py)<br>• [`storage/models/ember_baseline_v1/model.onnx`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/models/ember_baseline_v1/model.onnx)<br>• [`storage/models/ember_baseline_v1/model.onnx.sha256`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/models/ember_baseline_v1/model.onnx.sha256)<br>• [`storage/models/ember_baseline_v1/onnx_validation_report.json`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/models/ember_baseline_v1/onnx_validation_report.json) |
| **ML-14** | Modern Corpus (2024–2026) Retraining Pipeline | **`BLOCKED (Corpus)`** / **`PASS (Pipeline Code)`** | • Passive PE ingest deduplication & validation script [`scripts/ingest_modern_corpus.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/ingest_modern_corpus.py)<br>• Out-of-core streaming feature extractor [`scripts/extract_features_streaming.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/extract_features_streaming.py) enforcing $<3.5\text{ GB}$ RAM constraint<br>• Candidate model trainer [`scripts/train_modern_baseline.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/train_modern_baseline.py) with threshold calibration $\tau_{1\%}^*$<br>• Provenance standard [`docs/data/MODERN_CORPUS_PROVENANCE.md`](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/data/MODERN_CORPUS_PROVENANCE.md)<br>• Pipeline test suite passing (5/5 tests)<br>• Authoritative model (`f2fd3ed4...`) completely untouched and preserved | • Live training on modern PE malware (no 2024–2026 PE samples exist in storage)<br>• Evaluation on Ethiopian enterprise benign software (no local benign corpus exists) | • [`scripts/ingest_modern_corpus.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/ingest_modern_corpus.py)<br>• [`scripts/extract_features_streaming.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/extract_features_streaming.py)<br>• [`scripts/train_modern_baseline.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/train_modern_baseline.py)<br>• [`docs/data/MODERN_CORPUS_PROVENANCE.md`](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/data/MODERN_CORPUS_PROVENANCE.md)<br>• [`tests/ml/test_modern_training_pipeline.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/test_modern_training_pipeline.py) |

---

## 3. Decision Threshold Reconciliation

A rigorous reconciliation of threshold references across all codebase modules, metadata files, test suites, and documentation resolved the following:

### 3.1 Threshold Inventory and Lineage
- **Operational & Evaluation Threshold: $\tau_{1\%}^* = 0.800395$ (Exact: `0.8003951606744594`)**
  - **Source:** Calibrated on the 52,073-sample validation partition of the primary authoritative model ([`D:\ethio_ai_defender_artifacts\ember_baseline_v1\metadata.json`](file:///D:/ethio_ai_defender_artifacts/ember_baseline_v1/metadata.json)) to achieve a 1.0% False Positive Rate.
  - **Active Operational Usage:** Hardcoded in [`app/pipeline/orchestrator.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/pipeline/orchestrator.py#L351, #L388, #L413) as `active_threshold: 0.800395`. A sample with $p \ge 0.800395$ triggers `review_priority = "ELEVATED"` and routes uncorroborated alerts to `PENDING_REVIEW`.
  - **Test Suite Usage:** Directly verified in [`tests/ml/test_ml13_analyst_confirmation_gate.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/test_ml13_analyst_confirmation_gate.py) and [`tests/ml/test_onnx_inference.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/test_onnx_inference.py#L96).
- **Secondary Model In-Repo Threshold: $\tau_{1\%} = 0.694102$**
  - **Source:** Calibrated on the secondary in-repo model ([`storage/models/ember_baseline_v1/metadata.json`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/models/ember_baseline_v1/metadata.json)). Kept for repository testing when the primary D: drive artifact is unmounted.
- **Erroneous Historical Reference: `0.8336`**
  - **Source & Purpose:** `0.8336` was an internal tree split threshold present in `storage/ember2018/ember_model_2018.txt`. An earlier draft of the completion report inadvertently referenced `0.8336` in narrative text.
  - **Reconciliation:** No Python operational file, configuration variable, or test ever used `0.8336` as an operational decision boundary. All narrative text is hereby reconciled to the verified authoritative threshold: **$\tau_{1\%}^* = 0.800395$**.

### 3.2 Decision Policy Parity Under ONNX
- Enabling ONNX Runtime does **not** alter the operational decision policy.
- In [`tests/ml/test_onnx_inference.py::test_04_threshold_decision_consistency`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/test_onnx_inference.py#L94-L104), classifications produced by ONNX Runtime at $\tau = 0.800395$ were compared against scikit-learn.
- **Result:** $100.000\%$ identical classifications ($10,000 / 10,000$ decisions identical across random, edge-case, and real EMBER vectors).

---

## 4. Milestone Implementation & Safety Reviews

### 4.1 ML-13 — Cascaded Analyst-Confirmation Gate

#### Problem & Defensive Intent
At an enterprise base rate of 0.1% true malware (1,000:1 benign imbalance), an empirical False Positive Rate of 2.235% causes precision to collapse to 3.73%, generating approximately 22,350 false alerts per 1,000,000 processed executables. The intent of ML-13 is **not** to mathematically eliminate false positives from the ML model, but rather to **inhibit autonomous host-level blocking or quarantine actions** based purely on statistical ML predictions, requiring human analyst confirmation before any response actions can occur.

#### Implementation & Invariants
1. **Zero Autonomous Intervention:**
   - In [`app/pipeline/orchestrator.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/pipeline/orchestrator.py#L400-L460), if a sample produces $p \ge 0.800395$ but deterministic signatures are absent (0 YARA matches and heuristic score $< 70$), the sample transitions to `PENDING_REVIEW` with `active_blocking_inhibited = True`.
   - Autonomous quarantine and blocking are prohibited for ML-only findings.
2. **Review Persistence & Immutability:**
   - Review verdicts are persisted to the `analyst_reviews` table via Alembic migration `b2c3d4e5f6a7`.
   - Idempotency is enforced: duplicate submissions return HTTP 409 Conflict.
   - Rejections (`FALSE_POSITIVE`) transition the review state but **do not mutate, erase, or mask** the original raw feature vectors, extracted strings, PE hashes, or original ML scores.
3. **Role-Based Access Control & Audit Trail:**
   - Endpoints `POST /api/analyses/{id}/review` and `GET /api/analyses/{id}/reviews` require authentication.
   - Roles `analyst` and `admin` are permitted to submit reviews; role `viewer` is rejected with HTTP 403 Forbidden.
   - Every review action records an immutable structured audit event (`ANALYSIS_CONFIRMED`, `ANALYSIS_REJECTED`) to `storage/logs/audit.jsonl`.
4. **Safety Limitations & Residual Risks:**
   - The gate does **not** make the ML model accurate or immune to false alerts. The model still flags benign software with $p \ge 0.800395$.
   - The gate relies on human SOC analysts. This introduces residual operational risks: analyst queue fatigue, review backlog latency during alert floods, and human error (incorrectly confirming benign software or rejecting true zero-day threats).

---

### 4.2 OPS-02 — Containerized Ghidra Sidecar Service

#### Architecture & Isolation
- **Container Hardening ([`docker/ghidra-sidecar/Dockerfile`](file:///C:/Users/MILKWAY/ethio-ai-defender/docker/ghidra-sidecar/Dockerfile)):** Eclipse Temurin OpenJDK 17 + Ghidra 11.x headless. Non-root user `ghidra` (UID/GID `10001:10001`). Read-only root filesystem (`read_only: true`). All Linux capabilities dropped (`cap_drop: ALL`). Quarantined samples mounted read-only (`:ro`).
- **Internal RPC ([`docker/ghidra-sidecar/sidecar_server.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/docker/ghidra-sidecar/sidecar_server.py)):** Spawns Ghidra `analyzeHeadless` strictly via argument arrays (no shell injection). Token-authenticated via `X-Sidecar-Token`. Ephemeral `/tmp/workspace` is purged after every execution. Zero binary execution: static disassembly only.
- **Graceful Fallback ([`app/analyzers/ghidra_analyzer.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ghidra_analyzer.py)):** If the sidecar is offline, times out, or fails, the client returns `available=False, status="UNAVAILABLE"` without interrupting the parent pipeline. All 17 tests in `tests/test_ghidra_analyzer.py` pass.

#### Blocker: Host Docker Engine Unavailable
- `docker` is not installed on the Windows host (`The term 'docker' is not recognized`).
- **Status:** **`BLOCKED (Host Runtime)`** / **`PASS (Code & Container Artifacts)`**.
- We explicitly do not claim successful live container execution. Resumption requires installing Docker Desktop with WSL2.

---

### 4.3 PERF-01 — ONNX Runtime Optimization & Benchmark Validation

#### Export & Mathematical Parity
- Converted the authoritative model (`HistGradientBoostingClassifier`, SHA-256: `f2fd3ed4...`) and in-repo model (`baf625e1...`) to ONNX Opset 15 via [`scripts/export_onnx.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/export_onnx.py).
- Evaluated on $10,000$ 2,381-dimensional vectors (5,000 Gaussian random, 1,000 edge cases, 4,000 real EMBER test vectors):
  - **$\max |\Delta|$:** **$3.078038 \times 10^{-7}$** ($\ll 10^{-5}$ acceptance limit).
  - **Mean $|\Delta|$:** **$4.875709 \times 10^{-8}$**.
  - **Numerical Parity ($\epsilon < 10^{-5}$):** **`PASSED`**.
  - **Bitwise Equality:** **`FALSE`** (as expected across differing double-precision CPU vs SIMD multithreaded tree traversal engines).
  - **Bounds & Finiteness:** $100\%$ finite, strictly in $[0.0, 1.0]$.

#### Benchmark Validation & Scope Distinction
- **Exact Benchmark Harness:** [`scripts/export_onnx.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/export_onnx.py#L219-L275), `run_benchmark`.
- **Environment:** Windows 11 x64, Python 3.14.4, `onnxruntime==1.31.1`, `scikit-learn==1.6.1`, `numpy==2.2.3`. Single-vector batch size 1 (`(1, 2381)`).
- **Warmup & Iterations:** 20 warmup iterations, 200 measured iterations.
- **Measured Latency Results (Reproduced on Authoritative Model):**
  - **scikit-learn (`model.joblib`):** Median = **$6.050\text{ ms}$** (P95: $15.906\text{ ms}$, Mean: $7.628\text{ ms}$, Std: $5.661\text{ ms}$). *(Cold initial run: Median $13.13\text{ ms}$, P95 $46.28\text{ ms}$)*.
  - **ONNX Runtime (`model.onnx`):** Median = **$0.040\text{ ms}$** (P95: $0.067\text{ ms}$, Mean: $0.045\text{ ms}$, Std: $0.017\text{ ms}$). *(Cold initial run: Median $0.08\text{ ms}$, P95 $0.20\text{ ms}$)*.
  - **Measured Model Kernel Speedup:** **$149.39\times$ to $159.68\times$** reduction in isolated model forward-pass latency.
- **Critical Scope Boundary (Model Latency vs End-to-End Pipeline Latency):**
  > [!IMPORTANT]
  > This speedup applies **strictly to the isolated numerical model kernel** (`session.run` vs `predict_proba`). It does **not** measure end-to-end sample analysis. Production inference incurs additional pipeline overhead:
  > - Passive PE feature parsing via `pefile`/`lief` (~15–30 ms).
  > - `multiprocessing` IPC pipe serialization/deserialization to `MLProcessWorker` (~5–10 ms).
  > - SQLite persistence, YARA scanning, and threat scoring.
  > Therefore, this optimization resolves CPU saturation during batch vector scoring, but must not be represented as a 150x speedup of the total pipeline.

#### Operational Selection Logic
- Default: `settings.ML_ONNX_ENABLED` is `False`. scikit-learn `.joblib` is used by default.
- When `ML_ONNX_ENABLED=true`, `EmberModelClassifier` and `MLProcessWorker` verify the SHA-256 digest against `TRUSTED_ONNX_MODEL_SHA256_SET` and initialize the ONNX session.
- If ONNX is missing or tampered, the system falls back safely to `.joblib`.

---

### 4.4 ML-14 — Modern Corpus Retraining Pipeline

#### Architecture & Safety Controls
- **Passive Ingestion ([`scripts/ingest_modern_corpus.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/ingest_modern_corpus.py)):** Uses `pefile.PE(fast_load=True)` to inspect PE headers and Authenticode digital signatures. Zero binary execution or emulation.
- **Low-Memory Streaming Extractor ([`scripts/extract_features_streaming.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/extract_features_streaming.py)):** Streams vectors into disk memory-mapped files (`X_modern.mmap`, `y_modern.mmap`), enforcing a $<3.5\text{ GB}$ physical RAM boundary.
- **Candidate Trainer ([`scripts/train_modern_baseline.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/scripts/train_modern_baseline.py)):** Trains `HistGradientBoostingClassifier` with deterministic train/validation split (seed 42). Outputs candidate model exclusively to an isolated directory: [`storage/models/ember_modern_candidate_v1/`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/models/ember_modern_candidate_v1/). It cannot overwrite the authoritative model (`f2fd3ed4...`).
- **Pipeline Test Suite:** 5/5 tests in `tests/ml/test_modern_training_pipeline.py` pass using synthetic PE binaries.

#### Blocker: Modern Corpus Data Unavailable
- Inspection of `storage/` confirms only 2018 EMBER data is available. No 2024–2026 PE malware or Ethiopian institutional software exists.
- **Status:** **`BLOCKED — REQUIRED MODERN CORPUS UNAVAILABLE`**.
- Resumption instructions and data provenance requirements are fully documented in [`docs/data/MODERN_CORPUS_PROVENANCE.md`](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/data/MODERN_CORPUS_PROVENANCE.md).

---

## 5. Master Regression Evidence & Storage Integrity

### 5.1 Master Regression Execution
- **Command:** `venv\Scripts\pytest.exe tests/ -q`
- **Exit Code:** `0`
- **Result:** **761 passed**, 0 failed, 0 skipped, 22 subtests passed in 246.42s (182 library deprecation warnings).

### 5.2 Storage & Protected File Integrity Check
All protected files and hashes remain bit-identical before and after all release audit operations:

| Protected Target | Expected SHA-256 Digest | Verified Current SHA-256 | Integrity Status |
| :--- | :--- | :--- | :--- |
| **Operational Database** ([`storage/defender.db`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/defender.db)) | `02D51F7A39E07B1C9716BB5420BC72D81CF6AB103580BA06AEF3FE442D7AEC24` | `02D51F7A39E07B1C9716BB5420BC72D81CF6AB103580BA06AEF3FE442D7AEC24` | **BIT-IDENTICAL** (0 bytes mutated) |
| **Authoritative Model** (`D:\ethio_ai_defender_artifacts\...\model.joblib`) | `F2FD3ED4E4FC0B482600BB92FE24E36D23A93617BF214F62019DEF5C352BD684` | `F2FD3ED4E4FC0B482600BB92FE24E36D23A93617BF214F62019DEF5C352BD684` | **BIT-IDENTICAL** (Untouched) |
| **Secondary In-Repo Model** ([`storage/models/.../model.joblib`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/models/ember_baseline_v1/model.joblib)) | `BAF625E1787C6E3B6E2648CAEA2020435A95F077C53A1D5B52D1087EFB25E59B` | `BAF625E1787C6E3B6E2648CAEA2020435A95F077C53A1D5B52D1087EFB25E59B` | **BIT-IDENTICAL** (Untouched) |
| **Reference LightGBM 2018** ([`storage/ember2018/ember_model_2018.txt`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/ember2018/ember_model_2018.txt)) | `509DE4A83E2D76B69FB3025CED0429E5F40F6A95CA40122B9EEDD03317FFF5E2` | `509DE4A83E2D76B69FB3025CED0429E5F40F6A95CA40122B9EEDD03317FFF5E2` | **BIT-IDENTICAL** (Untouched) |
| **Exported Authoritative ONNX** (`D:\ethio_ai_defender_artifacts\...\model.onnx`) | *New Artifact* | `AB09494D6CB753D089FB978ECA8DEF6CBDEC0190BBE63740641B4A7A4B62FF38` | **VALIDATED** |
| **Exported Secondary ONNX** ([`storage/models/.../model.onnx`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/models/ember_baseline_v1/model.onnx)) | *New Artifact* | `F43B2D4F915D9467CBB306E58BEE59F8B80EE5CD9108259930A6E0CCE0A0A232` | **VALIDATED** |

- **`ML_ENABLED=false` Default:** Enforced in [`app/core/config.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/core/config.py).
- **ML Parity Gate:** Closed (`is_reliable=False`) in [`app/ml/classifier.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/classifier.py).
- **Zero Live Detonation:** Verified across all ingestion, feature extraction, and disassembler scripts.
- **Git Working Tree:** No resets or cleans executed; no files committed.

---

## 6. Release Verification Conclusion

The codebase demonstrates:
1. **Zero Test Regressions:** 761/761 tests passing with zero failures.
2. **Defensive Safety Invariants Maintained:** Autonomous ML-only quarantine is strictly prohibited; uncorroborated alerts require analyst confirmation under ML-13.
3. **Substantial Model Optimization:** Raw forward-pass latency improved by ~150x with strict mathematical parity ($\max |\Delta| = 3.08 \times 10^{-7}$).
4. **Transparent Governance:** Docker daemon absence and 2024–2026 modern corpus absence are formally registered as blockers rather than fabricated.

**Final Release Status: ACCEPT WITH EXPLICIT LIMITATIONS (Controlled Analyst-Assisted Evaluation).**
