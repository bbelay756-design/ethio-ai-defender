# ETHIO-AI DEFENDER — KNOWN LIMITATIONS AND SECURITY GATES

**Document ID:** DOC-SEC-GATES-01  
**Target Release:** Release-04 Stabilization / Handover  
**Scope:** Machine Learning Reliability Gates, Environmental Constraints, and Security Invariants  
**Date:** October 29, 2026  

---

## 1. Machine Learning Safety Architecture & Invariants

ETHIO-AI Defender deploys an EMBER-v2 gradient-boosted decision tree baseline (`ember-baseline-hgb`, 2,381 feature dimensions) for static PE malware triage. To prevent autonomous operational harm, denial-of-service, or false-positive disruption in enterprise networks, the following architectural invariants are hardcoded and non-bypassable:

### 1.1 Hardcoded Reliability & Blocking Gates
Throughout the analysis pipeline ([app/pipeline/orchestrator.py](file:///C:/Users/MILKWAY/ethio-ai-defender/app/pipeline/orchestrator.py)) and ML analyzer ([app/analyzers/ml_analyzer.py](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ml_analyzer.py)), all ML outputs enforce:

```python
ml_data["is_reliable"] = False
ml_data["advisory_only"] = True
ml_data["active_blocking_inhibited"] = True  # Always inhibited for ML alone
```

- **`is_reliable = False`:** Explicitly communicates to downstream API consumers, SIEMs, and orchestration pipelines that the score is a statistical heuristic, not an authoritative detection verdict.
- **`advisory_only = True`:** ML scores serve exclusively to sort analyst triage queues (`NORMAL` vs `ELEVATED` review priority) and are never used as standalone blocking criteria.
- **`active_blocking_inhibited = True`:** Autonomous network disconnection, process termination, or file quarantine based solely on an ML score is structurally disabled at the code level.

### 1.2 The ML-13 Cascaded Rejection Gate
In an enterprise environment where malware prevalence is low (e.g., $1\%$ base rate), even a classifier with a nominal $1\%$ False Positive Rate experiences severe base-rate precision collapse:

$$\text{Precision} = \frac{\text{TPR} \times \text{Prevalence}}{(\text{TPR} \times \text{Prevalence}) + (\text{FPR} \times (1 - \text{Prevalence}))} \approx \frac{0.80 \times 0.01}{(0.80 \times 0.01) + (0.01 \times 0.99)} \approx 44.7\%$$

Under realistic enterprise traffic distributions (e.g., $0.1\%$ prevalence), precision collapses to **$3.73\%$**—meaning more than 96 out of 100 autonomous blocks would impact legitimate business software.

To solve this, the **ML-13 Cascaded Rejection Gate** enforces:
1. **Deterministic Indicators Rule:** If deterministic evidence is present (YARA rule match > 0 or Heuristic Threat Score $\ge 70$), deterministic detection governs.
2. **Uncorroborated High ML Score:** If an ML score exceeds the target threshold ($\tau \ge 0.800395$) without deterministic corroboration, the case is transitioned to `rejection_gate_state = "PENDING_REVIEW"` and `requires_analyst_review = True`. Autonomous blocking is strictly inhibited until a human analyst confirms the verdict.

---

## 2. Model Cryptographic Verification & Artifact Invariants

### 2.1 Cryptographic Digest Allowlist
The model loader ([app/ml/classifier.py](file:///C:/Users/MILKWAY/ethio-ai-defender/app/ml/classifier.py)) validates serialized artifacts against hardcoded SHA-256 digests prior to deserialization:

| Model Role | Storage Location | Artifact Format | Expected SHA-256 Checksum | Validation Rule |
| :--- | :--- | :---: | :--- | :--- |
| **Primary Model** | `D:\ethio_ai_defender_artifacts\ember_baseline_v1\` | `model.joblib` | `f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684` | Authoritative verified training artifact |
| **Primary ONNX** | `D:\ethio_ai_defender_artifacts\ember_baseline_v1\` | `model.onnx` | `ab09494d6cb753d089fb978eca8def6cbdec0190bbe63740641b4a7a4b62ff38` | Accelerated forward pass artifact |
| **Secondary Model** | `storage/models/ember_baseline_v1/` | `model.joblib` | `baf625e1787c6e3b6e2648caea2020435a95f077c53a1d5b52d1087efb25e59b` | In-repo fallback artifact |
| **Secondary ONNX** | `storage/models/ember_baseline_v1/` | `model.onnx` | `f43b2d4f915d9467cbb306e58bee59f8b80ee5cd9108259930a6e0cce0a0a232` | In-repo accelerated fallback |

### 2.2 Fail-Closed Deserialization Policy
If a model artifact is missing, unverified, or exhibits any byte drift:
- The classifier immediately raises `EmberModelError`.
- It does **NOT** fall back to unverified artifacts.
- Analysis pipeline execution continues safely without ML (`status = "DISABLED"` or `"FAILED"`), ensuring core static analysis remains operational.

---

## 3. Known Environmental & Analytical Limitations

### 3.1 Unresolved LIEF Compatibility Divergence (`LIM-LIEF`)
- **Limitation Description:** The platform utilizes modern `lief` 1.0.0 (`1.0.0-d05b3499b` on Python 3.14). The original EMBER 2018 feature extraction scripts were authored against legacy LIEF 0.11/0.12, which exposed different exception hierarchies and section attribute models.
- **Current State:** The upstream test suite (`tests/ml/test_upstream_reference_parity.py`) successfully passes 20/20 tests via in-memory compatibility shims (`_compat_transform`). However, invoking raw external extraction scripts without shims will encounter LIEF attribute mismatches.
- **Remediation Policy:** Upstream dependencies were intentionally preserved without pinning to unmaintained legacy libraries, maintaining Python 3.14 runtime stability.

### 3.2 Continuous Test Runner Benchmark Timing Variance (`LIM-PERF`)
- **Limitation Description:** The pipeline performance benchmark in [tests/test_module_19_final_integration.py](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/test_module_19_final_integration.py) asserts that full static analysis executes in $< 1500\text{ ms}$:
  ```python
  self.assertLess(t_total, 1500.0, f"Analysis pipeline exceeded 1500ms threshold: {t_total:.2f}ms")
  ```
- **Observed Behavior:**
  - **Standalone Run:** Consistently executes in **580 ms to 920 ms** and **PASSES** cleanly.
  - **Continuous 760+ Test Run:** Under extended continuous full-suite execution, CPU thermal throttling, memory accumulation, and pytest runner overhead cause execution to take **1,629 ms to 1,776 ms**, failing the strict 1,500 ms assertion by ~129–276 ms.
- **Classification:** CI benchmark timing sensitivity under heavy multi-threaded test saturation; not a production latency regression. Recommended roadmap action: calibrate assertion threshold to 2,000 ms in CI environments.

### 3.3 Absence of Representative Ethiopian Enterprise Validation Corpus (`LIM-CORPUS`)
- **Limitation Description:** The baseline model was trained and evaluated against global benchmarks (EMBER 2018).
- **Impact:** No verified corpus of contemporary 2024–2026 PE malware or authentic Ethiopian government, banking, and enterprise administrative binaries was available in the repository. The model's empirical false-positive rate on local Amharic-localized or regional business applications remains uncharacterized.
- **Mitigation:** The model must remain strictly in non-blocking advisory mode until local calibration is performed.

### 3.4 Ghidra Headless Analyzer Availability (`LIM-GHIDRA`)
- **Limitation Description:** Ghidra reverse-engineering requires either a local installation (`GHIDRA_HOME`) or the containerized Ghidra Sidecar service (`GHIDRA_SIDECAR_ENABLED=true`).
- **Current State:** In host environments without an active Docker daemon or extracted Ghidra binaries, the platform gracefully degrades and reports Ghidra analysis as `status = "UNAVAILABLE"`. Core static analysis (PE parsing, YARA, IOCs, ML) continues without disruption.

---

## 4. Security Findings & API Authorization Gaps

The security audit identified five API-level defects requiring remediation prior to exposing REST endpoints to untrusted or multi-tenant networks:

| ID | Severity | Category | Description | Workaround / Mitigation |
| :--- | :---: | :--- | :--- | :--- |
| **SEC-04-01** | **HIGH** | Authorization (BOLA) | Anonymous callers can query `GET /api/analyses` and retrieve historical analysis details. | Restrict platform network access to trusted analysts via reverse proxy / firewall. |
| **SEC-04-02** | **HIGH** | Privilege Escalation | Unprivileged `VIEWER` users can delete analyst notes or update case priority/status. | Enforce analyst-only roles; restrict viewer accounts to trusted internal evaluators. |
| **SEC-04-03** | **MEDIUM** | Stored XSS | Server-side HTML report generation (`GET /api/analyses/{id}/report?format=html`) formats attacker-controlled PE strings without `html.escape()`. | View analyses exclusively through the SPA dashboard ([frontend/static/js/app.js](file:///C:/Users/MILKWAY/ethio-ai-defender/frontend/static/js/app.js)), which strictly escapes all dynamic content. |
| **SEC-04-04** | **MEDIUM** | Data Concurrency | Missing database unique constraint on `analyst_reviews.analysis_id` allows race conditions during concurrent review submissions. | Enforce sequential analyst workflow; avoid concurrent triage submissions on the same sample. |
| **SEC-04-05** | **LOW** | Information Disclosure | `GET /api/files/{analysis_id}` exposes sample filename and hashes without session verification. | Network perimeter access control. |
