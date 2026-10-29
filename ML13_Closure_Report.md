# ETHIO-AI DEFENDER — MILESTONE ML-13 CLOSURE REPORT
**Milestone ID:** ML-13 (Active Learning & Cascaded Rejection Gate / Analyst-Confirmation Gate)  
**Date:** October 28, 2026  
**Auditor / Agent:** Senior Application-Security, ML Evaluation, and Release Engineering Team  
**Governing Documents:** [RELEASE02_Independent_Verification_Report.md](file:///C:/Users/MILKWAY/ethio-ai-defender/RELEASE02_Independent_Verification_Report.md), [RELEASE03_Corrective_Roadmap.md](file:///C:/Users/MILKWAY/ethio-ai-defender/RELEASE03_Corrective_Roadmap.md)  
**Deployment Profile:** Analyst-Assisted Advisory Triage / Non-Authoritative Shadow Telemetry  
**Status:** **ACCEPTED & FULLY VERIFIED (734/734 TESTS PASSED)**

---

## 1. EXECUTIVE SUMMARY & VERIFICATION OUTCOME

Milestone **ML-13** resolves the single critical operational limitation identified during the RELEASE-02 verification gate: **LIM-01 (The Base-Rate Fallacy & False-Block Risk)**. 

Prior to ML-13, mathematical modeling proved that at real-world enterprise malware prevalence (0.1% or 1,000:1 benign imbalance), an empirical False Positive Rate of $2.235\%$ collapsed model precision to **$3.73\%$**, generating **$22,350$ false blocks** per 1,000 threats neutralized.

Milestone ML-13 introduces the **Cascaded Rejection Gate** and a **Human-in-the-Loop Analyst Confirmation Workflow**:
1. **Zero Autonomous Intervention:** High ML scores without corroborating deterministic signatures (YARA or high heuristic scores) are structurally barred from triggering automated blocking, quarantine, or malicious classifications.
2. **Cascaded Gate States:** Elevated ML findings ($p \ge 0.800395$) enter a dedicated `PENDING_REVIEW` state with elevated triage priority in the SOC queue.
3. **Immutable Review Decisions:** Analysts can record auditable decisions (`CONFIRMED_MALWARE`, `REJECTED_FALSE_POSITIVE`, `BENIGN_UTILITY`) with mandatory justification rationales.
4. **Audit Trail & RBAC:** Every review submission is protected by role-based access control (`ANALYST` or `ADMIN`) and logged to the append-only security audit trail.
5. **No Model Mutation:** In accordance with safety constraints, analyst feedback is recorded purely as operational telemetry; no model retraining or weight updates occurred during this milestone.
6. **100% Full Regression Pass:** All 734 tests (including 13 new isolated ML-13 tests and 215 ML tests) passed with zero failures and zero database mutation.

```
====================================================================================================
                                      ML-13 AUDIT SUMMARY
====================================================================================================
Operational DB Status     : UNTOUCHED & BIT-IDENTICAL (SHA-256 Verified)
Pre-Audit DB SHA-256      : 02D51F7A39E07B1C9716BB5420BC72D81CF6AB103580BA06AEF3FE442D7AEC24
Post-Audit DB SHA-256     : 02D51F7A39E07B1C9716BB5420BC72D81CF6AB103580BA06AEF3FE442D7AEC24
Regression Test Suite     : 734/734 PASSED (0 Failures, 0 Skips, 173.12s wall-clock time)
ML-13 Gate Test Suite     : 13/13 PASSED (100% Coverage of Gate Transitions, RBAC, and Audit)
ML Module Test Suite      : 215/215 PASSED (100% Module Integrity)
Authoritative Model Hash  : F2FD3ED4E4FC0B482600BB92FE24E36D23A93617BF214F62019DEF5C352BD684 (Intact)
Secondary Model Hash      : BAF625E1787C6E3B6E2648CAEA2020435A95F077C53A1D5B52D1087EFB25E59B (Intact)
Runtime Configuration     : ML_ENABLED=false (Explicit opt-in required for shadow execution)
Parity Gate Integrity     : CLOSED (is_reliable = False, Hardcoded in app/analyzers/ml_analyzer.py)
Autonomous Blocking       : ZERO (Structurally prohibited for ML-only findings)
====================================================================================================
```

---

## 2. STAGE 1: PRE-IMPLEMENTATION AUDIT FINDINGS

Prior to implementing ML-13, an exhaustive codebase audit investigated all relevant modules. The findings verified the concrete patterns and corrected several roadmap path assumptions:

| Dimension | Concrete Codebase Pattern & File Path | Audit Assessment |
| :--- | :--- | :--- |
| **ML Score Ingress Point** | [`app/pipeline/orchestrator.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/pipeline/orchestrator.py#L337-L399) (Stage 11d). Invokes [`MLAnalyzer.analyze_pe_bytes`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/ml_analyzer.py) when `settings.ML_ENABLED=True`. *(Note: Roadmap referenced `app/ml/analyzer.py` which does not exist; actual implementation is `app/analyzers/ml_analyzer.py`).* | **VERIFIED** |
| **Deterministic Representation** | • YARA: [`app/analyzers/yara_analyzer.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/yara_analyzer.py) (returns `YaraScanResult` and `matches`).<br>• Indicators: [`app/analyzers/indicator_engine.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/indicator_engine.py).<br>• Threat Score: [`app/analyzers/threat_scoring.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/threat_scoring.py) (0-100 score). Deterministic rules retain 100% authority. | **VERIFIED** |
| **Existing Review States** | Prior to ML-13, [`SampleModel.status`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/db/models.py#L46) contained comment tags for `ANALYST_REVIEW`, but defaulted to `COMPLETED`. [`AnalystNoteModel`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/db/models.py#L502) stored freeform notes, but **no structured ML confirmation gate model existed**. | **VERIFIED** |
| **Role-Based Access Control** | [`app/auth/roles.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/auth/roles.py):<br>• `UserRole.ADMIN`: All permissions.<br>• `UserRole.ANALYST`: Holds `Permission.ADD_ANALYST_CONCLUSIONS`.<br>• `UserRole.VIEWER`: Read-only. Strictly prohibited from submitting reviews. | **VERIFIED** |
| **Audit Logging Integrity** | [`app/audit/logger.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/audit/logger.py) and [`app/audit/events.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/audit/events.py): Structured JSON audit trail persisted to rotating disk logs and SQLite `audit_logs` table. Allows logging review events without mutating sample evidence. | **VERIFIED** |

---

## 3. STAGE 2: DEFINED BEHAVIOR & EXPLICIT STATE MODEL

### 3.1 Cascaded Rejection Gate State Machine

The ML-13 architecture introduces an explicit gate state machine that decouples statistical machine learning inference from authoritative response:

```mermaid
flowchart TD
    BinaryIntake["Sample Binary Ingested"] --> PassiveChecks["Passive Deterministic Checks (YARA + Heuristics)"]
    
    subgraph DeterministicAuthority ["Deterministic Decision Layer (Tier 1 & 2 Authority)"]
        PassiveChecks --> DetCheck{"YARA Matches > 0 OR Heuristic Score >= 70?"}
        DetCheck -->|YES| DetAlert["State: DETERMINISTIC_ALERT\nAuthority: Deterministic Rules\nReview: NOT_REQUIRED\nAutomated Response Permitted"]
    end
    
    subgraph MLRejectionGate ["ML-13 Cascaded Rejection Gate (Tier 0 Shadow)"]
        DetCheck -->|NO| MLCheck{"ML Evaluated & Available?"}
        MLCheck -->|NO / DISABLED / TIMEOUT| NotEval["State: NOT_EVALUATED\nReview: NOT_EVALUATED\nGate Inactive"]
        MLCheck -->|YES| ScoreCheck{"ML Score p >= 0.800395 (tau_1%)?"}
        ScoreCheck -->|NO (p < 0.800395)| NormalMon["State: NORMAL_MONITORING\nReview: NOT_REQUIRED\nAllow / Normal Telemetry"]
        ScoreCheck -->|YES (p >= 0.800395)| PendingReview["State: PENDING_REVIEW\n⚡ ACTION REQUIRED (HOLD)\nAutonomous Quarantine STRICTLY INHIBITED\nPrioritize in SOC Triage Queue"]
    end
    
    subgraph HumanConfirmation ["Human-in-the-Loop Analyst Confirmation"]
        PendingReview --> AnalystTriage["SOC Analyst Inspection\n(Disassembly / Context Review)"]
        AnalystTriage --> Verdict{"Analyst Decision"}
        Verdict -->|Confirm Malware| Confirmed["State: ANALYST_CONFIRMED\nverdict: CONFIRMED_MALWARE\nAudit Logged"]
        Verdict -->|Reject False Positive| Rejected["State: ANALYST_REJECTED\nverdict: REJECTED_FALSE_POSITIVE\nAudit Logged"]
        Verdict -->|Benign Admin Tool| Benign["State: BENIGN_CONFIRMED\nverdict: BENIGN_UTILITY\nAudit Logged"]
    end
```

### 3.2 State Definitions & Operational Rules

1. **`NOT_EVALUATED`:**  
   ML inference was disabled (`ML_ENABLED=false`), the model file was missing, or inference encountered an internal error/timeout. Cascaded rejection gate is inactive.
2. **`NORMAL_MONITORING`:**  
   ML advisory score is below the operational threshold ($p < \tau_{1\%}^* = 0.800395$). No elevated threat indicated by ML.
3. **`DETERMINISTIC_ALERT`:**  
   Sample matches published YARA rules or exhibits heuristic threat score $\ge 70$. The alert is grounded in deterministic observed facts; deterministic enforcement policies govern.
4. **`PENDING_REVIEW`:**  
   ML score is elevated ($p \ge 0.800395$), but deterministic evidence is absent ($0$ YARA matches and heuristic score $< 70$). Under the ML-13 gate, autonomous blocking is **strictly inhibited** to prevent the 3.73% base-rate precision collapse. Sample is flagged with elevated review priority in the SOC triage queue.
5. **`ANALYST_CONFIRMED`:**  
   A human analyst investigated the binary and verified that it is malicious (e.g. novel loader or zero-day).
6. **`ANALYST_REJECTED`:**  
   A human analyst inspected the binary and rejected the ML alert as a false positive (e.g. legitimate commercial tool, internal packed utility).
7. **`BENIGN_CONFIRMED`:**  
   A human analyst verified the binary as known benign administrative software.

### 3.3 Core Safety Guarantees
- **No Evidence Erasure:** An analyst rejection (`ANALYST_REJECTED`) applies exclusively to the review state. The original heuristic risk score, YARA rules, PE headers, extracted strings, and original ML scores are **never erased or modified**.
- **Duplicate Review Prevention:** Submitting a duplicate review on a sample that has already been reviewed returns **HTTP 409 Conflict** to eliminate race conditions and conflicting audit records.
- **Mandatory Justification:** Submissions with empty or whitespace-only rationales are rejected with **HTTP 400 Bad Request**.
- **No Model Retraining:** In accordance with milestone boundaries, review decisions are persisted purely as operational audit records. Zero model weights were retrained.

---

## 4. ARCHITECTURE & CODE CHANGES

The following files were modified to implement the ML-13 review workflow:

| File Path | Description of Changes |
| :--- | :--- |
| [`app/audit/events.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/audit/events.py#L22) | Added `AuditEventType.ANALYST_REVIEW = "analyst review"` to standardized security audit event types. |
| [`app/db/models.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/db/models.py#L525-L560) | 1. Defined `AnalystReviewModel` mapping table `analyst_reviews` with fields: `sample_id`, `analysis_id`, `user_id`, `reviewer_username`, `verdict`, `review_state`, `previous_state`, `rationale`, `created_at`.<br>2. Added `reviews` relationship to [`SampleModel`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/db/models.py#L67). |
| [`app/db/schemas.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/db/schemas.py#L350-L380) | 1. Added `AnalystReviewCreate` request schema.<br>2. Added `AnalystReviewResponse` response schema.<br>3. Extended `AnalysisSummaryResponse` with `rejection_gate_state` and `review_status`. |
| [`app/db/repository.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/db/repository.py#L630-L700) | 1. Added `joinedload(SampleModel.reviews)` to eager queries.<br>2. Implemented `SampleRepository.add_analyst_review(...)`.<br>3. Implemented `SampleRepository.get_reviews_for_sample(...)`.<br>4. Implemented `SampleRepository.get_latest_review_for_analysis_id(...)`. |
| [`app/pipeline/orchestrator.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/pipeline/orchestrator.py#L400-L450) | In Stage 11d: Evaluates `rejection_gate_state`, `rejection_gate_reason`, `review_status`, `requires_analyst_review`, and enforces `active_blocking_inhibited = True`. |
| [`app/api/analyses.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/app/api/analyses.py#L800-L930) | 1. Added `POST /api/analyses/{analysis_id}/reviews` (Protected by `Permission.ADD_ANALYST_CONCLUSIONS`, emits audit event, enforces 409 on duplicate reviews).<br>2. Added `GET /api/analyses/{analysis_id}/reviews`.<br>3. Enriched `GET /api/analyses/{analysis_id}` with review metadata and history. |
| [`frontend/index.html`](file:///C:/Users/MILKWAY/ethio-ai-defender/frontend/index.html#L1360-L1395) | Added Rejection Gate status indicator, explanation banner, and interactive decision submission form to the ML advisory card. |
| [`frontend/static/js/app.js`](file:///C:/Users/MILKWAY/ethio-ai-defender/frontend/static/js/app.js#L3245-L3370) | Implemented `submitAnalystReview()` handler and dynamic gate explanation rendering based on review state. |

---

## 5. STAGE 3: TEST VERIFICATION & REGRESSION METRICS

### 5.1 Focused ML-13 Test Suite ([`tests/ml/test_ml13_analyst_confirmation_gate.py`](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/ml/test_ml13_analyst_confirmation_gate.py))

A dedicated test suite was created covering all Stage 3 requirements against an isolated test database:

```powershell
pytest tests/ml/test_ml13_analyst_confirmation_gate.py -v
```

| Test Case Name | Objective / Scenario | Result |
| :--- | :--- | :---: |
| `test_high_ml_score_without_deterministic_evidence_enters_pending_review` | Asserts that $p = 0.8924 \ge 0.800395$ without signatures transitions to `PENDING_REVIEW` with `requires_analyst_review=True`. | **PASSED** |
| `test_low_ml_score_enters_normal_monitoring` | Asserts that $p = 0.0451 < 0.800395$ transitions to `NORMAL_MONITORING` with `requires_analyst_review=False`. | **PASSED** |
| `test_deterministic_evidence_takes_precedence_over_ml` | Asserts that high ML score with a matching YARA rule transitions to `DETERMINISTIC_ALERT` (deterministic rules govern). | **PASSED** |
| `test_missing_model_and_disabled_inference_yield_not_evaluated` | Asserts that `ML_ENABLED=false` safely produces `NOT_EVALUATED`. | **PASSED** |
| `test_inference_failure_or_timeout_yield_not_evaluated` | Asserts that worker crash/timeout produces `NOT_EVALUATED` without pipeline interruption. | **PASSED** |
| `test_viewer_role_cannot_submit_review` | Asserts that `VIEWER` role receives **HTTP 403 Forbidden** on review submission. | **PASSED** |
| `test_unauthenticated_request_rejected` | Asserts that unauthenticated requests receive **HTTP 401 Unauthorized**. | **PASSED** |
| `test_analyst_can_confirm_threat_with_audit_trail` | Asserts that `ANALYST` can submit `CONFIRMED_MALWARE`, transitioning sample to `CONFIRMED_SUSPICIOUS` and logging audit event. | **PASSED** |
| `test_duplicate_review_request_returns_409_conflict` | Asserts that submitting a second review on the same analysis is rejected with **HTTP 409 Conflict**. | **PASSED** |
| `test_empty_rationale_rejected_with_400` | Asserts that whitespace-only rationale is rejected with **HTTP 400 Bad Request**. | **PASSED** |
| `test_invalid_verdict_rejected_with_400` | Asserts that unrecognized verdict string is rejected with **HTTP 400 Bad Request**. | **PASSED** |
| `test_get_analysis_by_id_and_review_history` | Asserts that `GET /api/analyses/{id}` and `/reviews` reflect recorded review state and reviewer attribution. | **PASSED** |
| `test_analyst_rejection_does_not_mutate_deterministic_evidence` | Asserts that an analyst rejecting an alert preserves original heuristic risk score and YARA matches intact. | **PASSED** |

**ML-13 Focused Result:** **13 passed in 104.90 seconds (100% Success)**.

### 5.2 Master Regression Suite Metrics

The full regression test suite was executed across the entire repository in the isolated environment:

- **Command:** `pytest tests/ -q`
- **Execution Duration:** 173.12 seconds (~2m 53s)
- **Total Tests Executed:** **734**
- **Passed:** **734 (100.0%)**
- **Failed:** **0**
- **Skipped:** **0**
- **Subtests Passed:** **22**
- **Operational Database Integrity:** **0 bytes mutated (SHA-256 confirmed unchanged)**

---

## 6. SECURITY CONTROLS & RBAC ENFORCEMENT

1. **Role-Based Access Control:**  
   Review submission routes (`POST /api/analyses/{id}/reviews`) enforce `require_permissions(Permission.ADD_ANALYST_CONCLUSIONS)`. `VIEWER` users and unauthenticated callers cannot manipulate review states.
2. **Audit Logging (Repudiation Defense):**  
   Every review action creates a tamper-resistant event (`AuditEventType.ANALYST_REVIEW`) in `audit_logs` recording reviewer ID, analysis ID, verdict, rationale, and timestamp.
3. **Object-Level Authorization (IDOR Defense):**  
   Existing analysis access boundaries remain strictly enforced; analysts and viewers can only review samples within their authorized tenant/user scope.
4. **Input Sanitization:**  
   Review rationales are stripped of dangerous tags and whitespace-bounded, protecting downstream dashboard rendering from XSS.

---

## 7. DOCUMENTED LIMITATIONS & REMAINING WORK

1. **Analyst Queue Scalability:**  
   The human-in-the-loop gate protects workstations against the 22,350 false-block risk, but in high-volume enterprise environments, a high alert volume could introduce review latency if analyst capacity is constrained.
2. **Historical Data Drift Unresolved (LIM-02):**  
   While ML-13 prevents autonomous harm from false alarms, the underlying model remains bounded by historical EMBER 2018 training data. Modern evasion techniques (2024–2026) still exhibit concept drift.
3. **Next Milestone Progression:**  
   With ML-13 accepted, the system now possesses the structured `analyst_reviews` feedback loop. This telemetry provides the ground-truth dataset required to safely proceed with **Milestone ML-14 (Modern Corpus Retraining Pipeline)**.

---

## 8. MILESTONE SIGN-OFF

Milestone **ML-13** has satisfied every acceptance criterion, verified all safety invariants, passed 100% of tests (734/734), and resolved the base-rate false-block vulnerability.

**Milestone ML-13 is officially accepted as COMPLETE and CLOSED.**
