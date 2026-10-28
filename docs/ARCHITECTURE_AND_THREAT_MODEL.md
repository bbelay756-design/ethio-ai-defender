# ETHIO-AI DEFENDER — SYSTEM ARCHITECTURE & THREAT MODEL

**Classification:** Technical Documentation (DOC-01)  
**Platform Version:** 1.0.0 (Hardened Production Baseline)  
**Author:** Antigravity Engineering Pair

---

## 1. System Architecture Overview

ETHIO-AI Defender is structured as a defensive, multi-layer static malware analysis and reverse-engineering pipeline with strict physical and process-level isolation boundaries.

### 1.1 Architectural Flow

```mermaid
flowchart TD
    Client["Client Browser / REST API Client"] -->|HTTPS / JWT Auth| FastAPI["FastAPI Gateway (Uvicorn)"]
    FastAPI --> Middleware["BodySizeLimitMiddleware (51MB Limit)"]
    Middleware --> Auth["RBAC & Session Validator (ADMIN, ANALYST, VIEWER)"]
    Auth --> Intake["Module 01: Secure File Intake & Quarantine"]
    
    subgraph Passive Static Pipeline ["Passive Static Pipeline (Zero-Execution Boundary)"]
        Intake --> Hashes["Module 02: Streaming Cryptographic Hashes (SHA-256/1, MD5)"]
        Hashes --> PEParser["Module 03-05: PE Headers, Sections, & Shannon Entropy"]
        PEParser --> Strings["Module 06: String Intelligence (ASCII / UTF-16 Regex)"]
        Strings --> Imports["Module 07: Windows API Categorization (IAT)"]
        Imports --> Indicators["Module 08: Suspicious Indicator Rules"]
        Indicators --> YARA["Module 02B: Versioned YARA Engine (yara-python)"]
        YARA --> ThreatScore["Module 09: Heuristic Threat Scorer (0-100)"]
    end

    subgraph Isolated Worker Boundary ["Isolated Process Worker Boundary"]
        Intake -.->|Read Quarantined Bytes| MLWorker["app/ml/process_worker.py (Spawn Worker)"]
        MLWorker -->|EMBER 2381-dim Vector| GBDT["LightGBM / GBDT Baseline Classifier"]
        GBDT -->|Calibrated Prob + Latency| IPC["Defensive IPC Pipe (Wall-Clock Timeout: 10s)"]
    end

    IPC -.->|Non-Authoritative Telemetry| Orchestrator["Unified Pipeline Orchestrator"]
    ThreatScore --> Orchestrator
    
    subgraph Optional Integrations ["Optional & Degraded Integrations"]
        Orchestrator -.-> Ghidra["Module 20: Ghidra Headless RE (Status: UNAVAILABLE)"]
        Orchestrator -.-> AI["Module 11: AI Security Analyst (Grounded Explanation)"]
    end

    Orchestrator --> DB[("Relational SQLite Persistence (defender.db)")]
    Orchestrator --> Audit["Audit Logger (audit.jsonl)"]
    Orchestrator --> Reports["Report Generator (HTML, JSON, Markdown, Text)"]
```

---

## 2. Process Isolation & Wall-Clock Timeout Sequence

To guarantee that untrusted, potentially malformed PE files or native C extensions cannot hang or compromise the main web server, ML feature extraction and inference operate in an isolated spawned worker process.

```mermaid
sequenceDiagram
    autonumber
    participant Orch as Pipeline Orchestrator
    participant Worker as MLProcessWorker (Spawned)
    participant Model as GBDT Model Artifact

    Orch->>Worker: IPC Request (quarantined_path, deadline_seconds)
    activate Worker
    Note over Worker: Worker extracts EMBER 2,381 features<br/>Passive read only - zero execution
    Worker->>Model: predict_proba(X)
    Model-->>Worker: raw_prob = 0.052

    alt Completed within Deadline (e.g. 38 ms)
        Worker-->>Orch: IPC Response { status: "SUCCESS", calibrated_prob: 0.052, latency_ms: 38.0 }
    else Exceeded Wall-Clock Deadline (Timeout)
        Orch->>Worker: terminate() / Win32 TerminateProcess
        deactivate Worker
        Orch->>Orch: Set status="TIMEOUT", return fallback
        Orch->>Worker: Spawn fresh recycled worker
    end
    
    Note over Orch: ML output recorded as telemetry only.<br/>Parity gate is CLOSED. Heuristic verdict unaffected.
```

---

## 3. STRIDE Threat Model & Defensive Controls

| Threat Category | Threat Description | Platform Defensive Mitigation |
|---|---|---|
| **Spoofing** | Adversary attempts to forge user identity or spoof administrative requests. | PBKDF2-HMAC-SHA256 password hashing with independent per-user salt; signed HMAC-SHA256 JWT access tokens with unique JTI; instant session revocation on logout; `token_version` tracking invalidating stale tokens upon password reset or role alteration (`SEC-06`). |
| **Tampering** | Adversary attempts to tamper with stored rules, model artifacts, or quarantine files. | 1. **Model Artifacts:** Authoritative SHA-256 fingerprint verified against hardcoded `TRUSTED_BASELINE_MODEL_SHA256` prior to model instantiation.<br/>2. **YARA Rules:** Immutable versioning schema with SHA-256 source hashing. `RESTRICT` foreign key integrity prevents deletion of referenced historical rules.<br/>3. **Quarantine:** Stored in restricted permissions directory `storage/quarantine` with random UUID naming. |
| **Repudiation** | User denies uploading a file, publishing a rule, or exporting reports. | Append-only structured JSON security audit logger (`AuditLogger`) recording actor ID, IP address, timestamp, event type, and parameters. Audit events emitted for login, logout, file upload, rule publication, and report generation. |
| **Information Disclosure** | Sensitive server paths, tokens, or malicious sample payloads leaked to third parties. | 1. Internal absolute paths systematically scrubbed (`[REDACTED_PATH]/`).<br/>2. Raw binary byte streams and executable payloads never forwarded to external AI providers or logs.<br/>3. Redaction filters in audit logging scrub passwords, salts, tokens, and authorization headers.<br/>4. Object-level authorization (IDOR protection) ensures analysts only access authorized samples. |
| **Denial of Service** | Oversized payloads, parser bombs, or hung inference worker exhaust server resources. | 1. `BodySizeLimitMiddleware` rejects oversized bodies (>51MB) prior to multipart parsing.<br/>2. Native parsing and inference bounded by strict wall-clock timeout (`ML_TIMEOUT_SECONDS`, default 10s) with unconditional process termination (`TerminateProcess`).<br/>3. Memory safety verified: LightGBM training sub-sampled to 80k rows, worker recycling after 500 tasks, peak RAM < 120 MiB.<br/>4. Sliding window rate limiter for login and upload endpoints. |
| **Elevation of Privilege** | Attacker attempts to escalate from VIEWER to ANALYST or ADMIN. | 1. Strict three-tier RBAC (`ADMIN`, `ANALYST`, `VIEWER`).<br/>2. `SELF_REGISTRATION_ROLES` defaults to `VIEWER`; `ADMIN` role can never be self-assigned.<br/>3. All sensitive administration and publication routes enforce `has_permission()` checks in FastAPI dependencies. |

---

## 4. Fundamental Platform Invariants

1. **Zero Live Execution Guarantee:**
   Untrusted sample binaries are treated strictly as passive, immutable byte arrays for static structural inspection. Under no operational state or configuration are samples executed, mapped with write-and-execute permissions, or detonated.
2. **Closed Parity Gate & Non-Authoritative ML:**
   While the Parity Gate remains in state `OFFLINE_TEST_UNVERIFIED_PARITY`, machine learning scores are strictly experimental telemetry. ML models have **zero authority** over malicious verdicts, heuristic risk scores, alerts, or quarantine actions. Deterministic evidence and heuristic rules retain absolute authority.
3. **Graceful Fault Isolation:**
   Failure or timeout in any optional analysis stage (Ghidra, ML inference, cloud AI reasoning) degrades safely with structured status reporting (`UNAVAILABLE`, `TIMEOUT`, `FAILED`) without crashing or interrupting the primary static analysis pipeline.
