# ETHIO-AI Defender (የኢትዮ-ኤአይ መከላከያ)
**Defensive AI-Powered Malware Analysis & Reverse-Engineering Platform for Ethiopia**

[![Release](https://img.shields.io/badge/release-v0.4.0--stabilized-success.svg)](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/FINAL_RELEASE_READINESS_REPORT.md)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.12%20%7C%203.14-blue.svg)](file:///C:/Users/MILKWAY/ethio-ai-defender/requirements.txt)
[![Test Suite](https://img.shields.io/badge/tests-780%2B%20verified-brightgreen.svg)](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/FINAL_RELEASE_READINESS_REPORT.md)
[![Safety Invariant](https://img.shields.io/badge/safety-zero--execution-blue.svg)](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/file_intake.py)
[![ML Safety Gate](https://img.shields.io/badge/ML%20Gate-non--authoritative%20%7C%20shadow-orange.svg)](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/KNOWN_LIMITATIONS_AND_SECURITY_GATES.md)
[![Ghidra Sidecar](https://img.shields.io/badge/ghidra-v11.1%20sidecar-purple.svg)](file:///C:/Users/MILKWAY/ethio-ai-defender/docker-compose.yml)
[![Security Audited](https://img.shields.io/badge/security-SEC--08%20hardened-success.svg)](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/SEC08_Security_Remediation_Report.md)
[![Localization](https://img.shields.io/badge/locale-English%20%7C%20%E1%8A%A0%E1%88%9B%E1%88%AD%E1%8B%9B-orange.svg)](file:///C:/Users/MILKWAY/ethio-ai-defender/frontend/static/js/app.js)

---

## 📑 Table of Contents
1. [Executive Summary & Vision](#-1-executive-summary--vision)
2. [Core Architecture & End-to-End Pipeline](#-2-core-architecture--end-to-end-pipeline)
3. [Crucial Defensive Invariants & Safety Guarantees](#-3-crucial-defensive-invariants--safety-guarantees)
4. [Comprehensive Module Breakdown (Modules 01 - 22)](#-4-comprehensive-module-breakdown-modules-01---22)
5. [Database Baseline & Physical Isolation Strategy](#-5-database-baseline--physical-isolation-strategy)
6. [Unified Analysis Object Contract](#-6-unified-analysis-object-contract)
7. [Installation & Quick Start Guide](#-7-installation--quick-start-guide)
8. [Docker & Containerized Ghidra Sidecar](#-8-docker--containerized-ghidra-sidecar)
9. [Running Verification & Test Suites](#-9-running-verification--test-suites)
10. [REST API Reference & Role-Based Access Control](#-10-rest-api-reference--role-based-access-control)
11. [Dual-Language & Educational Capabilities](#-11-dual-language--educational-capabilities)
12. [Key Platform Documentation Sitemap](#-12-key-platform-documentation-sitemap)
13. [License & Ethical Disclaimer](#-13-license--ethical-disclaimer)

---

## 🛡️ 1. Executive Summary & Vision

**ETHIO-AI Defender (የኢትዮ-ኤአይ መከላከያ)** is a state-of-the-art defensive, educational, and operational cybersecurity platform tailored for national cyber resilience, Security Operations Centers (SOCs), Computer Emergency Response Teams (CERTs), and university reverse-engineering research laboratories in Ethiopia.

The platform provides **deterministic, zero-execution static analysis** of Windows Portable Executable (PE32 / PE32+) binaries (`.exe`, `.dll`) combined with:
- **Immutable YARA Pattern Matching** with cryptographic versioning and audit trails.
- **Containerized Ghidra Headless Reverse Engineering** via dedicated privilege-dropped sidecars.
- **Experimental Machine Learning Shadow Triage** (EMBER-v2 GBDT + ONNX acceleration) guarded by the **ML-13 Cascaded Rejection Gate**.
- **Human-in-the-Loop Analyst Confirmation Workflows** preventing autonomous blocking on uncorroborated statistical heuristics.
- **Privacy-Bounded Grounded AI Interpretations** (Google Gemini & offline rule fallbacks).
- **Interactive Dual-Language SOC Dashboard & Learning Labs** with native English and Amharic (አማርኛ) support.
- **SEC-08 Enterprise Security Hardening**: PBKDF2 password hashing, scoped JWTs, strict RBAC (`ADMIN`, `ANALYST`, `VIEWER`), XSS-immune report generation, and IDOR mitigation.

---

## 📐 2. Core Architecture & End-to-End Pipeline

```
                                      [ Analyst / API Request ]
                                                  ↓
                                        [ 1. Authentication ]
                                     (PBKDF2-HMAC / JWT / RBAC)
                                                  ↓
                                      [ 2. Secure File Intake ]
                               (50MB Limit, Path Sanitization, Whitelist)
                                                  ↓
                                      [ 3. File Validation ]
                                 (MZ / PE Magic Byte Verification)
                                                  ↓
                                    [ 4. Cryptographic Hashing ]
                                      (SHA-256, SHA-1, MD5)
                                                  ↓
                                     [ 5. PE Static Analysis ]
                               (DOS, NT, File & Optional Headers, Flags)
                                                  ↓
                                   [ 6. PE Section Inspection ]
                             (W+X Memory Flags, Slack Space, Permissions)
                                                  ↓
                                  [ 7. Shannon Entropy Engine ]
                               (Section & File Entropy 0.0 - 8.0)
                                                  ↓
                                   [ 8. Static String Engine ]
                             (ASCII & UTF-16: URLs, IPs, Registry, CMStore)
                                                  ↓
                                 [ 9. Windows API Import Engine ]
                             (IAT Categorization & Risk Capability Map)
                                                  ↓
                                [ 10. Suspicious Indicator Engine ]
                             (Multi-Feature Heuristic Threat Rules)
                                                  ↓
                                 [ 11. YARA Scanning Engine ]
                             (Versioned & Cached Cryptographic Rules)
                                                  ↓
                      +---------------------------+---------------------------+
                      ↓                                                       ↓
          [ 11b. Ghidra Headless RE ]                             [ 11c. ML Shadow Analysis ]
        (Containerized Sidecar / Host)                        (EMBER v2 GBDT / ONNX Runtime)
        (Isolated Decompilation & CFG)                        (Non-Authoritative Shadow Score)
                      ↓                                                       ↓
                      +---------------------------+---------------------------+
                                                  ↓
                                 [ 11d. ML-13 Rejection Gate ]
                           (Requires Corroboration / Analyst Gate)
                                                  ↓
                                  [ 12. Threat Scoring Engine ]
                                (0-100 Score & MITRE ATT&CK Matrix)
                                                  ↓
                               [ 13. Ethiopian Context Engine ]
                            (Domestic .et Infrastructure Triage)
                                                  ↓
                                [ 14. AI Security Analyst ]
                            (Privacy-Bounded Grounded Reasoning)
                                                  ↓
                                [ 15. Database Persistence ]
                            (Atomic Multi-Table Transaction Commit)
                                                  ↓
                                [ 16. Security Report Engine ]
                            (JSON / Markdown / Sanitized HTML / TXT)
                                                  ↓
                                 [ 17. Modern SOC Dashboard ]
                              (Responsive Dual-Language EN/AM UI)
```

---

## 🔒 3. Crucial Defensive Invariants & Safety Guarantees

### 1. Strict Static Analysis Only (Zero Live Execution)
* Uploaded binaries are strictly inspected in isolated byte arrays and quarantined on disk with restricted permissions.
* Binaries are **never executed**, spawned into processes, or passed to subshells.
* The platform contains zero offensive capability, exploitation primitives, or attack automation.

### 2. Three-Tier Evidence Separation
* **Tier 1: Observed Evidence**: Cryptographic hashes, raw PE headers, extracted strings, section virtual/raw sizes.
* **Tier 2: Rule-Based Indicators**: Deterministic heuristic correlations (e.g., W+X sections, memory allocation primitives, YARA signatures).
* **Tier 3: AI Interpretation**: Grounded natural-language summaries and defensive mitigation recommendations.
* **AI Invariant**: The AI layer cannot alter or override Tier 1 facts or Tier 2 deterministic verdicts.

### 3. Machine Learning Safety & The ML-13 Cascaded Rejection Gate
In enterprise networks where malware prevalence is low (e.g., $1\%$ base rate), even a high-performing classifier experiences severe **base-rate precision collapse**:

$$\text{Precision} = \frac{\text{TPR} \times \text{Prevalence}}{(\text{TPR} \times \text{Prevalence}) + (\text{FPR} \times (1 - \text{Prevalence}))} \approx \frac{0.80 \times 0.01}{(0.80 \times 0.01) + (0.01 \times 0.99)} \approx 44.7\%$$

At $0.1\%$ prevalence, precision drops to **$3.73\%$**, meaning over 96 out of 100 autonomous blocks would disrupt legitimate business software. 

To eliminate automated false-positive disruption, ETHIO-AI Defender enforces five hardcoded ML invariants:
1. **`is_reliable = False`**: Indicates to SIEMs and downstream tools that ML is a statistical heuristic, not an authoritative detection verdict.
2. **`advisory_only = True`**: ML output is used strictly to prioritize analyst triage queues.
3. **`active_blocking_inhibited = True`**: Autonomous endpoint blocking or quarantine based on ML alone is disabled at code level.
4. **Cascaded Rejection Gate**: When an ML score is elevated ($\tau \ge 0.800395$) without corroborating deterministic evidence (YARA match or Threat Score $\ge 70$), the case transitions to `PENDING_REVIEW` and requires human analyst sign-off before any action.
5. **Cryptographic Model Allowlist**: Models are validated against hardcoded SHA-256 digests (`f2fd3ed4...`) prior to deserialization. Modified or untrusted models are rejected immediately (*Fail-Closed*).

### 4. Privacy Boundary & Redaction
* Binary payloads, system paths (`C:\Users\...`), authorization tokens, and API credentials are automatically redacted before sending prompts to external LLM providers or audit logs.

### 5. Resilient Isolation & Fault Tolerance
* Every analyzer is wrapped in independent error boundaries. If an analyzer fails or encounters malformed bytes, the error is recorded in `errors: []` while all other analyzers continue executing safely.

---

## 📦 4. Comprehensive Module Breakdown (Modules 01 - 22)

| Module | Subsystem | Technical Highlights & Core Responsibility |
| :--- | :--- | :--- |
| **Module 01** | **Secure File Intake** | Enforces 50MB maximum ceiling, `.exe`/`.dll` whitelist, path traversal neutralization (`../../`), null-byte stripping, Windows device name defense (`CON`, `PRN`, `AUX`, `NUL`), and isolated staging. |
| **Module 02** | **Cryptographic Hashing** | Streamed cryptographic hashing computing SHA-256 (unique sample ID), SHA-1, and MD5 with instant deduplication check. |
| **Module 02B**| **YARA Scanning & Versioning** | Compiled C-extension YARA pattern matching (`yara-python`) with immutable rule versioning (`rule_version_id`), relational provenance, and atomic rollback. |
| **Module 03** | **PE Static Header Analyzer** | Parsing of DOS header, NT headers, COFF header, Optional Header, Subsystem, Machine Architecture (`x86`/`x64`), and compilation timestamp. |
| **Module 04** | **PE Section Analyzer** | Evaluation of virtual vs. raw section discrepancies, slack space analysis, and memory protection flag auditing (detecting dangerous W+X sections). |
| **Module 05** | **Shannon Entropy Engine** | Mathematical entropy calculation ($H(X) = -\sum p \log_2 p$) measuring byte distribution across sections (0.0 to 8.0) to flag packing, encryption, and obfuscation. |
| **Module 06** | **Static String Engine** | Regex extraction of ASCII and UTF-16LE strings identifying URLs, IPv4/IPv6 addresses, domains, registry persistence keys, and command strings. |
| **Module 07** | **Import / API Analyzer** | Import Address Table (IAT) parsing, mapping imported Windows DLL functions to risk capability domains (`MEMORY`, `PROCESS`, `INJECTION`, `NETWORK`, `EVASION`). |
| **Module 08** | **Indicator Engine** | Multi-feature heuristic rules engine correlating static traits into explainable threat indicators with confidence scores. |
| **Module 09** | **Threat Scoring Engine** | Heuristic mathematical scoring (0-100) assigning structured severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) mapped to MITRE ATT&CK tactics. |
| **Module 10** | **Ethiopian Context Engine** | Domestic sector priority classification (Government, Banking, Telecommunications, Healthcare, Academic) based on verified `.et` domains and critical infrastructure targets. |
| **Module 11** | **Grounded AI Security Analyst** | Multi-provider abstraction ([Google Gemini](file:///C:/Users/MILKWAY/ethio-ai-defender/app/core/config.py), Offline Rule-Based) with strict prompt grounding and hallucination checks. |
| **Module 12** | **Learning Center & Safe Labs** | Interactive educational lab breaking down reverse-engineering concepts in 5 structured stages in English and Amharic with synthetic safe demo binaries. |
| **Module 13** | **Security Report Generator** | Multi-format reporting (`JSON`, `Markdown`, `HTML`, `Plain Text`) with complete SEC-08 XSS escaping and institutional metadata customization. |
| **Module 14** | **Database Persistence** | Relational SQLite persistence via SQLAlchemy ORM, foreign-key cascade integrity, schema migrations via Alembic, and atomic multi-table commits. |
| **Module 15** | **Modern Web SOC Dashboard** | Responsive single-page dashboard with real-time analysis tabs, drag-and-drop intake, live preview frames, and instantaneous EN/AM localization. |
| **Module 16** | **Authentication & RBAC** | PBKDF2-HMAC password hashing, signed JWT tokens, token blacklisting on logout, account lockout after 5 failed attempts, and role gates (`ADMIN`, `ANALYST`, `VIEWER`). |
| **Module 17** | **Security Audit Logging** | Structured JSON audit logging for all authentication, analysis, report generation, and administrative actions with automated PII/token redaction. |
| **Module 18** | **Defensive Test Harness** | In-memory synthetic PE fixtures, fuzzing harnesses, SQL injection tests, XSS validation, and RBAC authorization verification. |
| **Module 19** | **Pipeline Orchestrator** | High-level coordinator executing all analyzers sequentially with isolated failure domains and unified object output. |
| **Module 20** | **Ghidra Headless RE** | Headless decompilation and function recovery via local Ghidra or containerized sidecar. Extracts functions, call graphs, imports, and decompiled code. |
| **Module 21** | **ML Static Shadow Analysis** | Bounded subprocess worker computing EMBER-v2 (2,381 feature dimensions) static extraction, GBDT inference, and ONNX Runtime acceleration under strict timeouts. |
| **Module 22** | **Analyst Confirmation Gate** | Human-in-the-loop review workflow (`POST /api/analyses/{id}/review`) resolving uncorroborated ML alerts and providing audit trails for SOC triage decisions. |

---

## 🗄️ 5. Database Baseline & Physical Isolation Strategy

To prevent operational database contamination and ensure strict data provenance, ETHIO-AI Defender enforces a three-tier physical database separation:

```
                                  [ Database Topography ]
                                             │
      ┌──────────────────────────────────────┼──────────────────────────────────────┐
      ↓                                      ↓                                      ↓
[ Operational DB Baseline ]        [ Local Development DB ]            [ Automated Pytest DB ]
  storage/defender.db                storage/dev_defender.db             pytest_defender.db
  • SHA-256 verified                 • Default for local work            • Created in temp directory
  • Bit-identical frozen             • Loaded via .env                   • Ephemeral & disposable
  • 2,595 historical records         • Safe for debugging & testing      • Cleaned up after test run
```

- **Operational Baseline (`storage/defender.db`)**: Protected production database holding verified historical triage records. Never targeted by development or testing scripts.
- **Development Database (`storage/dev_defender.db`)**: Isolated copy automatically referenced in [.env](file:///C:/Users/MILKWAY/ethio-ai-defender/.env) for local developer workflows and feature validation.
- **Pytest Isolation Guarantee (`tests/conftest.py`)**: All test runs automatically provision isolated disposable SQLite databases in the operating system temporary directory. Tests will fail closed if an attempt is made to run against production.

---

## 📊 6. Unified Analysis Object Contract

Every static analysis execution delivers a standardized JSON response conforming to the Module 19 schema:

```json
{
    "analysis_id": "ANL-001234",
    "file": {
        "filename": "sample.exe",
        "file_size": 24576,
        "file_kind": "EXE",
        "machine_type": "x64",
        "compile_time": "2026-02-16 14:22:00"
    },
    "hashes": {
        "md5": "eef52d1656582cb18a4f2deba3aed525",
        "sha1": "b5d848777ff7528e10408bd3725c898c8c7d3db1",
        "sha256": "3aca6c684a39c9ecaf3de614663d9c2240be7869d5ed5642b49140034ca9db9e"
    },
    "pe": {
        "type": "PE32+",
        "machine_architecture": "x64",
        "entry_point": "0x00001000",
        "subsystem": "Windows GUI"
    },
    "sections": [
        {
            "name": ".text",
            "virtual_address": "0x1000",
            "virtual_size": 4096,
            "raw_size": 4096,
            "entropy": 6.12,
            "characteristics": ["IMAGE_SCN_MEM_READ", "IMAGE_SCN_MEM_EXECUTE"]
        }
    ],
    "entropy": {
        "file_entropy": 6.45,
        "classification": "NORMAL"
    },
    "strings": {
        "urls": ["https://telecom.et/auth"],
        "ip_addresses": ["196.188.120.10"],
        "registry_paths": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "commands": ["powershell.exe -enc ..."]
    },
    "imports": [
        {
            "dll": "KERNEL32.dll",
            "api": "VirtualAlloc",
            "category": "MEMORY",
            "risk_relevance": "HIGH"
        }
    ],
    "indicators": [
        {
            "id": "IND-MEM-001",
            "name": "Dynamic Memory Allocation Primitive",
            "category": "MEMORY",
            "severity": "HIGH",
            "evidence": "VirtualAlloc imported",
            "confidence": 0.95
        }
    ],
    "risk_score": {
        "score": 65,
        "risk_level": "HIGH",
        "mitre_tactics": ["Defense Evasion", "Execution"]
    },
    "ethiopian_context": {
        "environment": "FINANCIAL",
        "relevance": "HIGH",
        "reason": "Domestic financial/telecom endpoints identified."
    },
    "machine_learning": {
        "score": 0.824,
        "threshold": 0.800395,
        "advisory_priority": "ELEVATED",
        "is_reliable": false,
        "advisory_only": true,
        "active_blocking_inhibited": true,
        "rejection_gate_state": "PENDING_REVIEW",
        "requires_analyst_review": true
    },
    "ai_assessment": {
        "assessment": "HIGH",
        "confidence": "HIGH",
        "summary": "Observed memory manipulation primitives and domestic telecom endpoints indicate high risk.",
        "key_findings": ["VirtualAlloc detected", "Domestic telecom.et indicator"],
        "limitations": ["Static analysis only; zero live execution performed."]
    },
    "report": {
        "report_id": "REP-ANL-001234",
        "language": "en"
    },
    "errors": []
}
```

---

## 🚀 7. Installation & Quick Start Guide

### Prerequisites
* **Python**: 3.10 to 3.14 (Verified on Python 3.12 and Python 3.14.4 64-bit).
* **Operating System**: Windows 10/11 / Windows Server, or Linux (Ubuntu 22.04+, Debian 12+).
* **Hardware**: 4 CPU cores, 8 GB RAM (16 GB recommended if running Ghidra RE).

### Step 1: Clone Repository & Create Virtual Environment
```powershell
git clone https://github.com/organization/ethio-ai-defender.git
cd ethio-ai-defender

python -m venv venv
.\venv\Scripts\Activate.ps1
```

*(On Linux / macOS: `source venv/bin/activate`)*

### Step 2: Install Python Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
Copy [.env.example](file:///C:/Users/MILKWAY/ethio-ai-defender/.env.example) to `.env`:
```powershell
cp .env.example .env
```

Generate a secure 32+ character HMAC secret key:
```powershell
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
```

Configure the key and settings in [.env](file:///C:/Users/MILKWAY/ethio-ai-defender/.env):
```dotenv
SECRET_KEY=<your-generated-secret-key>
APP_ENV=development
DEBUG=True
DATABASE_URL=sqlite:///C:/Users/MILKWAY/ethio-ai-defender/storage/dev_defender.db
```

*(Optional: Set `GEMINI_API_KEY` for Google Cloud LLM reasoning; falls back seamlessly to rule-based reasoning if omitted).*

### Step 4: Verify Active Database Target
```powershell
python -c "from app.core.config import settings; print('Active DB:', settings.DATABASE_URL)"
```
*Expected output:* `Active DB: sqlite:///C:/Users/MILKWAY/ethio-ai-defender/storage/dev_defender.db`

### Step 5: Start the Platform
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- **SOC Web Dashboard**: [`http://127.0.0.1:8000`](http://127.0.0.1:8000)
- **Interactive OpenAPI Documentation**: [`http://127.0.0.1:8000/docs`](http://127.0.0.1:8000/docs)

---

## 🐳 8. Docker & Containerized Ghidra Sidecar

To run Ghidra Headless Reverse Engineering inside a hardened, isolated sandbox without installing Java or Ghidra on your host machine, use the bundled Docker Compose sidecar:

```powershell
docker-compose up -d ghidra-sidecar
```

### Security Architecture of the Ghidra Sidecar:
- **Non-Root Execution**: Runs as unprivileged user `10001:10001`.
- **Read-Only Root Filesystem**: `read_only: true` with dynamic workspace inside an in-memory `tmpfs` volume (`/tmp`, `noexec`, `nosuid`).
- **Read-Only Quarantine**: Quarantined binaries are mounted strictly read-only (`./storage/quarantine:/samples:ro`).
- **Privilege Dropping**: `cap_drop: ALL`, `no-new-privileges: true`.
- **Loopback Isolation**: Bound strictly to `127.0.0.1:8089`.

To enable the platform to communicate with the sidecar, set in [.env](file:///C:/Users/MILKWAY/ethio-ai-defender/.env):
```dotenv
GHIDRA_SIDECAR_ENABLED=true
GHIDRA_SIDECAR_URL=http://127.0.0.1:8089
```

---

## 🧪 9. Running Verification & Test Suites

The test suite runs against disposable SQLite databases created automatically in temporary storage.

### 1. Full Test Suite (780+ Tests Passing):
```powershell
$env:PYTHONPATH="."
pytest tests/ -q
```

### 2. SEC-08 Security Remediation & RBAC Suite:
```powershell
$env:PYTHONPATH="."
pytest tests/test_auth01_authorization.py tests/test_sec05_xss_remediation.py tests/test_analyst_review_migration.py -v
```

### 3. Machine Learning Isolation & Analyst Confirmation Gate Suite:
```powershell
$env:PYTHONPATH="."
pytest tests/ml/test_ml13_analyst_confirmation_gate.py tests/ml/test_inference_timeout_and_isolation.py tests/ml/test_onnx_inference.py -v
```

### 4. Ghidra Headless RE Verification Suite:
```powershell
$env:PYTHONPATH="."
pytest tests/test_ghidra_analyzer.py -v
```

### 5. YARA Versioning & Relational Provenance Suite:
```powershell
$env:PYTHONPATH="."
pytest tests/test_yara_pipeline_integration.py tests/test_yara_rule_api.py tests/test_yara_rule_versioning.py -v
```

### 6. Pipeline Benchmark Execution (Standalone):
```powershell
$env:PYTHONPATH="."
pytest tests/test_module_19_final_integration.py -k "test_performance_pipeline_benchmarks" -v
```

---

## 📖 10. REST API Reference & Role-Based Access Control

All protected endpoints enforce strict role boundaries. The platform recognizes three roles:
* **`ADMIN`**: Full platform management, user administration, and YARA rule publishing.
* **`ANALYST`**: Full file intake, static analysis, case review, notes, and report exports.
* **`VIEWER`**: Educational access, safe practice labs, self-generated reports, and sample viewing.

| Method | Endpoint | Required Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Public | Serves SOC Dashboard UI or system health JSON. |
| `POST` | `/api/auth/register` | Public | Self-registration (restricted to `SELF_REGISTRATION_ROLES`, default `VIEWER`). |
| `POST` | `/api/auth/login` | Public | Authenticates credentials, returns signed JWT access token. |
| `GET` | `/api/auth/me` | Authenticated | Retrieves active user identity, role, and granted permissions. |
| `POST` | `/api/auth/logout` | Authenticated | Revokes JWT token and adds JTI to revocation blacklist. |
| `GET` | `/api/auth/users` | Admin Only | Lists registered platform users and role assignments. |
| `POST` | `/api/files/upload` | Analyst / Admin | Quarantines binary and initiates tracking. Requires `UPLOAD_FILES`. |
| `POST` | `/api/analyses` | Analyst / Admin | Uploads binary and executes complete 18-stage static pipeline. |
| `GET` | `/api/analyses` | Authenticated | Scoped analysis history listing (tenancy protected). |
| `GET` | `/api/analyses/{id}` | Owner / Admin | Returns complete Unified Analysis Object for a sample. |
| `GET` | `/api/analyses/{id}/pe` | Owner / Admin | Retrieves PE headers, section characteristics, and entropy. |
| `GET` | `/api/analyses/{id}/imports` | Owner / Admin | Retrieves categorized IAT imports with capability tags. |
| `GET` | `/api/analyses/{id}/iocs` | Owner / Admin | Retrieves extracted IOCs, network indicators, and YARA hits. |
| `GET` | `/api/analyses/{id}/ai` | Owner / Admin | Retrieves grounded AI security explanation and ATT&CK mapping. |
| `GET` | `/api/analyses/{id}/ghidra` | Owner / Admin | Retrieves structured Ghidra decompilation and function symbols. |
| `GET` | `/api/analyses/{id}/report` | Owner / Admin | Generates multi-format report (`json`, `markdown`, `html`, `text`). |
| `POST` | `/api/analyses/{id}/review` | Analyst / Admin | Submits human analyst review resolving uncorroborated ML alerts. |
| `GET` | `/api/analyses/{id}/review` | Authenticated | Retrieves current analyst confirmation status and review notes. |
| `POST` | `/api/analyses/{id}/notes` | Analyst / Admin | Adds analyst triage notes (strictly blocked for `VIEWER`). |
| `PATCH`| `/api/analyses/{id}/case` | Analyst / Admin | Updates case priority or investigation status. |
| `GET` | `/api/files/{analysis_id}` | Owner / Admin | Secure sample metadata retrieval (IDOR protected). |
| `DELETE`| `/api/dashboard/samples/{id}`| Owner / Admin | Deletes analyzed sample and cascades related records. |
| `GET` | `/api/yara/rules` | Authenticated | Lists active compiled YARA detection rules. |
| `POST` | `/api/yara/rules` | Admin Only | Creates a new YARA rule specification. |
| `GET` | `/api/yara/rules/{id}/versions` | Authenticated | Retrieves cryptographic version history of a YARA rule. |
| `POST` | `/api/yara/rules/{id}/versions` | Admin Only | Publishes an immutable new rule version. |
| `POST` | `/api/yara/rules/{id}/deactivate`| Admin Only | Deactivates rule from pipeline compilation. |
| `POST` | `/api/yara/rules/{id}/reactivate`| Admin Only | Reactivates rule in pipeline compilation. |
| `GET` | `/api/audit/logs` | Admin Only | Paginated access to security audit events. |
| `GET` | `/api/audit/stats` | Admin Only | Aggregated platform security event metrics. |
| `GET` | `/api/audit/logs/export/json` | Admin Only | Exports audit log records in structured JSON. |
| `GET` | `/api/audit/logs/export/csv` | Admin Only | Exports audit log records in standard CSV. |

---

## 🌍 11. Dual-Language & Educational Capabilities

* **Instant Localization (English & Amharic)**: Toggle effortlessly between English and Amharic (`አማርኛ`) across all 8 SOC dashboard views.
* **Technical Nomenclature Preservation**: Standard international cybersecurity terms (`PE`, `API`, `SHA-256`, `DLL`, `x86`, `x64`, `Entropy`, `IAT`) are intentionally preserved in Latin typography to prevent translation ambiguity while surrounding explanations are rendered in fluent Amharic.
* **Safe Practice Labs**: Built-in synthetic test samples allow students and junior analysts to inspect PE headers, sections, and heuristics without handling live malicious software.
* **5-Stage Reverse-Engineering Learning Center**:
  1. *What is it? (ምንድን ነው?)* — Foundational concept introduction.
  2. *Why does it matter? (ለምን ይጠቅማል?)* — Defensive operational context.
  3. *In-Depth Technical Explanation (ዝርዝር ማብራሪያ)* — Low-level binary architecture details.
  4. *Does it prove malicious behavior? (የጥቃት ማረጋገጫ ነው?)* — Realistic threat assessment context.
  5. *What should I learn next? (ቀጥሎ ምን መማር አለብኝ?)* — Practical next steps and research guidance.

---

## 📚 12. Key Platform Documentation Sitemap

| Document Title | Path | Focus Area |
| :--- | :--- | :--- |
| **Final Release Readiness Report** | [docs/FINAL_RELEASE_READINESS_REPORT.md](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/FINAL_RELEASE_READINESS_REPORT.md) | Release certification, database baseline audit, and verification evidence. |
| **Known Limitations & Security Gates** | [docs/KNOWN_LIMITATIONS_AND_SECURITY_GATES.md](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/KNOWN_LIMITATIONS_AND_SECURITY_GATES.md) | ML-13 Cascaded Rejection Gate, base-rate collapse math, model hashes. |
| **Installation & Configuration** | [docs/INSTALLATION_AND_CONFIGURATION.md](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/INSTALLATION_AND_CONFIGURATION.md) | In-depth setup, environment variables, and deployment profiles. |
| **Operations, Backup & Recovery** | [docs/OPERATIONS_BACKUP_AND_RECOVERY.md](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/OPERATIONS_BACKUP_AND_RECOVERY.md) | Database snapshot procedures, forensic preservation, and recovery workflows. |
| **SEC-08 Security Remediation Report** | [docs/SEC08_Security_Remediation_Report.md](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/SEC08_Security_Remediation_Report.md) | RBAC boundary verification, XSS report sanitization, and review idempotency. |
| **Architecture & Threat Model** | [docs/ARCHITECTURE_AND_THREAT_MODEL.md](file:///C:/Users/MILKWAY/ethio-ai-defender/docs/ARCHITECTURE_AND_THREAT_MODEL.md) | Threat boundaries, STRIDE analysis, and defensive isolation architecture. |

---

## ⚖️ 13. License & Ethical Disclaimer

**ETHIO-AI Defender (የኢትዮ-ኤአይ መከላከያ)** is developed strictly for **defensive cybersecurity triage, national digital resilience, incident response, and educational reverse engineering**. 

- The platform contains **zero attack capabilities, dynamic detonation capabilities, or exploit payload automation**.
- Users are strictly responsible for adhering to applicable national laws and institutional policies. 
- Never upload, decompile, or analyze binary software without explicit authorization from the legitimate system owner.
