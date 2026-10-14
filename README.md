# ETHIO-AI Defender (የኢትዮ-ኤአይ መከላከያ)
**Defensive AI-Powered Malware Analysis & Reverse-Engineering Platform for Ethiopia**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](file:///C:/Users/MILKWAY/ethio-ai-defender/verify_module_20.py)
[![Test Suite](https://img.shields.io/badge/tests-386%2F386%20passed-success.svg)](file:///C:/Users/MILKWAY/ethio-ai-defender/verify_module_20.py)
[![Safety Invariant](https://img.shields.io/badge/safety-zero--execution-blue.svg)](file:///C:/Users/MILKWAY/ethio-ai-defender/app/analyzers/file_intake.py)
[![Localization](https://img.shields.io/badge/locale-English%20%7C%20%E1%8A%A0%E1%88%9B%E1%88%AD%E1%8B%9B-orange.svg)](file:///C:/Users/MILKWAY/ethio-ai-defender/frontend/static/js/app.js)

---

## 🛡️ 1. Executive Summary & Vision

**ETHIO-AI Defender** is a defensive, educational, and operational cybersecurity platform tailored for national cyber resilience, Security Operations Centers (SOCs), and university reverse-engineering research laboratories in Ethiopia.

The platform provides deterministic, zero-execution static analysis of Windows Portable Executable (PE32 / PE32+) binaries (`.exe`, `.dll`) combined with privacy-bounded AI interpretations, interactive bilingual learning modes (English and Amharic), and enterprise-grade security audit controls.

---

## 📐 2. Core Architecture & End-to-End Pipeline

```
                                  [ User Request ]
                                         ↓
                                [ 1. Authentication ]
                                (PBKDF2 / JWT / RBAC)
                                         ↓
                              [ 2. Secure File Intake ]
                       (50MB Limit, .exe/.dll Whitelist)
                                         ↓
                              [ 3. File Validation ]
                         (MZ / PE Magic Verification)
                                         ↓
                            [ 4. Cryptographic Hash ]
                             (SHA-256 / SHA-1 / MD5)
                                         ↓
                             [ 5. PE Static Analysis ]
                       (DOS, NT, File & Optional Headers)
                                         ↓
                           [ 6. PE Section Analysis ]
                     (W+X Detection, Slack Space, Permissions)
                                         ↓
                          [ 7. Shannon Entropy Engine ]
                     (Information Density & Packing Clues)
                                         ↓
                           [ 8. Static String Engine ]
                     (ASCII & UTF-16: URLs, IPs, Registry)
                                         ↓
                         [ 9. Windows API Import Engine ]
                     (IAT Function Categorization & Risk)
                                         ↓
                      [ 10. Suspicious Indicator Engine ]
                     (Multi-Feature Heuristic Correlations)
                                         ↓
                         [ 11. Threat Scoring Engine ]
                        (0-100 Score & MITRE ATT&CK Map)
                                         ↓
                       [ 11b. Ghidra Headless RE ]
                     (Isolated Static Reverse Engineering)
                                         ↓
                      [ 12. Ethiopian Context Engine ]
                    (Domestic .et & Infrastructure Triage)
                                         ↓
                       [ 13. AI Security Analyst ]
                   (Fact-Grounded Explanation & Fallback)
                                         ↓
                        [ 14. Database Persistence ]
                       (Atomic Multi-Table SQLite ORM)
                                         ↓
                        [ 15. Security Report Engine ]
                     (JSON / Markdown / HTML / Text Export)
                                         ↓
                          [ 16. Modern SOC Dashboard ]
                      (Responsive Dual-Language Web UI)
```

---

## 🔒 3. Crucial Defensive Invariants & Safety Guarantees

1. **Strict Static Analysis Only (Zero Live Execution)**:
   * Uploaded binaries are strictly inspected in memory and quarantined on disk.
   * Binaries are **never executed**, spawned in processes, or passed to subshells.
   * No dynamic detonation, exploit mechanisms, or attack automation.
2. **Three-Tier Evidence Distinction**:
   * **Tier 1: Observed Evidence**: Cryptographic hashes, raw PE headers, extracted strings, section offsets.
   * **Tier 2: Rule-Based Indicators**: Deterministic heuristic correlations (e.g., W+X sections, memory allocation APIs).
   * **Tier 3: AI Interpretation**: Grounded natural-language security summaries and defensive guidance.
   * **AI Invariant**: The AI layer cannot alter or override observed factual evidence.
3. **Data Protection & Privacy Boundary**:
   * Executable byte streams, passwords, bearer tokens, API keys, and internal filesystem paths (`C:\Users\...`) are strictly redacted before generating AI prompts or audit logs.
4. **Resilient Failure Handling**:
   * If a single analyzer encounters corrupt or unexpected byte sequences, the pipeline captures the error in the `errors: []` log, preserves partial findings, and delivers the unified analysis without crashing.

---

## 📦 4. Comprehensive Module Breakdown (Modules 01 - 20)

| Module | Name | Responsibility & Key Deliverables |
| :--- | :--- | :--- |
| **Module 01** | **Secure File Intake** | Enforces 50MB maximum upload limit, whitelists `.exe`/`.dll` extensions, sanitizes path traversal (`../../etc/passwd`), null bytes, Windows reserved devices (`CON`, `PRN`, `AUX`, `NUL`), and quarantines files safely. |
| **Module 02** | **File Hash Analyzer** | Streamed cryptographic hashing computing SHA-256 (primary unique ID), SHA-1, and MD5 with deduplication lookup. |
| **Module 03** | **PE Static Analyzer** | Structural inspection of DOS MZ header, NT headers, machine architecture (`x86`/`x64`), entry point, subsystem, and compilation timestamp. |
| **Module 04** | **PE Section Analyzer** | Memory layout evaluation, W+X permission detection, virtual-to-raw size discrepancy analysis, and slack space inspection. |
| **Module 05** | **Entropy Analyzer** | Shannon entropy calculation ($H(X) = -\sum p \log_2 p$) measuring byte randomness per section (0.0 to 8.0) to identify packing/compression. |
| **Module 06** | **String Analyzer** | High-performance regex classification extracting ASCII and UTF-16LE strings (URLs, IP addresses, domains, Windows registry paths, and commands). |
| **Module 07** | **Import / API Analyzer** | Import Address Table (IAT) parsing, mapping imported Windows DLL APIs to technical capability categories (Memory, Network, Process, Registry, Persistence, Anti-Analysis). |
| **Module 08** | **Indicator Engine** | Multi-feature heuristic correlation rules linking static artifacts into explainable threat indicators with confidence ratings. |
| **Module 09** | **Threat Scoring Engine** | Heuristic mathematical scoring (0-100) assigning structured severity levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) with MITRE ATT&CK tactic mappings. |
| **Module 10** | **Ethiopian Context Engine** | Domestic sector prioritization (Government, Financial, University, Healthcare, Telecom, Enterprise) based on verified `.et` ccTLDs and infrastructure indicators. |
| **Module 11** | **AI Security Analyst** | Multi-provider abstraction (`GeminiProvider`, `MockAIProvider`, `OfflineRuleBasedProvider`) with privacy redaction and fact-grounding validation. |
| **Module 12** | **Learning Center** | Interactive cybersecurity education engine presenting beginner-to-advanced lessons on PE headers, entropy, IAT imports, and reverse engineering in English & Amharic. |
| **Module 13** | **Report Generator** | Multi-format security report generation (`JSON`, `Markdown`, `HTML`, `Plain Text`) in English and Amharic with 16 structured sections. |
| **Module 14** | **Database Persistence** | Relational SQLite database with SQLAlchemy ORM, foreign keys, indexes, and atomic multi-table transaction commits. |
| **Module 15** | **Web SOC Dashboard** | Responsive dashboard UI with 8 real-time views, drag-and-drop intake, live demo sample, and instantaneous EN/AM language toggling. |
| **Module 16** | **Authentication & RBAC** | PBKDF2-HMAC-SHA256 password hashing, signed JWT tokens, token blacklist revocation on logout, account lockout (5 failed attempts = 15-min lockout), and role-based access (`ADMIN`, `ANALYST`, `STUDENT`). |
| **Module 17** | **Security Audit Logging** | Structured JSON audit logging for security events (login, logout, upload, analysis start/complete/failure, report export) with sensitive data redaction. |
| **Module 18** | **Security Testing Suite** | Comprehensive defensive test harness with in-memory synthetic PE fixtures testing path traversal, SQLi, XSS, fuzzing, rate limiting, and IDOR. |
| **Module 19** | **Final System Integration** | Unified Pipeline Orchestrator delivering the standardized Unified Analysis Object with graceful error isolation and full regression verification. |
| **Module 20** | **Ghidra Headless Reverse Engineering** | Runs Ghidra's supported `analyzeHeadless` workflow over the quarantined sample in an isolated per-analysis workspace. Extracts structured program identity, architecture, entry point, functions, imports, exports, and strings. Never executes the sample, uses subprocess argument arrays only, enforces a hard timeout, cleans workspaces per configuration, and degrades gracefully when Ghidra is not installed. |

---

## 📊 5. Unified Analysis Object Contract

Every analysis produces a standardized JSON response conforming to the Module 19 schema:

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
    "ai_assessment": {
        "assessment": "HIGH",
        "confidence": "HIGH",
        "summary": "Observed memory manipulation primitives and domestic telecom endpoints indicate high risk.",
        "key_findings": ["VirtualAlloc detected", "Domestic telecom.et indicator"],
        "limitations": ["Static analysis only; no dynamic execution performed."]
    },
    "report": {
        "report_id": "REP-ANL-001234",
        "language": "en"
    },
    "errors": []
}
```

---

## 🚀 6. Installation & Quick Start

### Prerequisites
* Python 3.10+ (tested on Python 3.12 / 3.14)
* SQLite 3

### 1. Clone & Setup Virtual Environment
```powershell
git clone https://github.com/organization/ethio-ai-defender.git
cd ethio-ai-defender

python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure Environment
```powershell
cp .env.example .env
```
*(Optional: add `GEMINI_API_KEY` in `.env` for cloud LLM reasoning; defaults to deterministic offline provider if absent).*
*(Optional: set `GHIDRA_HOME` in `.env` to your extracted Ghidra directory to enable headless reverse engineering; the platform degrades gracefully and reports Ghidra as unavailable if it is not installed).*

### 3. Launch Development Server
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Access the Dashboard at: **`http://127.0.0.1:8000`**  
Access the API Documentation at: **`http://127.0.0.1:8000/docs`**

---

## 🧪 7. Running the Test Suites

### Master Regression Runner (Modules 01 - 19):
```powershell
python verify_module_19.py
```

### Module 20 (Ghidra Integration) Verification:
```powershell
python verify_module_20.py
```

### Run Full Test Suite via Standard `unittest`:
```powershell
python -m unittest discover tests
```

### Run Defensive Security Audit Tool:
```powershell
python audit_security_issues.py
```

---

## 📖 8. REST API Reference

| Method | Endpoint | Access Level | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Public | Serves SOC Dashboard UI or system health JSON. |
| `POST` | `/api/files/upload` | Public / User | Validates and quarantines PE binaries, returns `analysis_id`. |
| `POST` | `/api/dashboard/analyze` | Public / User | Executes complete 15-stage pipeline, returns Unified Analysis Object. |
| `GET` | `/api/dashboard/samples` | Public / User | Lists analyzed samples in database. |
| `GET` | `/api/dashboard/samples/{id}/full` | Owner / Admin | Fetches full multi-section sample details with IDOR protection. |
| `GET` | `/api/dashboard/samples/{id}/report` | Owner / Admin | Exports security report in JSON, Markdown, HTML, or Plain Text. |
| `GET` | `/api/analyses/{id}/pe` | Owner / Admin | Returns completed PE structure, sections, and entropy metrics. |
| `GET` | `/api/analyses/{id}/imports` | Owner / Admin | Returns categorized imports with search and risk filters. |
| `GET` | `/api/analyses/{id}/iocs` | Owner / Admin | Returns extracted IOCs, correlated indicators, and YARA matches. |
| `GET` | `/api/analyses/{id}/ai` | Owner / Admin | Returns grounded AI assessment and MITRE ATT&CK candidates. |
| `GET` | `/api/analyses/{id}/ghidra` | Owner / Admin | Returns structured Ghidra reverse-engineering metadata and recovered functions. |
| `POST`| `/api/analyses/threat-intel/lookup` | Analyst / Admin | Queries configured threat-intelligence providers for an indicator. |
| `DELETE`| `/api/dashboard/samples/{id}` | Owner / Admin | Deletes analyzed sample and cascading records. |
| `POST` | `/api/auth/register` | Public | Registers new platform user (`STUDENT`, `ANALYST`, or `ADMIN`). |
| `POST` | `/api/auth/login` | Public | Authenticates user credentials, returns signed JWT access token. |
| `GET` | `/api/auth/me` | Authenticated | Returns current authenticated user profile and active permissions. |
| `POST` | `/api/auth/logout` | Authenticated | Revokes current JWT access token (blacklists JTI). |
| `GET` | `/api/auth/users` | Admin Only | Lists registered users and roles (RBAC guarded). |
| `GET` | `/api/audit/logs` | Admin Only | Retrieves security audit logs with pagination and filters. |
| `GET` | `/api/audit/stats` | Admin Only | Aggregates platform security event statistics. |
| `GET` | `/api/audit/logs/export/json` | Admin Only | Exports full audit logs in JSON format. |
| `GET` | `/api/audit/logs/export/csv` | Admin Only | Exports full audit logs in CSV format. |

---

## 🌍 9. Dual-Language & Educational Capabilities

* **English & Amharic Support**: Instant localization toggle across all 8 dashboard tabs.
* **Technical Nomenclature Preservation**: Standard terms (`PE`, `API`, `SHA-256`, `DLL`, `x86`, `x64`, `Entropy`) are retained in Latin format within Amharic explanations to maintain precise engineering clarity.
* **Interactive Learning Center**: Reverse-engineering concept breakdowns across 5 structured educational stages:
  1. *What is it? (ምንድን ነው?)*
  2. *Why does it matter? (ለምን ይጠቅማል?)*
  3. *In-Depth Technical Explanation (ዝርዝር ማብራሪያ)*
  4. *Does it prove malicious behavior? (የጥቃት ማረጋገጫ ነው?)*
  5. *What should I learn next? (ቀጥሎ ምን መማር አለብኝ?)*

---

## ⚖️ 10. License & Ethical Disclaimer

**ETHIO-AI Defender** is developed strictly for **defensive cybersecurity analysis, threat intelligence triage, and educational reverse engineering**. It contains zero attack or exploitation capabilities. Never analyze binaries without proper authorization.
