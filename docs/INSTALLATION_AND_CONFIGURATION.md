# ETHIO-AI DEFENDER — INSTALLATION AND CONFIGURATION GUIDE

**Document ID:** DOC-INSTALL-CONFIG-01  
**Target Release:** Release-04 Stabilization / Handover  
**Platform:** ETHIO-AI Defender (Defensive Malware Analysis & SOC Triage Platform)  
**Date:** October 29, 2026  

---

## 1. System Requirements & Prerequisites

### 1.1 Operating Environment
- **Operating System:** Windows 10/11 / Windows Server 2022, or Linux (Ubuntu 22.04 LTS / Debian 12 / Rocky Linux 9).
- **Python Runtime:** Python 3.10 to 3.14 (Verified on Python 3.14.4 64-bit).
- **Hardware Minimums:**
  - CPU: 4 Cores (x86_64) recommended for parallel static analysis and ONNX inference.
  - RAM: 8 GB minimum (16 GB recommended when running local Ghidra headless analysis).
  - Storage: 10 GB available SSD space for platform code, SQLite databases, and quarantine/sample storage.

### 1.2 Optional Component Dependencies
- **Ghidra Headless Analyzer:** Ghidra 11.0+ extracted locally with OpenJDK 17+, or containerized Ghidra Sidecar service (requires Docker Engine).
- **YARA:** `yara-python` compiled C-bindings (bundled in requirements).
- **ONNX Runtime:** `onnxruntime` 1.16+ for CPU vector inference acceleration.

---

## 2. Directory Structure & Storage Layout

The application manages data across strict, access-controlled subdirectories:

```
C:\Users\MILKWAY\ethio-ai-defender\
├── app/                  # FastAPI Application, Services, ML, and Database models
├── alembic/              # Database schema versioning and migration scripts
├── frontend/             # Single-Page Application (HTML5, Vanilla JS, CSS)
├── rules/                # YARA rules repository and community rule definitions
├── scripts/              # Offline utility scripts (dataset extraction, training, ONNX export)
├── storage/              # Runtime persistence (Git-ignored)
│   ├── defender.db       # Operational SQLite database baseline (Protected)
│   ├── dev_defender.db   # Dedicated local development database (Isolated)
│   ├── evidence/         # Forensic snapshot repositories (Cryptographically frozen)
│   ├── logs/             # System and audit event logging (defender.log, audit.jsonl)
│   ├── models/           # In-repo secondary model artifacts (ember_baseline_v1)
│   ├── quarantine/       # Isolated sample storage
│   └── uploads/          # Temporary file staging directory
└── tests/                # Pytest verification suites and regression tests
```

---

## 3. Configuration & Environment Variables

Platform configuration is managed via [app/core/config.py](file:///C:/Users/MILKWAY/ethio-ai-defender/app/core/config.py) using `python-dotenv`. Environment variables defined in [.env](file:///C:/Users/MILKWAY/ethio-ai-defender/.env) or injected by the host OS govern application behavior.

### 3.1 Core Security & Web Configuration
| Variable Name | Default Value | Description & Constraints |
| :--- | :--- | :--- |
| `SECRET_KEY` | *(None - Required)* | Cryptographic HMAC signing secret for JWT access tokens. Must be at least 32 characters long. Startup fails closed if missing or insecure. |
| `APP_ENV` | `development` | Deployment environment flag (`development`, `staging`, `production`). |
| `DEBUG` | `True` | Debug mode toggle (`true`/`false`). Must be `false` in production. |
| `HOST` | `127.0.0.1` | Network bind address for Uvicorn ASGI server. |
| `PORT` | `8000` | Network port for HTTP/REST API endpoints. |
| `CORS_ORIGINS` | `""` | Comma-separated list of allowed web origins. Empty disables cross-origin requests (recommended for same-origin single-host deployment). Wildcards (`*`) are strictly rejected. |
| `CORS_ALLOW_CREDENTIALS` | `false` | Permits cookie/credential headers when explicit origins are configured. |

### 3.2 Upload & Storage Constraints
| Variable Name | Default Value | Description |
| :--- | :--- | :--- |
| `MAX_FILE_SIZE_BYTES` | `52428800` (50 MB) | Maximum permitted sample file size for static analysis intake. |
| `MAX_UPLOAD_BODY_BYTES` | `53477376` (51 MB) | Maximum raw HTTP multipart request body size enforced by ASGI middleware before parsing. |
| `UPLOAD_CHUNK_SIZE` | `1048576` (1 MB) | Chunk size for streaming file uploads into quarantine. |
| `LOG_LEVEL` | `INFO` | Console and file logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |

### 3.3 Database URLs & Isolation Strategy
| Variable Name | Default / Workspace Value | Purpose |
| :--- | :--- | :--- |
| `DATABASE_URL` | `sqlite:///storage/dev_defender.db` *(in .env)* | Primary database connection URL. Configured to the isolated development database for local engineering. |
| `ALEMBIC_DATABASE_URL` | *(Unset / Fallback to DATABASE_URL)* | Explicit connection URL used by Alembic schema migration commands. |

> [!IMPORTANT]
> In production deployments, set `DATABASE_URL="sqlite:///storage/defender.db"` via container/host environment variables. In local development environments, [.env](file:///C:/Users/MILKWAY/ethio-ai-defender/.env) points to `storage/dev_defender.db` to prevent accidental mutations of operational data.

### 3.4 Machine Learning Safety Configuration
| Variable Name | Default Value | Description & Safety Invariant |
| :--- | :--- | :--- |
| `ML_ENABLED` | `false` | Enables machine learning static feature extraction and inference. Default is disabled. |
| `ML_SHADOW_MODE` | `true` | Restricts ML evaluation to non-authoritative advisory scoring. Never triggers automated host-level blocking. |
| `ML_ONNX_ENABLED` | `false` | Enables CPU vector acceleration via ONNX Runtime when verified artifacts exist. |
| `ETHIO_ML_TRUSTED_MODEL_SHA256` | *(Code Constant)* | Cryptographic digest required to load model artifacts. Rejects untrusted or modified models. |

---

## 4. Installation & Setup Procedure

### Step 1: Clone Repository & Create Virtual Environment
```powershell
cd C:\Users\MILKWAY\ethio-ai-defender
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 2: Install Python Dependencies
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
Copy [.env.example](file:///C:/Users/MILKWAY/ethio-ai-defender/.env.example) to [.env](file:///C:/Users/MILKWAY/ethio-ai-defender/.env) if not present, and generate a strong 32-character secret:
```powershell
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
```
Ensure [.env](file:///C:/Users/MILKWAY/ethio-ai-defender/.env) includes the development database configuration:
```dotenv
DATABASE_URL=sqlite:///C:/Users/MILKWAY/ethio-ai-defender/storage/dev_defender.db
```

### Step 4: Verify Database Target
Before running any application command, confirm the active database target:
```powershell
python -c "from app.core.config import settings; print('Active DB:', settings.DATABASE_URL)"
```
*Expected output:* `Active DB: sqlite:///C:/Users/MILKWAY/ethio-ai-defender/storage/dev_defender.db`

### Step 5: Start Application
```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Access the web dashboard at `http://127.0.0.1:8000/`.

---

## 5. Development & Testing Procedures

### 5.1 Automated Test Suite Execution
Always execute tests targeting the `tests/` directory explicitly:
```powershell
pytest tests/ -q
```
*Isolation Guarantee:* [tests/conftest.py](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/conftest.py) intercepts all pytest runs and redirects `DATABASE_URL` to a disposable temporary SQLite database in the OS temp directory (`pytest_defender.db`).

### 5.2 Standalone Script Execution
When running profiling, feature extraction, or ad-hoc analysis:
```powershell
$env:DATABASE_URL = "sqlite:///C:/Users/MILKWAY/ethio-ai-defender/storage/dev_defender.db"
python scripts/extract_features_streaming.py
```
*Rule:* Never execute standalone scripts with `$env:DATABASE_URL` pointing to `storage/defender.db`.
