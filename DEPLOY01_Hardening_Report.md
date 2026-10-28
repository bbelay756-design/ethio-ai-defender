# ETHIO-AI DEFENDER — MILESTONE DEPLOY-01 OPERATIONAL HARDENING & DEPLOYMENT REPORT

**Date:** 2026-10-28  
**Status:** COMPLETE & DOCUMENTED  
**Auditor / Agent:** Antigravity Pair Programmer  
**Operational Database SHA-256:** `02D51F7A39E07B1C9716BB5420BC72D81CF6AB103580BA06AEF3FE442D7AEC24`

---

## 1. Operational Security Hardening

### 1.1 Secret Key & Token Authentication
- **Fail-Closed Startup:** The application enforces `settings.validate_security()` at startup (`app/main.py:lifespan`). If `SECRET_KEY` is empty, unset, whitespace-only, or equal to the legacy literal `CHANGE_THIS_TO_A_SECURE_RANDOM_SECRET_KEY_MIN_32_CHARS`, startup immediately raises a `RuntimeError` and terminates.
- **Key Generation:** Operators must generate an entropy-strong secret before launch:
  ```powershell
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- **Token Invalidation:** Token versions (`token_version`) and JTI blacklisting guarantee immediate invalidation of sessions upon password change, role modification, or logout.

### 1.2 CORS Hardening
- **Strict Allowlist:** CORS is disabled by default (`CORS_ORIGINS=""`).
- **Wildcard Rejection:** Any wildcard `*` in `CORS_ORIGINS` triggers startup termination via `settings.validate_cors()`.
- **Credential Protection:** `CORS_ALLOW_CREDENTIALS` defaults to `false` and cannot be paired with non-explicit origins.

### 1.3 Rate Limiting & Input Bounds
- **Body Size Limit Middleware:** `BodySizeLimitMiddleware` intercepts requests and enforces `MAX_UPLOAD_BODY_BYTES` (51MB) *before* multipart parser memory allocation, returning HTTP 413.
- **Account Lockout:** Enforces 5 failed login attempts per account before triggering a 15-minute lockout period.
- **Login Rate Limiting:** Enforces 10 login requests per minute per IP address.

---

## 2. Windows Service & Process Management

ETHIO-AI Defender is engineered for robust execution on Windows Server and Windows 11 enterprise environments.

### 2.1 Starting the Service
From PowerShell within the virtual environment:
```powershell
# Set Execution Policy and activate virtual environment
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
& .\venv\Scripts\Activate.ps1

# Run FastAPI backend via Uvicorn
$env:PYTHONPATH="."
uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1 --log-level info
```

### 2.2 Running as a Windows Service (NSSM)
For unattended enterprise production:
```cmd
nssm install EthioAIDefender "C:\Users\MILKWAY\ethio-ai-defender\venv\Scripts\python.exe" "-m uvicorn app.main:app --host 127.0.0.1 --port 8000"
nssm set EthioAIDefender AppDirectory "C:\Users\MILKWAY\ethio-ai-defender"
nssm set EthioAIDefender AppEnvironmentExtra PYTHONPATH=.
nssm start EthioAIDefender
```

### 2.3 ML Worker Process Management
- Heavy feature extraction and inference execute inside an isolated subprocess worker (`app/ml/process_worker.py`).
- Worker uses the Windows-native `multiprocessing.get_context("spawn")`.
- Wall-clock deadlines (`settings.ML_TIMEOUT_SECONDS`, default 10s) are enforced via `pipe.poll()`.
- Hung or unresponsive workers are forcefully terminated via `worker.terminate()` / Win32 `TerminateProcess` without leaving orphaned background threads.
- Worker processes automatically recycle after 500 inferences to eliminate native memory leaks.

---

## 3. Database Backup & Disaster Recovery Procedures

### 3.1 Online SQLite Backup Procedure
Never copy `storage/defender.db` while active write transactions are occurring. Use SQLite's online vacuum/backup API:
```powershell
# Perform consistent hot backup
$backupDate = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFile = "storage\backups\defender_backup_$backupDate.db"
New-Item -ItemType Directory -Force -Path "storage\backups" | Out-Null

python -c "import sqlite3; src = sqlite3.connect('storage/defender.db'); dst = sqlite3.connect('$backupFile'); src.backup(dst); dst.close(); src.close(); print('Backup complete: $backupFile')"

# Verify SHA-256 of backup
Get-FileHash -Algorithm SHA256 $backupFile
```

### 3.2 Database Restore Procedure
1. Stop backend service (`nssm stop EthioAIDefender` or terminate uvicorn).
2. Archive the current database file to `storage/defender.db.stale`.
3. Copy the verified backup file into `storage/defender.db`.
4. Run schema migration check:
   ```powershell
   alembic upgrade head
   ```
5. Restart backend service.

### 3.3 Recovery from Corrupted Artifacts
1. **Model Checksum Mismatch:** If the on-disk model artifact hash does not match `TRUSTED_BASELINE_MODEL_SHA256` (`f2fd3ed4e4fc0b48...`), the classifier fails closed and refuses to load:
   - System automatically degrades to `status="UNAVAILABLE"` and logs `ModelTamperedOrCorrupted`.
   - Pipeline continues processing deterministic PE, strings, and YARA analyses without interruption.
   - To restore, re-deploy the verified authoritative artifact into `D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib`.
2. **Corrupted Quarantine Files:** Quarantined samples that fail integrity checks are discarded. Quarantine records in the database retain file hashes and audit metadata.

**Milestone DEPLOY-01 is accepted as complete.**
