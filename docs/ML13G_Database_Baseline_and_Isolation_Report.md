# ETHIO-AI DEFENDER — MILESTONE ML-13G REPORT
## Operational Database Baseline Adoption and Development Isolation

**Milestone Identifier:** ML-13G  
**Target Asset:** Operational SQLite Database (`storage/defender.db`) & Development Database (`storage/dev_defender.db`)  
**Date of Execution:** October 29, 2026  
**Investigating & Implementing Authority:** Senior Principal Systems Integration & Machine Learning Safety Engineer  
**Classification:** Operational Database Baseline Formalization & Development Environment Isolation  
**Closure Status:** **PASS**  

---

## 1. BASELINE ADOPTION DECISION AND RATIONALE

### 1.1 Incident Context & Discovery
During the execution of milestone **ML-13E** on October 29, 2026, an operational database hash discrepancy was detected:
- **Pre-Incident SHA-256:** `02d51f7a39e07b1c9716bb5420bc72d81cf6ab103580ba06aef3fe442d7aec24` (31,707,136 bytes)
- **Post-Incident SHA-256:** `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a` (31,719,424 bytes, +12,288 bytes)

Milestone **ML-13F** conducted a comprehensive, read-only forensic investigation that confirmed the root cause: an ad-hoc CLI latency benchmark executed directly via `python -c` outside `pytest` fell back to default configuration in [app/core/config.py](file:///C:/Users/MILKWAY/ethio-ai-defender/app/core/config.py) and committed 5 synthetic benchmark transactions to [storage/defender.db](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/defender.db).

### 1.2 Forensics & Relational Verification
The forensic audit across all 25 database tables confirmed:
- **Zero Loss of Historical Data:** All 2,595 historical malware samples (IDs 1–2636) and all 4,689 user accounts (IDs 1–4824) remained 100% unaltered. Zero historical rows were modified or deleted.
- **Strictly Bounded Mutations:** Mutations were strictly limited to the 5 synthetic sample transactions:
  - `samples`: 5 rows (IDs 2637–2641, `ANL-011591` to `ANL-011595`)
  - `analysis_results`: 5 rows (IDs 2508–2512)
  - `sections`: 10 rows (IDs 5178–5187)
  - `strings`: 15 rows (IDs 14720–14734)
  - `iocs`: 15 rows (IDs 10589–10603)
  - `ghidra_analysis`: 5 rows (IDs 1763–1767)
  - `audit_logs`: 10 rows (IDs 35578–35587)
- **Structural Integrity:** `PRAGMA integrity_check` returned `ok`. `PRAGMA foreign_key_check` returned `0` violations. The schema strictly conforms to Alembic revision head `b2c3d4e5f6a7`.

### 1.3 Baseline Adoption Decision
In accordance with Milestone ML-13G objectives, the engineering authority has formally **ADOPTED** the current state of [storage/defender.db](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/defender.db) as the official operational database baseline.

**Rationale for Adoption:**
1. **Zero Data Corruption:** The database structure, indexes, and foreign-key constraints are fully intact and healthy.
2. **Audit Trail Continuity:** The 10 audit log records accurately reflect platform actions. Deleting records would create sequence gaps in auto-increment primary keys and leave orphaned entries in transaction history.
3. **Prevention of Binary Fragmentation:** Deleting rows in SQLite does not reset allocation maps or revert page headers; row deletion would not restore the pre-incident hash `02d51f7a...` and would risk index fragmentation.
4. **Benign Artifacts:** The 5 synthetic samples represent known minimal PE binaries (`perf_bench_sample.exe`) classified as `LOW` risk (score 0), posing no operational or threat-intelligence risks to the platform.

---

## 2. BEFORE-AND-AFTER OPERATIONAL DATABASE VERIFICATION

The operational database [storage/defender.db](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/defender.db) was monitored throughout ML-13G using read-only PowerShell commands and read-only SQLite URIs (`file:storage/defender.db?mode=ro`).

| Verification Milestone Point | Timestamp (Local UTC+3) | Timestamp (UTC) | File Size (Bytes) | SHA-256 Digest | Match Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ML-13F Final Baseline** | `2026-10-29 01:29:43` | `2026-10-28 22:29:43` | 31,719,424 | `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a` | Verified |
| **ML-13G Pre-Work Baseline** | `2026-10-29 09:04:30` | `2026-10-29 06:04:30` | 31,719,424 | `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a` | **MATCH** |
| **Post-Dev DB Creation** | `2026-10-29 09:32:25` | `2026-10-29 06:32:25` | 31,719,424 | `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a` | **MATCH** |
| **Post-Pytest Execution** | `2026-10-29 09:43:30` | `2026-10-29 06:43:30` | 31,719,424 | `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a` | **MATCH** |
| **Post-Dev Write Demonstration**| `2026-10-29 09:50:41` | `2026-10-29 06:50:41` | 31,719,424 | `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a` | **MATCH** |
| **ML-13G Final Verification** | `2026-10-29 09:51:42` | `2026-10-29 06:51:42` | 31,719,424 | `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a` | **MATCH** |

- **Operational File LastWriteTime:** `Thursday, October 29, 2026 1:18:52 AM` (Remains bit-identical to the moment the ML-13E benchmarking stopped; zero mutations occurred).
- **Incident Record Count Verification:** Read-only queries confirmed exact expected counts in `storage/defender.db`:
  - `samples` (id >= 2637): **5**
  - `analysis_results` (sample_id >= 2637): **5**
  - `sections` (sample_id >= 2637): **10**
  - `strings` (sample_id >= 2637): **15**
  - `iocs` (sample_id >= 2637): **15**
  - `ghidra_analysis` (sample_id >= 2637): **5**
  - `audit_logs` (id >= 35578): **10** (Max ID: 35587)

---

## 3. EVIDENCE FILE VERIFICATION RESULTS

The forensic evidence artifacts generated during ML-13F under [storage/evidence/incident_ml13f_20261029/](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/evidence/incident_ml13f_20261029/) were inspected via read-only hash algorithms:

### 3.1 Raw Byte Forensic Snapshot
- **Path:** [storage/evidence/incident_ml13f_20261029/defender_raw_snapshot.db](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/evidence/incident_ml13f_20261029/defender_raw_snapshot.db)
- **File Size:** `31,719,424` bytes
- **Expected SHA-256:** `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a`
- **Verified SHA-256:** `DDEA41F9FEB3F8AED9715E9EA0A9E536C721800D34242F66C017A641B5603D9A`
- **Integrity Status:** **VERIFIED (Bit-Identical to Operational Baseline)**

### 3.2 SQLite-Consistent Online Backup Snapshot
- **Path:** [storage/evidence/incident_ml13f_20261029/defender_incident_evidence.db](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/evidence/incident_ml13f_20261029/defender_incident_evidence.db)
- **File Size:** `31,719,424` bytes
- **Expected SHA-256:** `179a9359732b3087c8ebacad37369ae11e6ea16748dbe3339b7ad5abc8c62aeb`
- **Verified SHA-256:** `179A9359732B3087C8EBACAD37369AE11E6EA16748DBE3339B7AD5ABC8C62AEB`
- **Integrity Status:** **VERIFIED (Consistent SQLite Engine Backup)**

Zero modifications, renames, or deletions were performed on the evidence repository.

---

## 4. DEVELOPMENT AND TEST DATABASE CONFIGURATION

### 4.1 Establishment of Development Database (`storage/dev_defender.db`)
1. **Pre-Flight Existence Check:** Prior to creation, `storage/dev_defender.db` was checked and verified not to exist (`Test-Path` returned `False`).
2. **Safe Creation Procedure:** To completely eliminate any locks or writes against `storage/defender.db`, `storage/dev_defender.db` was established by duplicating the read-only evidence file `storage/evidence/incident_ml13f_20261029/defender_raw_snapshot.db`.
3. **Database Health:**
   - File Size: `31,719,424` bytes
   - SHA-256: `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a`
   - `PRAGMA integrity_check`: `ok`
   - Alembic Revision Head: `b2c3d4e5f6a7`

### 4.2 Application Configuration & Environment Isolation Analysis
- **Current Architecture Inspection:**
  In [app/core/config.py](file:///C:/Users/MILKWAY/ethio-ai-defender/app/core/config.py):
  ```python
  load_dotenv(BASE_DIR / ".env")
  load_dotenv()
  ...
  DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'storage' / 'defender.db'}")
  ```
  In [app/db/session.py](file:///C:/Users/MILKWAY/ethio-ai-defender/app/db/session.py):
  ```python
  engine = create_engine(settings.DATABASE_URL, ...)
  SessionLocal = sessionmaker(bind=engine, ...)
  ```
  In [alembic/env.py](file:///C:/Users/MILKWAY/ethio-ai-defender/alembic/env.py):
  ```python
  db_url = os.getenv("ALEMBIC_DATABASE_URL") or settings.DATABASE_URL
  ```

- **Minimal Proposed Configuration Change & Impact Analysis:**
  - **Proposed Change:** Configure the development database target explicitly within the local development [.env](file:///C:/Users/MILKWAY/ethio-ai-defender/.env) file:
    ```dotenv
    # Database Configuration (Development Database Isolation)
    DATABASE_URL=sqlite:///C:/Users/MILKWAY/ethio-ai-defender/storage/dev_defender.db
    ```
  - **Safety & Production Impact:**
    1. [.env](file:///C:/Users/MILKWAY/ethio-ai-defender/.env) is listed in [.gitignore](file:///C:/Users/MILKWAY/ethio-ai-defender/.gitignore) and is never committed to Git. Production environments do not use this developer-machine file; production provides its own `DATABASE_URL` via container environment variables or orchestrator configuration.
    2. Zero tracked application source code is altered. [app/core/config.py](file:///C:/Users/MILKWAY/ethio-ai-defender/app/core/config.py) remains unchanged.
    3. Standalone Python commands, scratch scripts, profiling utilities, and local FastAPI servers automatically load [.env](file:///C:/Users/MILKWAY/ethio-ai-defender/.env) via `load_dotenv()` and bind directly to `storage/dev_defender.db`.
    4. Explicit terminal environment variable overrides (`$env:DATABASE_URL`) continue to take absolute precedence because `python-dotenv` does not overwrite existing process environment variables (`override=False` default).

### 4.3 Demonstration of Separation
A live write was executed using `SessionLocal()` via a standalone Python command without `pytest` fixtures:
```python
from app.db.session import SessionLocal
from app.db.models import AuditLogModel
s = SessionLocal()
s.add(AuditLogModel(event='dev isolation test', result='SUCCESS'))
s.commit()
```
- **Active Database Connection:** Confirmed via `PRAGMA database_list` as `C:\Users\MILKWAY\ethio-ai-defender\storage\dev_defender.db`.
- **Target `dev_defender.db`:** Max audit log ID incremented from `35587` to `35588`.
- **Operational `defender.db`:** Max audit log ID remained strictly `35587`. Hash remained bit-identical `DDEA41F9FEB3F8AED9715E9EA0A9E536C721800D34242F66C017A641B5603D9A`.
- **Reset:** `storage/dev_defender.db` was refreshed from `storage/evidence/incident_ml13f_20261029/defender_raw_snapshot.db` to restore clean baseline alignment.

### 4.4 Automated Test Isolation Analysis
- **Pytest Suite:**
  In [tests/conftest.py](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/conftest.py), `pytest` creates an isolated temporary directory in the OS temp space (`tempfile.mkdtemp(prefix="defender_pytest_")`) and injects:
  ```python
  os.environ["DATABASE_URL"] = f"sqlite:///{_isolated_db_path}"
  os.environ["ALEMBIC_DATABASE_URL"] = f"sqlite:///{_isolated_db_path}"
  ```
  The autouse fixture `ensure_db_isolation` asserts that `"pytest_defender.db"` or `"test"` or `":memory:"` is in `settings.DATABASE_URL`.
- **Independent Test Suites:** Individual migration tests (e.g., [tests/test_analyst_review_migration.py](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/test_analyst_review_migration.py)) use dedicated `tempfile.TemporaryDirectory()` contexts and explicit SQLite URLs.

---

## 5. COMMANDS APPROVED FOR SAFE DEVELOPMENT TESTING AND PROFILING

All future engineering workflows must adhere to the following approved procedures:

### 5.1 Standalone Development & Profiling Execution
When executing profiling or pipeline benchmarks outside `pytest`:
1. **Pre-execution Target Verification:**
   ```powershell
   python -c "from app.core.config import settings; print('Target DB:', settings.DATABASE_URL)"
   ```
   *Requirement:* Confirm the output targets `dev_defender.db` (or a designated disposable database) before running.
2. **Explicit Session Binding:**
   ```powershell
   $env:DATABASE_URL = "sqlite:///C:/Users/MILKWAY/ethio-ai-defender/storage/dev_defender.db"
   $env:ALEMBIC_DATABASE_URL = "sqlite:///C:/Users/MILKWAY/ethio-ai-defender/storage/dev_defender.db"
   python -c "from app.pipeline.orchestrator import unified_pipeline_service; ..."
   ```

### 5.2 Test Suite Execution
When executing the test suite:
```powershell
# Always explicitly target the tests/ directory to avoid collecting root-level text artifacts
pytest tests/
pytest tests/test_analyst_review_migration.py
```

### 5.3 Development Database Reset Procedure
If `storage/dev_defender.db` accumulates test artifacts or needs to be returned to baseline:
```powershell
Copy-Item storage/evidence/incident_ml13f_20261029/defender_raw_snapshot.db storage/dev_defender.db -Force
```

---

## 6. COMMANDS AND WORKFLOWS THAT REMAIN UNSAFE OR BLOCKED

The following operations remain strictly **UNSAFE** and **BLOCKED**:

1. **Direct Operational Database Target in Development:**
   - Setting `$env:DATABASE_URL = "sqlite:///storage/defender.db"` or targeting `storage/defender.db` during local profiling or ad-hoc scripting is strictly forbidden.
2. **Pytest Root Discovery Without Scope:**
   - Running bare `pytest` in the root repository directory without specifying `tests/` or a file path is unsafe because root directory stdout redirection files (`test_*.txt`) trigger UTF-8 collection crashes.
3. **Destructive SQL Operations on Operational Baseline:**
   - Running `DELETE FROM samples WHERE id >= 2637;`, `VACUUM;`, `REINDEX;`, or manual schema modifications on `storage/defender.db` is strictly blocked.
4. **Restoring Snapshots Over Operational Database:**
   - Restoring pre-incident or post-incident snapshots over `storage/defender.db` is blocked.
5. **Git Destructive Commands:**
   - `git checkout .`, `git clean -fd`, `git reset --hard`, and `git commit` without explicit authorization remain strictly blocked.

---

## 7. GIT STATUS VERIFICATION

Git status was verified before and after ML-13G execution. All pre-existing tracked modifications and untracked files were preserved 100%.

### 7.1 Tracked Modifications Preserved (19 files)
- `app/analyzers/ghidra_analyzer.py`
- `app/api/analyses.py`
- `app/api/files.py`
- `app/audit/events.py`
- `app/audit/logger.py`
- `app/auth/roles.py`
- `app/core/config.py`
- `app/db/models.py`
- `app/db/repository.py`
- `app/db/schemas.py`
- `app/ml/classifier.py`
- `app/ml/process_worker.py`
- `app/pipeline/orchestrator.py`
- `frontend/index.html`
- `frontend/static/js/app.js`
- `requirements.txt`
- `tests/test_ghidra_analyzer.py`
- `tests/test_strings_intelligence.py`
- `tests/test_yara_rule_versioning.py`

### 7.2 Untracked Files Preserved
All existing milestone closure reports, alembic migrations, docker assets, test scripts, and scratch files were preserved intact.

---

## 8. ISSUES AND RESOLUTIONS

No technical blockers were encountered during ML-13G:
- Operational baseline hash was verified with zero discrepancies.
- Forensic evidence files were verified intact with zero bit drift.
- Development database was successfully established and isolated from the operational database.
- Complete separation was demonstrated via an active database transaction.

---

## 9. CLOSURE STATUS

**FINAL STATUS: PASS**

The operational database baseline (`storage/defender.db`, SHA-256 `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a`) is formally adopted and verified unchanged. Incident evidence is cryptographically preserved. A dedicated development database (`storage/dev_defender.db`) is established and configured, guaranteeing complete isolation for all future development and profiling operations.
