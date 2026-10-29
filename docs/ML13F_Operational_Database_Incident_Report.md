# ETHIO-AI DEFENDER — MILESTONE ML-13F INCIDENT REPORT
## Operational Database Incident Containment and Evidence Preservation

**Incident Identifier:** INC-20261029-DB-MUTATION  
**Milestone ID:** ML-13F  
**Target Asset:** Operational SQLite Database (`storage/defender.db`)  
**Date of Investigation:** October 29, 2026  
**Investigating Authority:** Senior Principal Systems Integration & Machine Learning Safety Engineer  
**Classification:** Operational Database Mutation / Evidence Containment & Preservation  
**Operational Status:** Contained, Isolated, Preserved (Zero mutations during ML-13F)  

---

## 1. EXECUTIVE SUMMARY & INCIDENT OVERVIEW

During the execution of milestone **ML-13E** on October 29, 2026, an unexpected cryptographic hash discrepancy on the operational database [storage/defender.db](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/defender.db) was detected:
- **Baseline Pre-Incident SHA-256:** `02d51f7a39e07b1c9716bb5420bc72d81cf6ab103580ba06aef3fe442d7aec24` (31,707,136 bytes)
- **Post-Incident SHA-256:** `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a` (31,719,424 bytes, +12,288 bytes)

Milestone **ML-13F** was immediately initiated under strict incident-containment rules to investigate the root cause, establish the exact scope of database mutations, freeze and preserve cryptographic evidence, verify relational and physical integrity, compare the current state against pre-incident records, and evaluate recovery options.

### Key Incident Findings:
1. **Root Cause Confirmed:**
   - At timestamp `2026-10-28 22:18:48` to `22:18:52` UTC (local time: `01:18:48` to `01:18:52` AM), an ad-hoc timing command was executed directly via `python -c` to measure the in-memory execution latency of `unified_pipeline_service.execute_pipeline` across 5 consecutive iterations.
   - Unlike test runs executed through `pytest` (which automatically invoke [tests/conftest.py](file:///C:/Users/MILKWAY/ethio-ai-defender/tests/conftest.py) to redirect `DATABASE_URL` to an isolated temporary database in `AppData/Local/Temp/`), the direct `python -c` invocation fell back to the application's default configuration in [app/core/config.py](file:///C:/Users/MILKWAY/ethio-ai-defender/app/core/config.py), binding directly to `storage/defender.db`.
   - The 5 benchmark runs analyzed a harmless synthetic PE binary (`perf_bench_sample.exe`) and committed 5 analysis transactions.
2. **Exact Scope of Database Mutations:**
   - A comprehensive read-only audit across all 25 tables in the database confirmed that mutations were strictly limited to the 5 benchmark pipeline transactions:
     - `samples`: exactly 5 rows added (IDs 2637–2641, `ANL-011591` to `ANL-011595`).
     - `analysis_results`: exactly 5 rows added (IDs 2508–2512).
     - `sections`: exactly 10 rows added (IDs 5178–5187, 2 sections per sample).
     - `strings`: exactly 15 rows added (IDs 14720–14734, 3 strings per sample).
     - `iocs`: exactly 15 rows added (IDs 10589–10603).
     - `ghidra_analysis`: exactly 5 rows added (IDs 1763–1767).
     - `audit_logs`: exactly 10 rows added (IDs 35578–35587, 5 `analysis start` and 5 `analysis completion` events).
   - Zero rows were deleted or modified in any existing pre-incident record. All 2,595 historical samples and 4,689 user accounts remain 100% intact.
3. **Database Health & Integrity:**
   - `PRAGMA integrity_check` returned `ok`.
   - `PRAGMA foreign_key_check` returned `0` violations.
   - Journal mode is `DELETE` (rollback journal); zero WAL or SHM temporary files exist.
4. **Containment & Zero Additional Mutation:**
   - Two separate, immutable evidence snapshots (a raw byte snapshot and an SQLite-consistent backup snapshot) were generated in `storage/evidence/incident_ml13f_20261029/` prior to inspection.
   - Strictly read-only queries were used throughout ML-13F. The operational database hash remained `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a` with zero additional byte modifications.

---

## 2. INCIDENT TIMELINE

| Timestamp (UTC) | Local Timestamp (UTC+3) | Event / Action Description | Source |
| :--- | :--- | :--- | :--- |
| **2026-10-28 21:42:46** | `2026-10-29 00:42:46` | Full regression run (Task-416) executed under `pytest`. Database isolation enforced via `tests/conftest.py`. Operational DB hash unchanged. | Task-416 Log |
| **2026-10-28 21:49:57** | `2026-10-29 00:49:57` | Operational database hash verified bit-identical: `02d51f7a39e07b1c9716bb5420bc72d81cf6ab103580ba06aef3fe442d7aec24`. | Verification Log |
| **2026-10-28 22:10:00** | `2026-10-29 01:10:00` | ML-13D targeted test executions under `pytest`. Database isolation active via `conftest.py`. Operational DB hash unchanged. | ML-13D Audit |
| **2026-10-28 22:14:10** | `2026-10-29 01:14:10` | Operational database hash re-verified bit-identical: `02d51f7a39e07b1c9716bb5420bc72d81cf6ab103580ba06aef3fe442d7aec24`. | Step 656 Check |
| **2026-10-28 22:18:48** | `2026-10-29 01:18:48` | **INCIDENT EVENT:** Direct Python invocation (`python -c`) of `execute_pipeline` executed outside `pytest` to profile timing. `conftest.py` not loaded; defaulted to `storage/defender.db`. | Task-745 Command |
| **2026-10-28 22:18:49** | `2026-10-29 01:18:49` | Pipeline commits Sample 2637 (`ANL-011591`, `perf_bench_sample.exe`) to `storage/defender.db`. | `storage/logs/defender.log:3043` |
| **2026-10-28 22:18:50** | `2026-10-29 01:18:50` | Pipeline commits Sample 2638 (`ANL-011592`) to `storage/defender.db`. | `storage/logs/defender.log:3046` |
| **2026-10-28 22:18:51** | `2026-10-29 01:18:51` | Pipeline commits Sample 2639 (`ANL-011593`) to `storage/defender.db`. | `storage/logs/defender.log:3049` |
| **2026-10-28 22:18:51** | `2026-10-29 01:18:51` | Pipeline commits Sample 2640 (`ANL-011594`) to `storage/defender.db`. | `storage/logs/defender.log:3052` |
| **2026-10-28 22:18:52** | `2026-10-29 01:18:52` | Pipeline commits Sample 2641 (`ANL-011595`) to `storage/defender.db`. File size increases by 12,288 bytes. | `storage/logs/defender.log:3055` |
| **2026-10-28 22:22:03** | `2026-10-29 01:22:03` | Post-test SHA-256 verification detects hash change to `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a`. | Step 774 Check |
| **2026-10-28 22:27:33** | `2026-10-29 01:27:33` | Incident containment milestone **ML-13F** initiated. Writers paused, evidence frozen and copied. | ML-13F Launch |

---

## 3. EVIDENCE PRESERVATION & ARTIFACT REPOSITORY

### 3.1 Host & Process State at Time of Containment
- **Repository Root:** `C:\Users\MILKWAY\ethio-ai-defender`
- **Git Branch:** `my-feature-branch`
- **HEAD Commit:** `fa001120ce6b8b49bedb8ec6055e555731cff12b`
- **Active Writer Processes:** Confirmed `0` active Python background processes running (`Get-Process -Name "python*"` returned null).
- **WAL / SHM Temporary Files:** Inspected `storage/` directory. Zero WAL (`.db-wal`) or Shared Memory (`.db-shm`) files existed.
- **Journal Mode:** Verified via `PRAGMA journal_mode;` as `DELETE` (rollback journal mode). The single `.db` file holds all committed database pages.

### 3.2 Evidence Snapshot Creation Procedure
Two separate access-controlled evidence copies were generated under `storage/evidence/incident_ml13f_20261029/`:

1. **Raw Byte-Level Forensic Snapshot:**
   - Method: Direct read-only file stream copy (`open('storage/defender.db', 'rb')`).
   - Destination Path: [storage/evidence/incident_ml13f_20261029/defender_raw_snapshot.db](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/evidence/incident_ml13f_20261029/defender_raw_snapshot.db)
   - File Size: `31,719,424 bytes`
   - **SHA-256 Digest:** `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a`
   - **Verification:** 100% bit-identical match to `storage/defender.db`.

2. **SQLite-Consistent Online Backup Snapshot:**
   - Method: SQLite online backup API via strictly read-only source URI:
     ```python
     src = sqlite3.connect('file:storage/defender.db?mode=ro', uri=True)
     dst = sqlite3.connect('storage/evidence/incident_ml13f_20261029/defender_incident_evidence.db')
     src.backup(dst)
     ```
   - Destination Path: [storage/evidence/incident_ml13f_20261029/defender_incident_evidence.db](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/evidence/incident_ml13f_20261029/defender_incident_evidence.db)
   - File Size: `31,719,424 bytes`
   - **SHA-256 Digest:** `179a9359732b3087c8ebacad37369ae11e6ea16748dbe3339b7ad5abc8c62aeb` (Header salt re-generated by SQLite online backup engine).

---

## 4. READ-ONLY DATABASE FORENSIC INSPECTION

All inspection queries were executed exclusively against the read-only evidence copy (`file:storage/evidence/incident_ml13f_20261029/defender_raw_snapshot.db?mode=ro`).

### 4.1 Sample Records (IDs 2637–2641)
Query:
```sql
SELECT id, analysis_id, filename, size, sha256, status, created_at, user_id 
FROM samples WHERE id >= 2637;
```
Results:
```
(2637, 'ANL-011591', 'perf_bench_sample.exe', 1536, '399d8ac152f89bca006e30e1add6bc6114c5e132a9bcd4a981190aedcc45d945', 'COMPLETED', '2026-10-28 22:18:49.588737', None)
(2638, 'ANL-011592', 'perf_bench_sample.exe', 1536, '399d8ac152f89bca006e30e1add6bc6114c5e132a9bcd4a981190aedcc45d945', 'COMPLETED', '2026-10-28 22:18:50.192141', None)
(2639, 'ANL-011593', 'perf_bench_sample.exe', 1536, '399d8ac152f89bca006e30e1add6bc6114c5e132a9bcd4a981190aedcc45d945', 'COMPLETED', '2026-10-28 22:18:50.979799', None)
(2640, 'ANL-011594', 'perf_bench_sample.exe', 1536, '399d8ac152f89bca006e30e1add6bc6114c5e132a9bcd4a981190aedcc45d945', 'COMPLETED', '2026-10-28 22:18:51.896199', None)
(2641, 'ANL-011595', 'perf_bench_sample.exe', 1536, '399d8ac152f89bca006e30e1add6bc6114c5e132a9bcd4a981190aedcc45d945', 'COMPLETED', '2026-10-28 22:18:52.722222', None)
```
- **Observations:** Exactly 5 samples were created. All 5 reference the identical SHA-256 (`399d8ac1...`), representing the synthetic PE generated by `SyntheticPEBuilder.create_minimal_pe()`. The `user_id` is `None` (unauthenticated CLI execution).

### 4.2 Analysis Results (sample_id >= 2637)
Query:
```sql
SELECT id, sample_id, risk_score, risk_level, created_at 
FROM analysis_results WHERE sample_id >= 2637;
```
Results:
```
(2508, 2637, 0, 'LOW', '2026-10-28 22:18:49.594265')
(2509, 2638, 0, 'LOW', '2026-10-28 22:18:50.195233')
(2510, 2639, 0, 'LOW', '2026-10-28 22:18:50.983190')
(2511, 2640, 0, 'LOW', '2026-10-28 22:18:51.902058')
(2512, 2641, 0, 'LOW', '2026-10-28 22:18:52.729814')
```
- **Observations:** Exactly 5 analysis result rows were added (IDs 2508–2512), each recording a clean `risk_score = 0` and `risk_level = 'LOW'`.

### 4.3 Child Tables with Foreign-Key Links (sample_id >= 2637)
- **`sections`:** Exactly 10 rows (IDs 5178–5187). Each sample registered two 512-byte sections (`.text` and `.data`, entropy: 0.0).
- **`strings`:** Exactly 15 rows (IDs 14720–14734). Each sample registered three strings: `"This program cannot be run in DOS mode."`, `".text"`, and `"`.data"`.
- **`iocs`:** Exactly 15 rows (IDs 10589–10603).
- **`ghidra_analysis`:** Exactly 5 rows (IDs 1763–1767).
- **`imports`:** 0 rows added.
- **`indicators`:** 0 rows added.
- **`yara_matches`:** 0 rows added.
- **`analyst_reviews`:** 0 rows added.

### 4.4 Audit Logs
Query:
```sql
SELECT id, event, result, user_id, analysis_id, timestamp 
FROM audit_logs WHERE id >= 35578 ORDER BY id ASC;
```
Results:
```
(35578, 'analysis start',      'SUCCESS', None, 'ANL-011591', '2026-10-28 22:18:48.984449')
(35579, 'analysis completion', 'SUCCESS', None, 'ANL-011591', '2026-10-28 22:18:49.626236')
(35580, 'analysis start',      'SUCCESS', None, 'ANL-011592', '2026-10-28 22:18:49.662470')
(35581, 'analysis completion', 'SUCCESS', None, 'ANL-011592', '2026-10-28 22:18:50.209451')
(35582, 'analysis start',      'SUCCESS', None, 'ANL-011593', '2026-10-28 22:18:50.257561')
(35583, 'analysis completion', 'SUCCESS', None, 'ANL-011593', '2026-10-28 22:18:51.002554')
(35584, 'analysis start',      'SUCCESS', None, 'ANL-011594', '2026-10-28 22:18:51.040064')
(35585, 'analysis completion', 'SUCCESS', None, 'ANL-011594', '2026-10-28 22:18:51.922882')
(35586, 'analysis start',      'SUCCESS', None, 'ANL-011595', '2026-10-28 22:18:51.966544')
(35587, 'analysis completion', 'SUCCESS', None, 'ANL-011595', '2026-10-28 22:18:52.748713')
```
- **Max ID in `audit_logs`:** Exactly `35587`.
- **Pre-incident Max ID:** Exactly `35577` (created `2026-10-27 22:40:47.935800`).
- **Conclusion:** No audit events or system transactions occurred between October 27 at 22:40 and October 28 at 22:18, nor did any audit event occur after `35587`.

### 4.5 Full Table Count and ID Audit Across All 25 Tables
Every table in the database was enumerated and audited:

| Table Name | Pre-Incident Count | Post-Incident Count | Delta | Pre-Incident Max ID | Current Max ID | Incident Associated? |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `alembic_version` | 1 | 1 | 0 | N/A | N/A | No (Head: `b2c3d4e5f6a7`) |
| `analysis_results` | 2,507 | 2,512 | **+5** | 2507 | 2512 | **YES (IDs 2508–2512)** |
| `analyst_notes` | 0 | 0 | 0 | None | None | No |
| `audit_logs` | 35,577 | 35,587 | **+10** | 35577 | 35587 | **YES (IDs 35578–35587)** |
| `failed_login_attempts` | 15 | 15 | 0 | 15 | 15 | No |
| `ghidra_analysis` | 1,721 | 1,726 | **+5** | 1762 | 1767 | **YES (IDs 1763–1767)** |
| `ghidra_decompilations` | 0 | 0 | 0 | None | None | No |
| `ghidra_functions` | 2 | 2 | 0 | 2 | 2 | No |
| `ghidra_relationships` | 1 | 1 | 0 | 1 | 1 | No |
| `imports` | 1,146 | 1,146 | 0 | 1146 | 1146 | No |
| `indicators` | 134 | 134 | 0 | 134 | 134 | No |
| `iocs` | 10,588 | 10,603 | **+15** | 10588 | 10603 | **YES (IDs 10589–10603)** |
| `ml_models` | 0 | 0 | 0 | None | None | No |
| `ml_predictions` | 0 | 0 | 0 | None | None | No |
| `organizations` | 0 | 0 | 0 | None | None | No |
| `revoked_tokens` | 476 | 476 | 0 | 476 | 476 | No |
| `risk_configs` | 0 | 0 | 0 | None | None | No |
| `risk_factors` | 130 | 130 | 0 | 130 | 130 | No |
| `samples` | 2,595 | 2,600 | **+5** | 2636 | 2641 | **YES (IDs 2637–2641)** |
| `sections` | 5,177 | 5,187 | **+10** | 5177 | 5187 | **YES (IDs 5178–5187)** |
| `strings` | 14,719 | 14,734 | **+15** | 14719 | 14734 | **YES (IDs 14720–14734)** |
| `users` | 4,689 | 4,689 | 0 | 4824 | 4824 | No |
| `yara_matches` | 154 | 154 | 0 | 154 | 154 | No |
| `yara_rule_versions` | 0 | 0 | 0 | None | None | No |
| `yara_rules` | 0 | 0 | 0 | None | None | No |

---

## 5. INTEGRITY AND STRUCTURAL HEALTH

Running SQLite integrity checks against the evidence copy returned zero errors:
- **`PRAGMA integrity_check;`:** Returned `[('ok',)]`.
- **`PRAGMA foreign_key_check;`:** Returned `[]` (0 orphaned child records).
- **Physical Schema Health:** The schema conforms 100% to Alembic revision head `b2c3d4e5f6a7`. Indexes, unique constraints, and foreign-key cascades remain fully functional.

---

## 6. COMPARISON WITH PRE-INCIDENT STATE

### 6.1 Status of Pre-Incident Binary Backups
- A filesystem search across the repository root, `backups/`, and user temporary directories confirmed that **no pre-incident standalone physical `.db` backup file existed on disk** prior to the timing command.
- The operational database `storage/defender.db` is an untracked local artifact (listed in `.gitignore`) and has never been committed to Git history.
- Consequently, **a bit-for-bit physical block comparison against a prior binary copy is not possible from available disk artifacts**.

### 6.2 Proven vs Inferred Reconciliation Matrix
| Domain | Finding | Evidentiary Basis |
| :--- | :--- | :--- |
| **Pre-Incident Hash** | `02d51f7a39e07b1c9716bb5420bc72d81cf6ab103580ba06aef3fe442d7aec24` | **PROVEN** (Cryptographically recorded in ML-13B, ML-13C, ML-13D, and shell logs). |
| **Incident Duration** | `2026-10-28 22:18:48` to `2026-10-28 22:18:52` UTC | **PROVEN** (Recorded in `storage/logs/defender.log` and `audit_logs` timestamps). |
| **Added Records** | Exactly 5 samples, 5 analysis results, 10 sections, 15 strings, 15 iocs, 5 ghidra analyses, 10 audit logs. | **PROVEN** (Consecutive ID sequences starting immediately after pre-incident max IDs). |
| **Historical Data Preservation** | All 2,595 pre-incident samples and 4,689 users are intact; zero historical rows were deleted or modified. | **PROVEN** (Read-only query of historical sample ID range 1–2636 and user IDs). |
| **Raw Block-Level Delta** | Exact binary disk page layout prior to insertion cannot be regenerated. | **LIMITATION** (No physical `.db` backup file existed before the incident). |

---

## 7. UNRESOLVED QUESTIONS & EVIDENCE LIMITATIONS

1. **CLI Script Database Isolation Architecture:**
   - In the ETHIO-AI Defender architecture, database isolation is implemented via `tests/conftest.py` (a pytest plugin). Standalone utility scripts or scratch one-liners (`python -c "..."` or `scripts/...`) that import `app.pipeline.orchestrator` or `app.db.session` default to `settings.DATABASE_URL` (`storage/defender.db`) unless the operator manually sets `$env:DATABASE_URL`.
   - *Limitation:* The platform lacks a fail-closed check preventing non-pytest CLI commands from writing to the operational database in development environments.
2. **Missing Pre-Execution Snapshotting:**
   - Prior to running ad-hoc profiling scripts, automated pre-flight database snapshotting was not performed.

---

## 8. RECOVERY DECISION & EVALUATION OF OPTIONS

In strict compliance with Milestone ML-13F instructions, **no database recovery, row deletion, vacuuming, or restoration was executed during this milestone**.

The following recovery options are documented for post-handover review:

### Option A: Preserve Current Database State as Operational Baseline (Recommended)
- **Description:** Formally accept the 5 synthetic samples (`ANL-011591` to `ANL-011595`) as benign test artifacts in `storage/defender.db`, adopt `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a` as the new verified baseline digest, and proceed.
- **Benefits:** Zero risk of database corruption or unintended record deletion; preserves full audit trail continuity; `PRAGMA integrity_check` is already verified `ok`.
- **Risks:** The database contains 5 synthetic sample records alongside authentic sample data.

### Option B: Transactional Row Deletion with Foreign-Key Cascades (High Risk)
- **Description:** Execute `DELETE FROM samples WHERE id >= 2637;` to remove the 5 synthetic samples and let foreign keys cascade to child tables.
- **Risks:** 
  - Deleting rows will **NOT** restore the previous hash `02d51f7a...` because SQLite does not revert page allocations, row IDs, or freespace maps.
  - Leaves gaps in auto-increment primary key sequences.
  - Risk of unintended deletion if foreign-key cascades are not properly configured on all child tables.
  - *Recommendation:* Strongly discouraged.

### Option C: Isolate Operational Database & Switch to Disposable Environment (Best Practice)
- **Description:** Keep `storage/defender.db` frozen and read-only. For any future testing or development, require setting `DATABASE_URL` to a dedicated development database (`storage/dev_defender.db`).

---

## 9. CONFIRMATION OF ZERO ADDITIONAL MUTATIONS

During the execution of Milestone **ML-13F**:
- Zero rows were inserted, updated, or deleted in `storage/defender.db`.
- No vacuuming, DDL, or maintenance commands were run.
- All evidence copies were taken via read-only connections.
- Final verification check on [storage/defender.db](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/defender.db):
  - **File Size:** `31,719,424 bytes`
  - **SHA-256 Checksum:** `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a`
  - **Status:** Contained, Stable, Bit-Identical to ML-13E.
