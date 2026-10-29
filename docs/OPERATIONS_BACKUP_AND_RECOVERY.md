# ETHIO-AI DEFENDER — OPERATIONS, BACKUP, AND RECOVERY GUIDE

**Document ID:** DOC-OPS-BACKUP-01  
**Target Release:** Release-04 Stabilization / Handover  
**Scope:** Operational Database Maintenance, Disaster Recovery, and Evidence Preservation  
**Date:** October 29, 2026  

---

## 1. Operational Database Baseline

### 1.1 Formally Adopted Baseline
The operational database for ETHIO-AI Defender is persisted at [storage/defender.db](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/defender.db). Following the ML-13F forensic audit and ML-13G formal adoption, the verified production baseline parameters are:

- **Filesystem Path:** `C:\Users\MILKWAY\ethio-ai-defender\storage\defender.db`
- **File Size:** `31,719,424` bytes
- **SHA-256 Digest:** `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a`
- **Schema Head:** Alembic Revision `b2c3d4e5f6a7` (`add_analyst_reviews_table`)
- **Journal Mode:** `DELETE` (Rollback journal; zero active WAL or SHM temporary files)

### 1.2 Incident History & Rationale for Baseline Delta
- **Pre-Incident Hash:** `02d51f7a39e07b1c9716bb5420bc72d81cf6ab103580ba06aef3fe442d7aec24` (31,707,136 bytes).
- **Incident Event (ML-13E):** At 2026-10-28 22:18 UTC, an ad-hoc CLI performance benchmark executed directly outside `pytest` fell back to default configuration and committed 5 synthetic benchmark transactions (`perf_bench_sample.exe`, IDs 2637–2641).
- **Adoption Rationale:** 
  1. All 2,595 historical malware samples and 4,689 user accounts are 100% intact. Zero historical records were deleted or modified.
  2. `PRAGMA integrity_check` returned `ok`; `PRAGMA foreign_key_check` returned 0 violations.
  3. Attempting to delete the 5 synthetic rows in SQLite would NOT restore the prior binary hash due to SQLite page allocation behavior, but would leave sequence gaps and risk table fragmentation.
  4. The current database state was formally adopted under **Milestone ML-13G** as the new immutable operational baseline.

> [!CAUTION]
> **Mandatory Protection Rules:**
> 1. Never delete the 5 incident-related synthetic records (`ANL-011591` to `ANL-011595`).
> 2. Never attempt to restore pre-incident snapshots over `storage/defender.db`.
> 3. Never run development profiling, test suites, or scratch commands against `storage/defender.db`.

---

## 2. Immutable Evidence Repositories

Forensic evidence snapshots generated during incident containment (ML-13F) are frozen under [storage/evidence/incident_ml13f_20261029/](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/evidence/incident_ml13f_20261029/):

| Evidence File | File Size | Cryptographic SHA-256 Digest | Preservation Role |
| :--- | :--- | :--- | :--- |
| [`defender_raw_snapshot.db`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/evidence/incident_ml13f_20261029/defender_raw_snapshot.db) | 31,719,424 | `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a` | Forensic raw byte snapshot bit-identical to operational baseline. |
| [`defender_incident_evidence.db`](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/evidence/incident_ml13f_20261029/defender_incident_evidence.db) | 31,719,424 | `179a9359732b3087c8ebacad37369ae11e6ea16748dbe3339b7ad5abc8c62aeb` | Consistent SQLite online backup snapshot. |

*Operating Rule:* Treat all files in `storage/evidence/` as read-only. Never rename, modify, or delete evidence snapshots.

---

## 3. Hot Online Backup Procedures

To back up an active SQLite database without locking active transactions or causing file corruption, use the SQLite Online Backup API via Python.

### 3.1 Hot Online Backup Script
Execute the following automated backup command:
```powershell
python -c "
import sqlite3, datetime, pathlib
timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
backup_dir = pathlib.Path('storage/backups')
backup_dir.mkdir(parents=True, exist_ok=True)
dest_path = backup_dir / f'defender_backup_{timestamp}.db'

src = sqlite3.connect('file:storage/defender.db?mode=ro', uri=True)
dst = sqlite3.connect(str(dest_path))
with dst:
    src.backup(dst, pages=100)
src.close()
dst.close()
print(f'Online backup completed successfully: {dest_path}')
"
```

### 3.2 Backup Integrity Verification
Immediately verify the integrity and foreign-key consistency of any newly generated backup:
```powershell
python -c "
import sqlite3, sys
conn = sqlite3.connect('file:storage/backups/defender_backup_<TIMESTAMP>.db?mode=ro', uri=True)
cur = conn.cursor()
cur.execute('PRAGMA integrity_check;')
res = cur.fetchone()[0]
cur.execute('PRAGMA foreign_key_check;')
fks = cur.fetchall()
conn.close()

if res == 'ok' and len(fks) == 0:
    print('BACKUP INTEGRITY VERIFIED: OK (0 FK violations)')
else:
    print(f'BACKUP VERIFICATION FAILED: {res}, FKs: {len(fks)}')
    sys.exit(1)
"
```

---

## 4. Disaster Recovery & Restoration Procedures

### 4.1 Restoring from a Valid Backup
In the event of physical disk corruption or catastrophic host failure:

1. **Stop Application Processes:**
   ```powershell
   Get-Process -Name "python*" | Stop-Process -Force
   ```
2. **Quarantine Damaged File:**
   ```powershell
   Move-Item storage/defender.db storage/defender_corrupted.db
   ```
3. **Restore Verified Baseline:**
   ```powershell
   Copy-Item storage/evidence/incident_ml13f_20261029/defender_raw_snapshot.db storage/defender.db
   ```
4. **Verify Restored Database Digest:**
   ```powershell
   (Get-FileHash storage/defender.db -Algorithm SHA256).Hash
   ```
   *Expected:* `DDEA41F9FEB3F8AED9715E9EA0A9E536C721800D34242F66C017A641B5603D9A`

### 4.2 Resetting the Development Database
If `storage/dev_defender.db` needs to be purged of development or profiling artifacts:
```powershell
Copy-Item storage/evidence/incident_ml13f_20261029/defender_raw_snapshot.db storage/dev_defender.db -Force
```
*Note:* This safely resets the development database to the clean operational baseline without touching `storage/defender.db`.

---

## 5. Storage Maintenance & Housekeeping

### 5.1 Audit Log Rotation
- Application audit events are recorded in [storage/logs/audit.jsonl](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/logs/audit.jsonl).
- Rotating file handlers enforce a maximum size of 10 MB per file with 10 rotated backups (`AUDIT_LOG_MAX_BYTES=10485760`, `AUDIT_LOG_BACKUP_COUNT=10`).
- Ensure the disk partition hosting `storage/logs/` has at least 2 GB of free space to accommodate rotated logs.

### 5.2 Quarantine Directory Management
- Uploaded PE binaries are isolated in [storage/quarantine/](file:///C:/Users/MILKWAY/ethio-ai-defender/storage/quarantine/) with restricted permissions.
- Inactive samples older than the institutional retention window (e.g., 90 days) should be archived to encrypted cold storage. Never delete samples directly from quarantine without synchronizing database `samples` records.
