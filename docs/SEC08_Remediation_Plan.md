# ETHIO-AI DEFENDER — SEC-08 REMEDIATION PLAN

**Document ID:** PLAN-SEC-08  
**Date:** October 29, 2026  
**Engineering Authority:** Application Security & Defensive Systems Integration  
**Governing Documents:**  
- `docs/FINAL_RELEASE_READINESS_REPORT.md`  
- `docs/KNOWN_LIMITATIONS_AND_SECURITY_GATES.md`  
- `RELEASE04_Remediation_Plan.md`  
- `AUTH01_Completion_Report.md`  

---

## 1. Preflight Baseline & Environment Verification

- **Repository Root:** `C:\Users\MILKWAY\ethio-ai-defender`
- **Active Git Branch:** `my-feature-branch`
- **HEAD Commit:** `fa001120ce6b8b49bedb8ec6055e555731cff12b`
- **Tracked Modifications Preserved:** 19 files.
- **Untracked Files Preserved:** 30 files.
- **Operational Database:** `storage/defender.db`
  - SHA-256: `ddea41f9feb3f8aed9715e9ea0a9e536c721800d34242f66c017a641b5603d9a`
  - Size: `31,719,424` bytes
  - State: Read-only, zero mutations.
- **Test Database Isolation Guarantee:** Verified via `tests/conftest.py`. All automated tests dynamically bind `DATABASE_URL` to an isolated temporary directory (`tempfile.mkdtemp(prefix="defender_pytest_")`). The operational database is never bound during tests.

---

## 2. Findings Analysis & Current Code Verification

### 2.1 SEC-04-01: Unauthenticated Analysis Enumeration
- **Reported Defect:** Anonymous callers could access `GET /api/analyses` and enumerate historical analyses without authentication.
- **Code Inspection:** In `app/api/analyses.py`, `list_analyses` already enforces `current_user: UserModel = Depends(require_permissions(Permission.VIEW_AUTHORIZED_ANALYSES))`. Non-admin users are strictly scoped to their own uploaded samples plus unassigned samples (`include_unassigned=True`). Object-level authorization is enforced on individual records via `_verify_sample_access(sample, current_user)`.
- **Status:** **Remediation already present in working tree.**
- **Verification Plan:** Verify with `tests/test_auth01_authorization.py` (Tests 01, 02, 03b, 04, 05, 08).

### 2.2 SEC-04-02: Insufficient VIEWER Permissions
- **Reported Defect:** Users with `VIEWER` role could add notes, delete analyst notes, and update case priorities/status.
- **Code Inspection:** In `app/api/analyses.py`:
  - `add_sample_note`: Enforces `require_permissions(Permission.ADD_ANALYST_CONCLUSIONS)` (`VIEWER` rejected with HTTP 403).
  - `delete_sample_note`: Enforces `require_permissions(Permission.ADD_ANALYST_CONCLUSIONS)` and ownership validation (`note.user_id == current_user.id` or `current_user.role == "ADMIN"`).
  - `update_sample_case`: Enforces `require_permissions(Permission.ADD_ANALYST_CONCLUSIONS)` and validates domain values for `case_status` and `case_priority`.
- **Status:** **Remediation already present in working tree.**
- **Verification Plan:** Verify with `tests/test_auth01_authorization.py` (Tests 09, 10, 11, 12, 15, 20).

### 2.3 SEC-04-03: HTML Report Stored XSS
- **Reported Defect:** Standalone server-generated HTML reports (`GET /api/analyses/{id}/report?format=html`) interpolated binary-controlled strings, section names, and IOCs without HTML escaping.
- **Code Inspection:** In `app/api/analyses.py`, `generate_html_report_view` strictly escapes all binary-derived metadata using `_escape_html_text()`, `_escape_html_attr()`, `_sanitize_url()`, and `_format_entropy()`.
- **Status:** **Remediation already present in working tree.**
- **Verification Plan:** Verify with `tests/test_sec05_xss_remediation.py` (7 tests).

### 2.4 SEC-04-05: File Metadata Authorization
- **Reported Defect:** `GET /api/files/{analysis_id}` exposed sample metadata without authentication.
- **Code Inspection:** In `app/api/files.py`, `get_file_record` enforces `current_user: UserModel = Depends(require_permissions(Permission.VIEW_AUTHORIZED_ANALYSES))` and verifies ownership (`sample.user_id != current_user.id` -> HTTP 403). Non-existent samples return HTTP 404.
- **Status:** **Remediation already present in working tree.**
- **Verification Plan:** Verify with `tests/test_auth01_authorization.py` (Tests 03, 06, 07).

### 2.5 SEC-04-04: Analyst Review Uniqueness
- **Reported Defect:** `AnalystReviewModel.analysis_id` has an index but lacks a database-level unique constraint or unique index. Concurrent review submissions could bypass the application-layer duplicate check (`get_latest_review_for_analysis_id`), causing conflicting duplicate review records.
- **Cardinality Analysis:**
  - Business Rule: An analysis can only have **one** review decision under the ML-13 analyst-confirmation gate. `create_analysis_review` explicitly rejects repeated submissions with HTTP 409 Conflict.
  - In `SampleModel`, `reviews = relationship("AnalystReviewModel", back_populates="sample", ...)` allows accessing reviews.
  - In `storage/defender.db`, `analyst_reviews` table currently has **0** rows (table does not exist in the baseline schema at `5655c33dba69`; introduced in Alembic migration `b2c3d4e5f6a7`). Zero operational duplicates exist.
- **Required Minimal Safe Changes:**
  1. In `app/db/models.py`, define `Index("ix_analyst_reviews_analysis_id", "analysis_id", unique=True)` in `AnalystReviewModel.__table_args__` (or `unique=True` on `Index`).
  2. In `alembic/versions/b2c3d4e5f6a7_add_analyst_reviews_table.py`, ensure `op.create_index(op.f('ix_analyst_reviews_analysis_id'), 'analyst_reviews', ['analysis_id'], unique=True)` creates a unique index.
  3. In `app/db/repository.py` and `app/api/analyses.py`, handle database `IntegrityError` during review creation and map race collisions gracefully to `HTTP 409 Conflict`.
  4. In `tests/test_analyst_review_migration.py`, update index uniqueness expectations and add a race-condition duplicate rejection test.

---

## 3. Implementation Steps

1. **Apply SEC-04-04 Model & Migration Update:**
   - Update `app/db/models.py` `AnalystReviewModel`.
   - Update `alembic/versions/b2c3d4e5f6a7_add_analyst_reviews_table.py`.
   - Update `app/api/analyses.py` to catch `IntegrityError` in `create_analysis_review`.
2. **Execute Regression Test Suite:**
   - Run `tests/test_auth01_authorization.py`.
   - Run `tests/test_sec05_xss_remediation.py`.
   - Run `tests/test_analyst_review_migration.py`.
   - Run relevant security, authentication, and API test suites.
3. **Verify Database Integrity:**
   - Confirm `storage/defender.db` hash is unchanged (`ddea41f9...`).
4. **Produce Deliverable Report:**
   - Generate `docs/SEC08_Security_Remediation_Report.md`.
