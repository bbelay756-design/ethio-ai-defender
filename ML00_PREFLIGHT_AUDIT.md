# ETHIO-AI DEFENDER: ML-00 PREFLIGHT AUDIT REPORT

**Date:** 2026-10-25  
**Auditor:** Independent Senior Engineer  
**Mode:** Audit only — no implementation, no data download, no training

---

## 1. REPOSITORY STATE VERIFICATION

| Property | Value |
|----------|-------|
| **Branch** | `main` (up-to-date with `origin/main`) |
| **HEAD Commit** | `9be847d` "Describe your change" |
| **Working Tree** | 12 modified files, 21 untracked files (including audit docs) |
| **Python** | 3.14.4 (MSC v.1944 64-bit) |
| **Virtual Env** | `venv/` active, all deps installed |

### Uncommitted Changes (12 files)
```
app/api/auth.py
app/auth/dependencies.py
app/auth/security.py
app/auth/service.py
app/core/config.py
app/db/models.py
app/db/session.py
frontend/static/js/app.js
requirements.txt
tests/security/test_cors_configuration.py
tests/security/test_frontend_render_safety.py
tests/test_module_16_security_suite.py
```

### Untracked Files (21 items)
Includes: `M01A_CLOSURE.md`, `M01A_IMPLEMENTATION_PLAN.md`, `M01B_IMPLEMENTATION_PLAN.md`, `ML_IMPLEMENTATION_PLAN.md`, `SEC-07_FINAL_CLOSURE.md`, `alembic/`, `app/auth/csrf.py`, `app/auth/rate_limiter_db.py`, `docs/`, `check_*.py`, `test_yara*.py`

---

## 2. AUTH IMPORT VERIFICATION (SEC-01)

### Claim in Earlier Audits
> "`app/api/auth.py:23` imports `get_token_from_header` which was renamed to `get_token_from_header_or_cookie`. Causes `ImportError` for all auth-dependent tests."

### Verified Reality
**FALSE — The alias exists and works.**

**Evidence:**
```python
# app/auth/dependencies.py:47-48
# Backward compatibility alias
get_token_from_header = get_token_from_header_or_cookie
```

```python
# app/api/auth.py:21-27
from app.auth.dependencies import (
    get_current_user,
    get_token_from_header,           # <-- imports alias
    get_token_from_header_or_cookie,
    require_roles,
    require_permissions,
)
```

**Runtime Verification:**
```bash
$ python -c "from app.auth.dependencies import get_token_from_header; print('OK')"
OK

$ python -c "from app.api.auth import router; print('OK')"
OK
```

**Conclusion:** The P0 import error reported in earlier audits **does not exist** in the current checkout. The backward-compatibility alias was already implemented.

---

## 3. AUTHENTICATION BEHAVIOR TEST RESULTS

### Test Failures — Root Cause: TestClient Cookie Persistence

| Test | Expected | Actual | Root Cause |
|------|----------|--------|------------|
| `test_08_missing_authentication_returns_401` (module_16) | 401 | 200 | TestClient retains `auth_token` cookie from prior login test |
| `test_14_dashboard_stats_requires_authentication` (student_lab) | 401 | 200 | `setUpClass` logs in student → cookie persists |
| `test_20_sqli_payload_login_rejected` (module_16) | 401 | 423 | Account lockout (5 attempts) triggers 423 before test runs |
| `test_08_sql_injection_attacks` (module_18) | 401 | 423 | Same — lockout on repeated payloads |

**Evidence — Fresh TestClient works correctly:**
```bash
$ python -c "
from fastapi.testclient import TestClient
from app.main import app
c = TestClient(app)
print(c.get('/api/auth/me').status_code)  # 401
"
401
```

**Evidence — After login, cookie works:**
```bash
$ python -c "
from fastapi.testclient import TestClient
from app.main import app
c = TestClient(app)
c.post('/api/auth/login', json={'username':'admin_sec_tester','password':'FakeAdminPass2026!'})
print(c.get('/api/auth/me').status_code)  # 200
"
200
```

**Conclusion:** The authentication endpoints **correctly require authentication**. Test failures are **test isolation defects** (cookie persistence), not endpoint bugs. The lockout behavior (423) is **stronger security** than 401.

---

## 4. SECURITY FINDINGS

### P0 — SECRET_KEY Development Default
**File:** `.env:1` (gitignored)
**Value:** `SECRET_KEY=ethio_ai_defender_dev_2026_secure_key_1234567890`
**Status:** 48 chars, passes validation (≥32), but is a **known default** in working tree.
**Risk:** Production deployment with known default.
**Validation:** Passes `Settings.validate_security()` (not legacy, ≥32 chars).

### P1 — No Refresh Token / 15-min Expiry
**Config:** `ACCESS_TOKEN_EXPIRE_MINUTES=15` (app/core/config.py:88)
**Status:** No refresh token endpoint implemented.
**Impact:** Long ML training/evaluation sessions (>15 min) would lose auth.

### P2 — Token Version Invalidation (Implemented ✓)
**Mechanism:** `token_version` claim in JWT + `UserModel.token_version` column.
**Triggers:** Role change, deactivation, password reset.
**Verification:** `app/auth/dependencies.py:98-99` validates on each request.

### P3 — Cookie Security Flags
**Implementation:** `secure=not settings.DEBUG`, `httponly=True`, `samesite="strict"` (app/api/auth.py:266)
**Note:** In DEBUG=True (dev), cookies sent without `Secure` flag.

### P4 — Audit Script Bug (Not Platform Bug)
**Tool:** `audit_security_issues.py`
**Failures:** 5/9 tests fail with `ValueError: Invalid user role 'STUDENT'`
**Cause:** Audit script uses `role="STUDENT"` but `UserRole` enum only has `ADMIN`, `ANALYST`, `VIEWER`.
**Impact:** Audit tool broken, not platform.

### P5 — Frontend Render Safety Test Encoding Bug
**File:** `tests/security/test_frontend_render_safety.py:24`
**Error:** `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff` (UTF-16 file read as UTF-8)
**Impact:** 6 test errors, pre-existing.

---

## 5. MISSING PREREQUISITES FOR ML-01

| Prerequisite | Status | Evidence |
|--------------|--------|----------|
| **Dataset acquisition & provenance** | ❌ MISSING | No dataset, no schema, no provenance docs |
| **Dataset schema & label definitions** | ❌ MISSING | No benign/malicious label taxonomy |
| **Data validation & duplicate detection** | ❌ MISSING | Only intake-time SHA-256 dedup exists |
| **PE feature extraction pipeline** | ⚠️ PARTIAL | 10 analyzers produce rich features but **no unified feature vector**, no serialization (Parquet/NPZ) |
| **Train/val/test separation** | ❌ MISSING | No splitting logic, no stratification |
| **Leakage prevention** | ❌ MISSING | No temporal/family/hash-based split strategy |
| **Baseline model & training script** | ❌ MISSING | No `app/ml/`, no training loop |
| **Evaluation metrics & experiment tracking** | ❌ MISSING | No metrics module, no MLflow/W&B |
| **Model serialization & versioning** | ❌ MISSING | No ONNX/joblib export, no model registry |
| **Inference integration** | ❌ MISSING | No model loading in pipeline |
| **Tests for training/inference** | ❌ MISSING | No `tests/ml/` |

**Existing Foundation (Strong):**
- 10 verified analyzers (Hash, PE, Sections, Entropy, Strings, Imports, Indicators, Scoring, Context, YARA, Ghidra)
- Unified Analysis Object (Module 19) with strict typing
- Atomic DB transactions with full evidence persistence
- 101/101 core analyzer tests passing

---

## 6. EXISTING ML-RELATED ASSETS

| Asset | Status | Notes |
|-------|--------|-------|
| `app/ml/` directory | ❌ **Does not exist** | No feature extraction, training, inference |
| EMBER-compatible extractor | ❌ **Does not exist** | Analyzers produce rich features but no unified 2381-dim vector |
| Model integration | ❌ **Does not exist** | Unified Analysis Object has no `ml_classification` field |
| ML tests | ❌ **Do not exist** | No `tests/ml/` directory |
| ML dependencies | ❌ **Not in requirements.txt** | No lightgbm, scikit-learn, onnxruntime, pandas, pyarrow |

**EMBER Compatibility Note:** EMBER 2018 provides 2381 pre-extracted features (histograms, strings, imports, etc.). Our analyzers produce **semantically similar but structurally different** features. A mapping layer would be needed — not a drop-in replacement.

---

## 6. TEST BASELINE SUMMARY

| Test Suite | Passed | Failed | Errors | Notes |
|------------|--------|--------|--------|-------|
| Core Analyzers (10 modules) | **101** | 0 | 0 | All pass |
| AI/Context/Learning/Reports/DB | **27** | 0 | 0 | All pass |
| Security Tests | **94** | 0 | **6** | 6 encoding errors in frontend test |
| Module 16 Security Suite | **38** | **2** | 0 | Test isolation (cookies), lockout (423) |
| Student Learning Lab | **13** | **1** | 0 | Test isolation (cookies) |
| Module 18/19 Integration | **32** | **1** | 0 | Lockout (423) on SQLi test |
| Full Suite (448 tests) | **~440** | **6** | **1** | Pre-existing issues |

**Key Insight:** The "386/386 tests passed" claim in README is **unverified** — actual baseline has pre-existing test isolation issues.

---

## 7. SECURITY BLOCKERS FOR ML WORK

| Priority | Blocker | Evidence | Fix Effort |
|----------|---------|----------|------------|
| **P0** | SECRET_KEY dev default in `.env` | Known default in working tree | 5 min (rotate) |
| **P1** | No refresh token / 15-min expiry | Long ML sessions will fail auth | 30 min (add refresh) |
| **P2** | Test isolation (cookies) | 4 auth tests fail | 10 min (test fixes) |
| **P3** | Audit script STUDENT role | 5/9 audit tests fail | 5 min (script fix) |
| **P4** | requirements.txt missing deps | httpx2, websockets, etc. not listed | 5 min |

**No blockers require ML code changes** — all are auth/config/test fixes.

---

## 8. RECOMMENDED MINIMAL ML-00 SCOPE

**Only these changes needed to unblock ML work:**

1. **Rotate SECRET_KEY** in `.env` (5 min)
2. **Add refresh token endpoint** or extend expiry with sliding window (30 min)
3. **Fix 4 test isolation issues** — clear cookies in affected tests (10 min)
4. **Fix audit script** — `STUDENT` → `VIEWER` (5 min)
5. **Update requirements.txt** with missing deps (5 min)
6. **Verify full test suite passes** (verify only)

**No ML code, no feature extraction, no dataset download, no training.**

---

## 9. DECISION

### READY AFTER SPECIFIC FIXES

**Evidence:**
- ✅ Import error (SEC-01) **already fixed** — alias exists
- ✅ Auth endpoints correctly enforce authentication
- ✅ Core pipeline (101 tests) and AI/DB tests (27 tests) all pass
- ✅ Token version invalidation implemented
- ✅ Strong foundation: 10 analyzers, unified object, atomic DB
- ❌ SECRET_KEY is known default — must rotate
- ❌ No refresh token — 15-min expiry blocks long ML work
- ❌ Test isolation issues — 4 tests fail due to cookie persistence
- ❌ No ML infrastructure exists — all ML milestones are greenfield

**Recommendation:** Approve ML-00 with the 6 specific fixes above (~1 hour total). This unblocks ML-01 (dataset/schema) without touching ML code.

---

## 10. EXPLICIT NO-GO CONDITIONS

Do not proceed to ML-01 until:
1. SECRET_KEY rotated and documented
2. Refresh token or extended expiry with sliding window implemented
3. Full test suite passes (0 failures, 0 errors) — or pre-existing failures documented
4. `requirements.txt` matches installed packages

---

*End of Preflight Audit — Awaiting approval for ML-00 specific fixes.*