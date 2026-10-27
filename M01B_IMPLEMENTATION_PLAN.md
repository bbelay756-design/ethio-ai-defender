# ETHIO-AI DEFENDER — MILESTONE M01B: AUTHENTICATION BEHAVIOR ALIGNMENT & SECURITY HARDENING PLAN (REVISED)

**Date:** 2026-10-25  
**Author:** Independent Application Security Engineer & Python Test Engineer  
**Status:** PLAN ONLY — No implementation performed

---

## 1. VERIFIED FINDINGS VS. UNRESOLVED HYPOTHESES

### 1.1 Authentication Endpoint Failures — RESOLVED (Test Contamination)

| Test | Expected | Actual | Root Cause |
|------|----------|--------|------------|
| `test_08_missing_authentication_returns_401` | 401 + "Missing Authorization header" | 401 + "Missing authentication. Provide Authorization header or auth_token cookie." | TestClient cookie persistence — prior login test sets `auth_token` cookie; endpoint correctly returns 401 but error message differs |
| `test_14_dashboard_stats_requires_authentication` | 401 | 200 | TestClient cookie persistence — `setUpClass` logs in student, sets `auth_token` cookie; subsequent GET uses cookie |

**Evidence:**
```bash
# Fresh TestClient — no cookies
$ python -c "from fastapi.testclient import TestClient; from app.main import app; c=TestClient(app); print(c.get('/api/auth/me').status_code)"
401

# After login — cookie set
$ python -c "
from fastapi.testclient import TestClient
from app.main import app
c=TestClient(app)
c.post('/api/auth/login', json={'username':'admin_sec_tester','password':'FakeAdminPass2026!'})
print(c.get('/api/auth/me').status_code)
"
200
```

**Conclusion:** Endpoints correctly require authentication. Test failures are **test isolation defects**, not endpoint bugs. The `auth_token` cookie (HttpOnly, SameSite=strict) is automatically sent by TestClient after login.

### 1.2 SQL Injection & Account Lockout — VERIFIED BEHAVIOR

**Lockout threshold:** 5 failed attempts (config: `MAX_FAILED_LOGIN_ATTEMPTS=5`)

| Attempt | Password | Response |
|---------|----------|----------|
| 1-4 | Injection payloads | 401 "Invalid username or password." |
| 5 | Injection payload | **423** "Account locked for 15 minutes due to excessive failed attempts." |
| 6+ | Any | **423** "Account is temporarily locked. Please try again in 15 minutes." |
| Correct password (while locked) | Valid | **423** (lockout takes precedence) |

**Test behavior:** SQLi tests iterate multiple payloads for same username → triggers lockout → 423.

**Security assessment:** 423 is **correct and stronger** than 401. Lockout prevents credential stuffing. Tests misaligned with security design.

### 1.3 Audit Script Role — CONFIRMED DEFECT

**File:** `audit_security_issues.py` — 4 occurrences of `role="STUDENT"` (lines 125, 144, 163, 189, 190)

**UserRole enum** (`app/auth/roles.py`): `ADMIN`, `ANALYST`, `VIEWER` — no `STUDENT`.

**Impact:** 4/9 audit tests fail on registration with `ValueError: Invalid user role 'STUDENT'`.

**Fix:** Replace `STUDENT` → `VIEWER` (preserves test intent: non-admin role).

### 1.4 SECRET_KEY Configuration — VERIFIED

| Property | Value | Assessment |
|----------|-------|------------|
| `.env` tracked? | **No** (gitignored) | ✅ Safe |
| Current key length | 48 chars | ✅ ≥32 minimum |
| Legacy insecure secret? | `ethio-ai-defender-secure-platform-master-key-2026` | ✅ Not in use |
| Validation | Passes `validate_security()` | ✅ |
| DEBUG default | `True` (from env default) | ⚠️ Cookie `Secure` flag = `not DEBUG` → cookies sent without Secure flag in dev |
| Token invalidation on rotation | `token_version` mechanism + HMAC secret change | ✅ Works |

**Risk:** Known development default in `.env` (working tree). Must rotate for production.

---

## 2. MINIMAL IMPLEMENTATION SCOPE

### 2.1 Test Fixes (Isolation Only)

| File | Test | Change |
|------|------|--------|
| `tests/test_module_16_security_suite.py` | `test_08_missing_authentication_returns_401` | Clear cookies before request OR update expected error message to match current behavior |
| `tests/test_student_learning_lab.py` | `test_14_dashboard_stats_requires_authentication` | Clear cookies before request (use fresh TestClient or `client.cookies.clear()`) |
| `tests/security/test_injection_and_xss.py` | `test_01_sqli_login_bypass_neutralized` | Use isolated user per payload OR reset rate limiter between attempts |
| `tests/test_module_16_security_suite.py` | `test_20_sqli_payload_login_rejected`, `test_21_sql_comment_payload_login_rejected` | Same as above |
| `tests/test_module_18_security_attacks.py` | `test_08_sql_injection_attacks` | Same as above |

**Approach:** Each SQLi test gets fresh username OR rate limiter reset. No weakening of lockout.

### 2.2 Audit Script Fix

| File | Lines | Change |
|------|-------|--------|
| `audit_security_issues.py` | 125, 144, 163, 189, 190 | `role="STUDENT"` → `role="VIEWER"` |

### 2.3 SECRET_KEY Hygiene

| File | Change |
|------|--------|
| `.env` | Document rotation procedure; **do not auto-rotate** (requires approval) |
| `app/core/config.py` | Add warning when `DEBUG=True` and default key detected |
| `README.md` | Document SECRET_KEY rotation + token invalidation |

---

## 3. EXACT FILES TO CHANGE

| File | Type | Lines | Justification |
|------|------|-------|---------------|
| `tests/test_module_16_security_suite.py` | Test fix | ~148-152, 347, 356 | Clear cookies or use fresh client for auth-negative tests; isolate SQLi users |
| `tests/test_student_learning_lab.py` | Test fix | ~247-250 | Clear cookies before dashboard-stats test |
| `tests/security/test_injection_and_xss.py` | Test fix | ~41 | Isolate SQLi test users |
| `tests/test_module_18_security_attacks.py` | Test fix | ~212 | Isolate SQLi test users |
| `audit_security_issues.py` | Script fix | 125, 144, 163, 189, 190 | `STUDENT` → `VIEWER` |
| `app/core/config.py` | Enhancement | ~31 | Warn on dev default key with DEBUG=True |
| `README.md` | Documentation | — | Rotation procedure + token invalidation notes |

---

## 4. ACCEPTANCE CRITERIA (OBSERVABLE EVIDENCE)

| Criterion | Verification Command | Pass Condition |
|-----------|---------------------|----------------|
| `/api/auth/me` without creds → 401 | `pytest tests/test_module_16_security_suite.py::TestComprehensiveSecurityModule16::test_08_missing_authentication_returns_401 -v` | Status 401; detail contains "Missing authentication" |
| `/api/learning/dashboard-stats` without creds → 401 | `pytest tests/test_student_learning_lab.py::TestStudentLearningLab::test_14_dashboard_stats_requires_authentication -v` | Status 401 |
| SQLi payloads → 401 (not lockout) | `pytest tests/security/test_injection_and_xss.py::TestInjectionAndXSS::test_01_sqli_login_bypass_neutralized -v` | Status 401 for each payload |
| SQLi lockout tests aligned | `pytest tests/test_module_16_security_suite.py::TestComprehensiveSecurityModule16::test_20_sqli_payload_login_rejected -v` | Status 401 (isolated user) or 423 documented |
| Audit script executes | `python audit_security_issues.py` | 9/9 tests pass |
| Full regression | `python -m pytest tests/ -v --tb=short 2>&1 | tail -20` | 0 failures (or only pre-existing non-M01B failures) |
| Config warning | `python -c "from app.core.config import settings; print('WARN' if settings.DEBUG and 'dev' in settings.SECRET_KEY.lower() else 'OK')"` | Warning emitted for dev default |
| No unrelated modifications | `git diff --stat` | Only listed files changed |

---

## 5. TEST PLAN

### 5.1 Focused Test Commands

```bash
# 1. Auth negative test isolation
python -m pytest tests/test_module_16_security_suite.py::TestComprehensiveSecurityModule16::test_08_missing_authentication_returns_401 -v
python -m pytest tests/test_student_learning_lab.py::TestStudentLearningLab::test_14_dashboard_stats_requires_authentication -v

# 2. SQLi injection tests (isolated users)
python -m pytest tests/security/test_injection_and_xss.py::TestInjectionAndXSS::test_01_sqli_login_bypass_neutralized -v
python -m pytest tests/test_module_16_security_suite.py::TestComprehensiveSecurityModule16::test_20_sqli_payload_login_rejected -v
python -m pytest tests/test_module_16_security_suite.py::TestComprehensiveSecurityModule16::test_21_sql_comment_payload_login_rejected -v
python -m pytest tests/test_module_18_security_attacks.py::TestModule18SecurityAttackVectors::test_08_sql_injection_attacks -v

# 3. Audit script
python audit_security_issues.py

# 4. Full regression (Windows-compatible)
python -m pytest tests/ -v --tb=short 2>&1
```

### 5.2 Expected Security Assertions

| Test | Assertion Type | Negative Case |
|------|----------------|---------------|
| `test_08_missing_authentication_returns_401` | Auth required | Valid token → 200 |
| `test_14_dashboard_stats_requires_authentication` | Auth required | Valid token → 200 |
| `test_01_sqli_login_bypass_neutralized` | Injection neutralized | Valid password → 200 |
| SQLi lockout tests | Lockout functions | Correct password after 5 fails → 423 |

### 5.3 Distinguishing Pre-existing vs. Regression Failures

- **Pre-existing (non-M01B):** None expected after fixes
- **Regression indicator:** Any test that passed in baseline (§1.1) now fails
- **Verification:** Run full suite before and after changes; diff results

### 5.4 Final Diff Check

```bash
git diff --stat
# Verify only these files modified:
# tests/test_module_16_security_suite.py
# tests/test_student_learning_lab.py
# tests/security/test_injection_and_xss.py
# tests/test_module_18_security_attacks.py
# audit_security_issues.py
# app/core/config.py
# README.md
```

---

## 6. ROLLBACK STRATEGY (PRESERVES UNCOMMITTED WORK)

```bash
# Rollback individual test files
git checkout HEAD -- tests/test_module_16_security_suite.py
git checkout HEAD -- tests/test_student_learning_lab.py
git checkout HEAD -- tests/security/test_injection_and_xss.py
git checkout HEAD -- tests/test_module_18_security_attacks.py

# Rollback audit script
git checkout HEAD -- audit_security_issues.py

# Rollback config/docs
git checkout HEAD -- app/core/config.py
git checkout HEAD -- README.md
```

**Guarantees:**
- ✅ Uncommitted files (`.env`, `alembic/`, `docs/`, `app/auth/csrf.py`, etc.) untouched
- ✅ Only tracked files in `git status` modified
- ✅ No `git reset`, `git stash`, or history rewriting

---

## 7. DEFERRED FINDINGS (LATER MILESTONES)

| Finding | Deferred To | Reason |
|---------|-------------|--------|
| DEBUG=True default → cookie Secure flag | M02 (Production Hardening) | Requires deployment config review |
| Token refresh / sliding window | M02 (Session Management) | UX improvement, not security defect |
| PDF report renderer | M03 (Reporting) | Feature gap, not security |
| STUDENT role in production RBAC | M04 (RBAC Expansion) | Requires permission matrix design |
| CI/CD pipeline | M05 (Operations) | Infrastructure |
| Dependency scanning (pip-audit) | M05 (Supply Chain) | Operational |
| ML classifier infrastructure | M10 (Milestone 1) | Core product objective |

---

## 8. CONCLUSION

**M01B Scope:** Test isolation fixes (4 files), audit script role correction (1 file), config warning + docs (2 files). **No production authentication logic changes.**

**Risk:** LOW — all changes are test/script/config only. Lockout behavior preserved (stronger security). Token invalidation on secret rotation verified.

**Next Step:** Review and approve plan → implement → verify acceptance criteria.

*End of Revised Plan — Awaiting explicit approval before implementation.*