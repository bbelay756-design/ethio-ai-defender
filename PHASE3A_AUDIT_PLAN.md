# ETHIO-AI Defender — M02B Phase 3A: Version-Aware YARA Scanning — Audit & Implementation Plan

## 1. Current Repository State

### 1.1 Git State
- **Branch**: `main`
- **Status**: Modified files: `app/db/models.py`, `app/db/schemas.py`, `app/db/session.py`
- **Untracked**: Phase 2 migration, service, tests, and numerous report files

### 1.2 Focused Test Results
```
venv\Scripts\python.exe -m pytest tests/test_yara_rule_versioning.py -q
# 37 passed, 33 warnings in 14.94s
```

### 1.3 Files Inspected

| File | Purpose |
|------|---------|
| `app/analyzers/yara_analyzer.py` | YARA scanning service (file-based rules) |
| `app/pipeline/orchestrator.py` | Analysis pipeline orchestration (lines 313-328, 622-630) |
| `app/db/repository.py` | `save_full_analysis_transaction` (lines 195-316) |
| `app/db/models.py` | `YaraRuleModel`, `YaraRuleVersionModel`, `YaraMatchModel` |
| `app/db/schemas.py` | `YaraMatchCreate`, `YaraMatchRead`, `YaraRuleCreate`, etc. |
| `app/services/yara_rule_publication_service.py` | Phase 2 publication service |
| `app/db/session.py` | Lightweight SQLite migrations |
| `alembic/versions/a1b2c3d4e5f6_add_yara_rule_versioning.py` | Migration |
| `tests/test_yara_rule_versioning.py` | 37 tests |

## 2. Current YARA Scan-to-Persistence Flow

### 2.1 Flow Diagram

```
File Intake → orchestrator.run_analysis()
  → Stage 11b: yara_analyzer_service.scan_bytes(content)
    → Loads .yar/.yara files from rules/ directory
    → Compiles with yara.compile(filepaths=...)
    → Matches against binary bytes
    → Returns YaraScanResult with list of YaraMatchItem
  → Stage 12 (persistence):
    → yara_matches_in = [YaraMatchCreate(rule_name=..., namespace=..., tags=..., description=...) for each match]
    → SampleRepository.save_full_analysis_transaction(db=db, ..., yara_matches_in=yara_matches_in)
      → Creates YaraMatchModel (rule_version_id NOT set → NULL)
```

### 2.2 Current YARA Analyzer Details

- **Location**: `app/analyzers/yara_analyzer.py`
- **Rule source**: Filesystem (`rules/*.yar`, `rules/*.yara`)
- **Compilation**: `yara.compile(filepaths={stem: path})` at init time
- **Caching**: `_compiled_rules` cached at instance level (singleton)
- **Unavailable YARA**: Returns `YaraScanResult(available=False, status="UNAVAILABLE")`
- **No DB integration**: Does not query `yara_rules` or `yara_rule_versions` tables

### 2.3 Current Match Persistence

- **Schema**: `YaraMatchCreate` has `rule_name`, `namespace`, `tags`, `description` — NO `rule_version_id`
- **Repository**: `YaraMatchModel` created without `rule_version_id` (defaults to NULL)
- **Result**: All new matches have `rule_version_id = NULL`

### 2.4 Model Fields (Verified)

**yara_rules**:
- `id`, `name` (unique), `namespace`, `source`, `compiled` (legacy BLOB), `version` (legacy int), `tags`, `description`, `author`, `is_active`, `created_at`, `updated_at`, `current_version_id` (FK → yara_rule_versions.id, ON DELETE SET NULL)

**yara_rule_versions**:
- `id`, `rule_id` (FK → yara_rules.id, ON DELETE CASCADE), `version`, `source`, `source_hash`, `description`, `author`, `tags`, `severity`, `category`, `published_by` (FK → users.id), `published_at`, `is_published`
- Unique index: `(rule_id, version)`

**yara_matches**:
- `id`, `sample_id` (FK → samples.id, ON DELETE CASCADE), `rule_name`, `namespace`, `tags`, `description`, `created_at`, `rule_version_id` (FK → yara_rule_versions.id, ON DELETE RESTRICT)

## 3. Gap Analysis: Current vs. Required

| Requirement | Current State | Gap |
|-------------|---------------|-----|
| Select active rules with valid current version | No DB rule selection; file-based | Need DB query layer |
| Compile exact version source | File-based compilation | Need DB-driven compilation |
| Match references exact version | `rule_version_id` not set | Need to thread version ID through |
| Inactive rules not scanned | No DB awareness | Need `is_active` filter |
| Rules without current version | N/A (file-based) | Need safe handling |
| Invalid/uncompilable rules | Compile failure → None | Need explicit outcomes |
| Unavailable YARA | Returns UNAVAILABLE | Already handled |
| Concurrency safety | No version locking | Need transaction design |
| Caching | Instance-level `_compiled_rules` | Need version-keyed cache |
| Legacy matches NULL provenance | Already NULL | ✅ Preserved |

## 4. Key Architectural Challenge

The current scanner is **file-based** (reads `.yar` files from disk). The Phase 2 system stores rules in the **database** (`yara_rules` + `yara_rule_versions`). Phase 3 must bridge this gap:

- **Option A**: Replace file-based scanning with DB-driven scanning (query active rules, compile from `current_version.source`)
- **Option B**: Keep file-based scanning for backward compat, add DB versioning as metadata only
- **Recommendation**: Option A — the entire purpose of M02B is to make DB-stored rules authoritative

## 5. Integration Contract

### 5.1 Rule Selection

```python
# Pseudocode for version-aware rule loading
def load_active_rules(db: Session) -> List[Tuple[YaraRuleModel, YaraRuleVersionModel]]:
    rules = db.query(YaraRuleModel).filter(
        YaraRuleModel.is_active == True,
        YaraRuleModel.current_version_id.isnot(None)
    ).all()
    result = []
    for rule in rules:
        version = db.query(YaraRuleVersionModel).filter(
            YaraRuleVersionModel.id == rule.current_version_id,
            YaraRuleVersionModel.rule_id == rule.id,
            YaraRuleVersionModel.is_published == True
        ).first()
        if version:
            result.append((rule, version))
    return result
```

### 5.2 Compilation

- Compile each rule's `version.source` using `yara.compile(source=source)`
- Cache compiled rules keyed by `(rule_id, version_id, source_hash)`
- If compilation fails, log warning and skip that rule (don't crash)
- If YARA unavailable, return UNAVAILABLE status (existing behavior)

### 5.3 Match Provenance

- Each `YaraMatchItem` must carry `rule_version_id`
- `YaraMatchCreate` schema must add `rule_version_id: Optional[int]`
- Repository must set `rule_version_id` on `YaraMatchModel`
- The referenced version must belong to the rule that produced the match

### 5.4 Consistency During Analysis

- Select all active rules with valid versions **once** at scan start
- Hold references to `(rule, version)` pairs throughout the scan
- Concurrent publication creates a new version row but doesn't modify existing ones
- The `current_version_id` pointer on `yara_rules` may change, but the selected version remains valid (FK ON DELETE SET NULL only triggers on version deletion, which is RESTRICTed when referenced by matches)

### 5.5 Transaction Design

- Rule selection happens in a read-only transaction (or no explicit transaction)
- Match persistence happens in `save_full_analysis_transaction` (existing atomic transaction)
- If match persistence fails, the entire analysis transaction rolls back (existing behavior)
- Rule version references are stable (immutable source) — no mid-scan version change

### 5.6 Caching

- Cache key: `(rule_id, version_id, source_hash)` — immutable identity
- Cache scope: instance-level (existing pattern), no cross-worker invalidation needed
- Invalidation: automatic on new version (different version_id → different cache key)
- No manual invalidation required

### 5.7 Error Handling

| Scenario | Behavior |
|----------|----------|
| YARA unavailable | Return UNAVAILABLE status (existing) |
| No active rules with versions | Return SUCCESS with 0 matches |
| Rule compilation fails | Log warning, skip rule, continue scanning |
| Rule source empty/invalid | Skip rule, log warning |
| DB unavailable during rule load | Return UNAVAILABLE or FAILED |
| Match persistence fails | Rollback entire transaction (existing) |
| Version deleted mid-scan | Impossible — RESTRICT prevents deletion of referenced versions |

## 6. Required Schema Changes

**None required.** The schema already supports:
- `yara_matches.rule_version_id` (nullable, FK → yara_rule_versions.id, ON DELETE RESTRICT)
- `yara_rules.current_version_id` (nullable, FK → yara_rule_versions.id, ON DELETE SET NULL)
- `yara_rule_versions` table with immutable source + hash

**Schema change needed in application layer only**:
- `YaraMatchCreate` needs `rule_version_id: Optional[int] = None`
- `YaraMatchRead` inherits it automatically

## 7. Test Matrix

| # | Test | Expected Outcome |
|---|------|-----------------|
| 1 | New match references exact published version | `rule_version_id` = version.id |
| 2 | Publishing new version changes subsequent scans | New analysis uses new version |
| 3 | In-progress analysis uses consistent version | Version selected once at scan start |
| 4 | Inactive rules not scanned | No matches from inactive rules |
| 5 | Rules without current version handled safely | Skipped, no crash |
| 6 | Invalid/uncompilable rules produce explicit outcome | Warning logged, rule skipped |
| 7 | Unavailable YARA preserves behavior | UNAVAILABLE status returned |
| 8 | Multiple matches and duplicates follow constraints | All matches persisted with correct version |
| 9 | Match cannot reference another rule's version | FK constraint enforced |
| 10 | Legacy matches retain NULL provenance | `rule_version_id IS NULL` |
| 11 | DB failure → no partial matches | Transaction rollback |
| 12 | Existing tests remain valid | All pass |

## 8. Ordered Implementation Plan (Phase 3B)

1. **Update `YaraMatchCreate` schema** — add `rule_version_id: Optional[int] = None`
2. **Update `YaraMatchModel` creation in repository** — accept and set `rule_version_id`
3. **Create version-aware scanner function** — query DB for active rules with current versions, compile from version source, cache by `(rule_id, version_id, source_hash)`
4. **Update `YaraScanResult` / `YaraMatchItem`** — add `rule_version_id` field
5. **Update orchestrator** — pass `rule_version_id` through to `YaraMatchCreate`
6. **Update YARA analyzer** — add DB-driven scanning alongside file-based (or replace)
7. **Write tests** — version-aware scanning, provenance, inactive rules, invalid rules, legacy preservation
8. **Run full test suite** — verify no regressions

## 9. Risks and Limitations

- **File-based to DB-based transition**: Existing `.yar` files in `rules/` directory may not have corresponding DB entries. Need migration or dual-mode support.
- **Performance**: Compiling many rules per analysis could be slow. Caching by version identity mitigates this.
- **Concurrency**: SQLite doesn't support `SELECT ... FOR UPDATE`. Version stability relies on immutable version rows (not mutable pointers).
- **YARA availability**: Existing graceful degradation must be preserved.
- **No cross-worker cache**: Each worker compiles independently. Acceptable for current architecture.

## 10. Verified Facts vs. Assumptions

### Verified
- YARA analyzer is file-based (`rules/*.yar`), not DB-driven
- Orchestrator persists matches without `rule_version_id`
- Schema already supports `rule_version_id` on `yara_matches`
- `YaraMatchCreate` lacks `rule_version_id` field
- 37 tests pass after Phase 2 fixes
- Development DB untouched (revision `5655c33dba69`, 127 matches)

### Assumptions (to verify during Phase 3B)
- File-based rules in `rules/` directory should be migrated to DB or kept as fallback
- The orchestrator's `db` session is available for rule loading during scan
- YARA compilation from DB-stored source works identically to file-based compilation