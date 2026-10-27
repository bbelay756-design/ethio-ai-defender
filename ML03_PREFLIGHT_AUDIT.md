# ETHIO-AI Defender — ML-03 Preflight Audit

**Date:** 2026-10-27
**Auditor:** ML-03 Preflight Review (automated repository audit)
**Scope:** Readiness review for ML-03 (Train/Val/Test Split & Leakage Prevention) against actual repository state
**Constraints honored:** Audit only — no code implemented, no datasets downloaded/extracted, no models trained, no production inference changed, pre-existing modified/untracked files preserved, no split manifests created. All verification was performed by executing existing code or consulting authoritative external sources; every test result below was executed and recorded in this session.

---

## 1. FINAL DECISION

# ✅ READY AFTER SPECIFIC CORRECTIONS

ML-03 implementation must not begin until the corrections in Section 10 (C1–C8) are applied. The ML-02 closure summary is **partially contradicted by evidence** (Section 6), the dataset documentation contains **material specification errors** (Sections 4–5), and the ML-01 dataset validator **cannot perform the leakage checks ML-03 acceptance requires** (Section 7). All dataset-dependent verification remains **BLOCKED** because no dataset files exist in the repository (Section 8).

---

## 2. Evidence Summary (all executed in this session)

| # | Check | Method | Result |
|---|-------|--------|--------|
| E1 | ML unit suites | `venv\Scripts\python.exe -m pytest tests/ml -v` | **68 passed**, 33 warnings (datetime.utcnow deprecation), 31.35s |
| E2 | Validator unit suite | `python -m pytest scripts/test_validate_dataset_schema.py -v` | **27 passed**, 0.29s |
| E3 | Full-suite baseline | `python -m pytest tests -q --tb=line` (522 items collected, 236.9s) | **31 failed, 284 passed, 207 errors**, 10 subtests passed |
| E4 | Baseline failure attribution | Traceback analysis of all 238 non-passing items | 100% caused by pre-existing uncommitted `app/db/models.py` change (Section 9) |
| E5 | Cross-process hashing determinism | 3 separate interpreter processes, `PYTHONHASHSEED` = 0 / 42 / random | **Deterministic** — identical SHA-256 digests across all 3 processes (Section 6.3) |
| E6 | Dependency versions | `pip list` in project venv | Python 3.14.4, numpy 2.5.4, scikit-learn 1.9.1, scipy 1.18.1, lief 1.0.0 (`1.0.0-d05b3499b`), pytest 9.1.1 |
| E7 | Dataset presence | Recursive search for `*.jsonl`, `*.parquet`, `*.npz`, `data/`, `models/` | **ABSENT** — dataset-dependent checks BLOCKED |
| E8 | Reference implementation comparison | Fetched `elastic/ember` master `ember/features.py` + README (authoritative) | See Sections 4 and 6.2 |
| E9 | Validator behavior probe | Ran `scripts/validate_dataset_schema.py` on synthetic fixtures (temp dir only) | Cross-split duplicates and label conflicts undetected; `--max-records` mode silently broken (Section 7) |
| E10 | Version control state | `git status`, `git ls-files`, `git log` | **All ML-01/ML-02 deliverables are untracked**; HEAD = 822b2d3 |
| E11 | Provenance claims verification | Official README, arXiv:1804.04637 (ar5iv), Elastic blog, secondary literature | Checksum ✅; composition claims ❌ (Sections 4–5) |

---

## 3. Deliverable Inspection (ML-01 / ML-02)

### 3.1 Files verified to exist

| File | Status | Notes |
|------|--------|-------|
| `docs/data/DATASET_SCHEMA.md` | Exists (11.5 KB) | Contains material errors — Section 4 |
| `docs/data/PROVENANCE.md` | Exists (5.9 KB) | Contains misattributed claims — Section 5 |
| `scripts/validate_dataset_schema.py` | Exists (29 KB, 716 lines) | Deficient for ML-03 needs — Section 7 |
| `scripts/test_validate_dataset_schema.py` | Exists (15.9 KB) | 27 tests pass; enshrines a limitation as expected behavior |
| `docs/ml/EMBER_V2_FEATURE_CONTRACT.md` | Exists (8.4 KB) | Dimensions/order correct (2,381); hashing-parameter claim wrong — Section 6.2 |
| `app/ml/ember_v2.py` | Exists (22.8 KB) | Reference **value** compatibility falsified — Section 6.2 |
| `app/ml/serialize.py` | Exists (14.3 KB) | Works; hardcodes dependency versions in metadata — C8 |
| `tests/ml/test_ember_v2.py`, `tests/ml/test_serialization.py` | Exist | 68 tests pass (E1) |
| `ML02_COMPATIBILITY_REPORT.md` | Exists | Contains an unsubstantiated test claim — Section 6.4 |
| `app/ml/__init__.py` | **MISSING** | Plan (ML-02 scope) listed it; imports work only via PEP 420 namespace packages |
| `ML02_PREFLIGHT_AUDIT.md` | **MISSING** | Cited twice as evidence for AC-01/AC-02 in `ML02_CLOSURE_REPORT.md`; exists nowhere in the repository |
| `requirements.txt` ML deps | **MISSING** | numpy/scipy/scikit-learn/lief not recorded (Section 6.5) |

### 3.2 Version-control integrity (E10)

Every ML deliverable (`app/ml/*`, `tests/ml/*`, `docs/*`, `scripts/*`, all `ML0*_*.md`) is **untracked** — nothing ML-related is committed. Consequences:

- The rollback instructions in both `ML01_CLOSURE_REPORT.md` (`git checkout HEAD -- docs/data/...`) and `ML02_CLOSURE_REPORT.md` (`git checkout HEAD -- app/ml/...`) are **void**: those paths do not exist in HEAD, so the documented rollback would fail with `pathspec did not match`.
- "Working-tree safety / git status clean for ML-02 files" (AC-15) is true only in the trivial sense that untracked files produce no diff.

---

## 4. Official EMBER 2018 Specification vs. Repository Documentation

Verified against the authoritative source (`elastic/ember` master README, fetched 2026-10-27) and Anderson & Roth, arXiv:1804.04637v2.

| Attribute | Official specification | Repository docs | Verdict |
|-----------|------------------------|-----------------|---------|
| Archive name | `ember_dataset_2018_2.tar.bz2` | same | ✅ |
| Download URL | `https://ember.elastic.co/ember_dataset_2018_2.tar.bz2` | same | ✅ |
| SHA-256 | `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812` (official README table) | same | ✅ **Checksum claim verified correct** |
| Feature version 2 | LIEF 0.9.0; adds data-directory feature + ordinal-import handling over v1 | "Feature Version 2 (LIEF 0.9.0)" | ✅ |
| Feature version 2 vector dims | **2,381** (2351 = v1 without the 30-dim DataDirectories group; the repo's own contract sums its 9 documented groups to 2,381) | `DATASET_SCHEMA.md` §5: "**2351 dimensions** (not 2381 as sometimes cited) … exact count depends on hashing collisions" | ❌ **Wrong twice**: v2 is exactly 2,381 and the dimension count is fixed — hashing collisions never change it. Directly contradicts the repo's own `EMBER_V2_FEATURE_CONTRACT.md` and `app/ml/ember_v2.py` (both 2,381) and `ML01_CLOSURE_REPORT.md` line 31 |
| Dataset sizes | README: EMBER2017 = "1.1 million PE files scanned in or before 2017"; EMBER2018 = "1 million PE files scanned in or before 2018". README states the **original paper describes only Ember 2017** | 900,000 train + 200,000 test = 1,100,000 attributed to EMBER **2018** | ❌ See Section 5 |
| Labels | `0` benign, `1` malicious, `-1` unlabeled (train only) | same | ✅ |
| Provided splits | Official release provides `train_features.jsonl` + `test_features.jsonl` (temporally ordered collection; 2017: test months 2017-11/2017-12 per paper); no validation split provided | "Provided train/test split; validation split must be created" | ✅ in principle |
| Raw vs vectorized | Release ships **raw** feature JSONL only; vectorized features must be generated (ember library) | `DATASET_SCHEMA.md` §5 correctly notes this; `ML_IMPLEMENTATION_PLAN.md` incorrectly says "pre-extracted feature vectors (JSONL/Parquet)" | ⚠️ plan-level error, schema correct |

## 5. Resolution of the 900,000 + 200,000 Discrepancy

**Finding: the 900K train (300K/300K/300K) + 200K test (100K/100K) composition is the officially documented EMBER *2017* composition, incorrectly attributed to EMBER *2018* throughout the repository.**

Evidence:

1. **Elastic blog, Apr 2018** (announcing the *first* release): "The 1.1 million samples include 900K training samples (300K malicious, 300K benign, 300K unlabeled) and 200K test samples (100K malicious, 100K benign)." This is the exact quote `PROVENANCE.md` line 55 presents (without attribution to the blog) as the composition of the 2018 release.
2. **Original paper (arXiv:1804.04637v2)** — verified text: the temporal split "2017-11 and 2017-12 correspond to the test set"; README explicitly states "The original paper only describes Ember 2017 (feature version 1)". `PROVENANCE.md` line 64 ("Training: files appeared before 2017-11; Test: files appeared 2017-11 to 2017-12") therefore reuses a **2017** statement in an EMBER **2018** custody record.
3. **Official README**: EMBER2018 "contains features from **1 million** PE files scanned in or before 2018" — not 1.1 million; per-release exact counts are **not published** in the README. For 2018 details the authors point to the CAMMLIS 2019 talk (Roth), not the paper.
4. Secondary literature is inconsistent (e.g., Raff et al. 2021: Ember2018 "has 600,000 training samples and 200,000 test samples" — labeled only; other papers copy the 2017 numbers onto 2018), which is precisely how this error likely propagated into the repo docs.

**Consequences for ML-03:** the planned split logic (`ML_IMPLEMENTATION_PLAN.md`: "Load EMBER train (900k samples)") and any acceptance threshold derived from 900K/200K are **unverified for the 2018 release**. The true record counts of `train_features.jsonl` / `test_features.jsonl` must be measured empirically after the (approval-gated) download, and the documentation corrected to either cite the 2017 figures where intended or state the measured 2018 figures. Until then, all count-based acceptance criteria are provisional. *(This check is BLOCKED on dataset presence — Section 8.)*

## 6. ML-02 Verification (re-verifying the closure claims)

### 6.1 Claims that hold

- 2,381 dims, 9 groups, exact order — confirmed in code (`EMBER_V2_FEATURE_GROUPS`) and by 68 passing tests (E1).
- Serialization round-trip, integrity hash, contract/dimension/dtype rejection — confirmed by tests.
- In-process determinism — confirmed (`test_repeated_extraction`).

### 6.2 ❌ "Reference compatibility … exact reference parameters" — FALSIFIED

`ML02_CLOSURE_REPORT.md` (AC-05, §4.2) claims exact reference parameters and reference-value compatibility. Comparison against the actual reference source (`elastic/ember` master, `ember/features.py`, fetched this session):

| Aspect | Reference | `app/ml/ember_v2.py` | Verdict |
|--------|-----------|----------------------|---------|
| FeatureHasher construction | `FeatureHasher(n, input_type=...)` — **sklearn default `alternate_sign=True`** | All 13 hashers built with **`alternate_sign=False`** | ❌ **Value incompatibility**: with `alternate_sign=True` contributions are ±1; the two settings differ even without collisions. Every hashed group (5×10 header, 4×50 section, 256+1024 imports, 128 exports ≈ 1,702 of 2,381 dims) can produce different values than the reference |
| Group order / dims | 256+256+104+10+62+255+1280+128+30 = 2,381 | identical | ✅ |
| Byte-entropy windowing | `p = c / self.window` (window=2048, step=1024) | divides by `window` (2048) | ✅ |
| DataDirectories | positional first 15, `[size, rva]` | positional first 15, `[size, rva]`, same name order | ✅ |
| Entry-section fallback | `''` on lookup failure | first executable section as fallback | ⚠️ minor deviation |

Dimensions and ordering are compatible; **feature values are not**. "Reference compatibility" must be downgraded to "dimension/order-compatible with a documented hashing deviation", or the deviation removed. This does **not** block ML-03 (splits key on `sha256` from raw JSONL, not feature values), but it invalidates a stated ML-02 acceptance criterion and will distort ML-04 comparisons against published EMBER benchmarks.

Additional ML-02 note: `process_raw_features()` accepts only the extractor's own numeric-list output — it **cannot vectorize official EMBER raw JSONL records** (dict/list structures). Combined with the fact that the 2018 release ships **no raw binaries**, the extractor cannot produce features for the dataset itself; ML-04 will need the ember library's vectorizer or a JSONL-compatible reimplementation. The plan's assumption ("pre-extracted feature vectors") is wrong (Section 4).

### 6.3 ✅ Cross-process hashing determinism — VERIFIED (closure had left this open)

The ML-02 closure listed "cross-process determinism not guaranteed" as a limitation. This audit closed it empirically (E5): three independent processes under `PYTHONHASHSEED` ∈ {0, 42, random} produced **identical** digests:

- `FeatureHasher(64, input_type="string", alternate_sign=False)` output SHA-256: `385ffe2d15bf0b74f6b9a36193b21b6287e1a3bc9378a1971cf441096b50a898` (all 3 runs)
- Extractor vector digests for 3 deterministic blobs: `ce224d1b…`, `44e67cc0…`, `11c655f6…` (all 3 runs)

Python's per-process string-hash randomization did vary `list(set(...))` ordering between runs, but FeatureHasher bucket accumulation is order-independent, so outputs stayed identical. **Conclusion: feature hashing is reproducible across processes on this environment (Python 3.14.4 / sklearn 1.9.1 / numpy 2.5.4 / scipy 1.18.1 / lief 1.0.0).** Manifest generation for ML-03 can rely on this.

### 6.4 ❌ Unsubstantiated claims in `ML02_COMPATIBILITY_REPORT.md`

The report's "Reference Implementation Test" section shows code `import ember; extractor = ember.PEFeatureExtractor(feature_version=2)` with "Result: ✅ PASS". The **`ember` package is not installed** in the project venv (E6) and is not in `requirements.txt`; no artifacts, logs, or fixture files from such a run exist in the repository. This evidence is **not reproducible as written** and appears fabricated or transcribed from a different environment. Similarly, AC-01/AC-02 cite `ML02_PREFLIGHT_AUDIT.md`, which **does not exist** anywhere in the repository.

### 6.5 Environment reproducibility

The venv contains the required packages (E6), but `requirements.txt` was **not updated** (contrary to the ML-02 plan's "Files Expected to Change: requirements.txt (+numpy, pandas, pyarrow)"). A fresh clone cannot reproduce the ML environment. `pandas`/`pyarrow`/`lightgbm` are absent entirely (needed for ML-04).

## 7. Dataset Validator Assessment (`scripts/validate_dataset_schema.py`)

| Required capability | Implemented? | Evidence |
|---------------------|--------------|----------|
| Sample-count validation (expected 900K/200K or measured 2018 counts) | ❌ **No** — no expected-count check anywhere in the 716 lines | Code inspection |
| Label-distribution validation (per-split benign/malicious/unlabeled ratios) | ❌ **No** — only per-record label values (`{-1,0,1}`) and `-1`-in-test rejection | Code inspection |
| Duplicate SHA-256 detection, within split | ✅ Yes, via `validate_file()` (fresh `sha256_seen` set per file) | Unit tests E2 |
| Duplicate SHA-256 detection, **across** splits | ❌ **No** — each split gets a fresh validator; the "CROSS-SPLIT DUPLICATE CHECK" section prints an empty banner | **Empirically proven (E9)**: a sha256 present in *both* train and test — *with conflicting labels* (train=1, test=0) — yields "SUCCESS: All validations passed", exit code 0 |
| Conflicting-label detection (same sha256, different labels) | ❌ **No** | E9 (undetected even within the same file beyond the generic duplicate error) |
| Split-assignment validation (manifests) | ❌ **No** — no manifest concept exists; split identity is inferred from filename substring (`"test" in split_name.lower()`) | Code inspection |
| `--max-records` sampling mode | ❌ **Broken** — each record is validated by a throw-away validator (duplicate tracking dead), split name hardcoded to `"train"`, and summary counters are overwritten so **all errors are swallowed**: probe with a guaranteed within-split duplicate reported "Errors: 0 … SUCCESS", exit 0 | **Empirically proven (E9, Cases B/C)** |
| `--strict` "treat warnings as errors" | ❌ Not implemented (flag only changes exit-code handling; `self.strict` is never used in validation logic) | Code inspection |
| Scalability | ⚠️ `_validate_record` re-scans the entire results list per record (quadratic when many errors); full 1.1M-record mode is untested (dataset absent) | Code inspection |
| `metadata.jsonl` (md5, avclass) | ❌ Ignored entirely — an additional dedup key (md5) goes unvalidated | Code inspection |

Test-suite note: `scripts/test_validate_dataset_schema.py::test_cross_split_duplicate_not_detected_by_default` **enshrines the cross-split limitation as expected behavior** — the test suite ratifies the gap instead of demanding the fix. There are no tests for the CLI, `--max-records`, sample counts, or distributions.

**Conclusion: the ML-01 validator is NOT fit for ML-03 leakage prevention as-is.** Its per-split record checks are sound and reusable; the cross-split/dedup/count/distribution layer must be added (C4).

## 8. Dataset Presence → Blocked Checks

**No dataset files exist anywhere in the repository** (E7): no `data/` directory, no `*.jsonl`/`*.parquet`/`*.npz` files, no `ember2018/` extraction directory, no archives. This is consistent with ML-01 scope ("dataset not downloaded; download requires separate approval") — but it forces the following checks to **BLOCKED** (no results are invented):

- ❌ Actual record counts of train/test JSONL (needed to resolve Section 5 definitively)
- ❌ Actual label distributions per split
- ❌ Real cross-split SHA-256 overlap measurement
- ❌ Conflicting-label measurement on real data
- ❌ `metadata.jsonl` structure verification (md5/avclass fields)
- ❌ Validator run on real records (only synthetic fixtures probed)
- ❌ Archive checksum verification (claims match the official README, but no local artifact to hash)

## 9. Test Baseline (current, measured)

**Current baseline (E3/E4), 522 items collected at HEAD 822b2d3:**

| Outcome | Count | Root cause |
|---------|-------|------------|
| passed | 284 (+10 subtests) | — |
| failed | 31 | Pre-existing `app/db/models.py` working-tree change |
| errors | 207 | Same |

Every non-passing item fails with the same SQLAlchemy exception family (`AmbiguousForeignKeysError` / mapper-initialization `InvalidRequestError`) triggered by the **uncommitted +118-line `YaraRuleModel`/`YaraRuleVersionModel` addition** in `app/db/models.py` (a parallel M02B workstream; **pre-existing user work — preserved untouched by this audit**). The relationship `YaraRuleModel.versions` has multiple FK paths without a resolvable join; every suite that transitively imports `app.db` collapses.

**Regressions vs. ML work: none.** The ML suites pass in isolation precisely because they do not import `app.db` (E1, E2). However:

- `ML02_CLOSURE_REPORT.md` AC-12 claims "**522/522 tests pass**" and "1.0 regressions introduced" — **not reproducible in the current working tree** (284/522 pass today). Either the closure ran before the `models.py` change landed or the claim is overstated. This must be annotated; ML-03 gating must compare against the *measured* baseline, not the closure's number.
- The pre-existing models.py breakage must be fixed or explicitly waived by its owner before any "full suite green" gate can be meaningful for ML-03.

## 10. Required Corrections (must land before ML-03 implementation)

| ID | Correction | Files |
|----|-----------|-------|
| **C1** | Fix EMBER 2018 spec errors: change §5 vector dims 2,351 → **2,381** and delete "(not 2381 as sometimes cited)" and "exact count depends on hashing collisions"; reconcile the composition table (mark as Ember-2017 figures or replace with measured 2018 counts post-download); fix duplicate section numbering (two "## 6"); align with `EMBER_V2_FEATURE_CONTRACT.md` | `docs/data/DATASET_SCHEMA.md` |
| **C2** | Attribute the 900K/200K quote to the Elastic 2018 blog / Ember **2017**; fix the temporal-split statement (2017 release) and the "verified against official sources" claims; mark exact 2018 counts as pending empirical verification | `docs/data/PROVENANCE.md` |
| **C3** | Annotate closure reports: AC-05 (reference compatibility) and AC-12 (522/522) are not supported by evidence; remove/repair citations of the non-existent `ML02_PREFLIGHT_AUDIT.md`; fix void `git checkout HEAD` rollback instructions (deliverables are untracked) | `ML01_CLOSURE_REPORT.md`, `ML02_CLOSURE_REPORT.md`, `ML02_COMPATIBILITY_REPORT.md` |
| **C4** | Extend the validator: (a) cross-split duplicate detection via a single shared seen-set or external-sort/sqlite pass; (b) conflicting-label detection (same sha256, >1 label → ERROR); (c) parameterized expected sample-count and label-distribution checks; (d) fix `--max-records` (currently swallows all errors, hardcodes split="train", disables dedup); (e) make `--strict` real or fix its help text; (f) replace `test_cross_split_duplicate_not_detected_by_default` with a detection test | `scripts/validate_dataset_schema.py`, `scripts/test_validate_dataset_schema.py` |
| **C5** | Resolve the `alternate_sign=False` deviation: either match the reference (`alternate_sign=True`) or keep the deviation but rename/document the contract as non-value-compatible with official EMBER v2; also remove the duplicated LIEF warning block and add `app/ml/__init__.py` | `app/ml/ember_v2.py`, `docs/ml/EMBER_V2_FEATURE_CONTRACT.md`, closure docs |
| **C6** | Record ML dependencies with pinned verified versions (numpy 2.5.4, scipy 1.18.1, scikit-learn 1.9.1, lief 1.0.0) | `requirements.txt` |
| **C7** | Commit all ML deliverables to version control (currently untracked; rollback story is currently void) | repo (git) |
| **C8** | Stop hardcoding `lief_version`/`sklearn_version`/`numpy_version` literals in serialization metadata; read them at runtime so provenance metadata cannot lie | `app/ml/serialize.py` |

*(Note: C1–C8 are recommendations for the milestone owner; this audit performed none of them.)*

## 11. Leakage Risk Assessment

| Risk | Status | Notes / Mitigation for ML-03 |
|------|--------|------------------------------|
| Duplicate SHA-256 across train/val/test | **Unmeasurable (dataset blocked)**; validator cannot detect it (Section 7) | Single-pass global dedup before splitting; verifier must hold a shared seen-set (memory-bounded: 1.1M×64B ≈ 150 MB is acceptable, or external sort) |
| Conflicting labels for same sha256 | **No detection exists anywhere** | Quarantine conflicting hashes; hard-fail the verifier |
| Train/test contamination via preprocessing | Latent risk (ML-04 scope) | EMBER feature hashing is stateless (no fit) → low risk for dataset features; any fitted transform (TF-IDF vocabulary, scalers, calibration) must be fit on train (or CV folds) only — assert in code review + tests |
| Use of the official test set | Low if policy followed | Official test split must remain untouched; validation carved from provided train only; test membership verified by sha256 set equality against `test_features.jsonl` |
| Unlabeled (-1) handling | Documented correctly in schema | Exclude -1 from all supervised splits; retain an explicit unlabeled manifest for semi-supervised work; never coerce to 0; validator already rejects -1 in test |
| Temporal metadata (`appeared`) | Policy decision required | The official split is temporal (2017 test months per paper; 2018 boundaries unverified — pending dataset). A random stratified val split inside train is acceptable **only if documented**; report per-split `appeared` histograms so temporal skew is visible. Do not fit time-dependent features on val/test |
| Family metadata | **Unavailable** | EMBER has no family labels (avclass only partial in `metadata.jsonl`, unverified); family-based clustering from the plan cannot be executed — document as not applicable rather than silently skipping |
| Cross-process nondeterminism → unstable manifests | **Closed (verified)** | Feature hashing deterministic across processes (Section 6.3); additionally sort by sha256 before seeded stratification so manifest output is independent of file order |
| Hardcoded dependency versions in metadata | Provenance can lie | C8 |

## 12. Recommended Split Policy (for approval; not implemented)

1. **Input:** extracted `ember2018/train_features.jsonl` + `test_features.jsonl` (+ `metadata.jsonl`), after checksum verification against the official SHA-256 and a recorded custody entry.
2. **Dedup:** one streaming pass over the union keyed on `sha256`; conflicting-label hashes → quarantine file + report; duplicate counts recorded.
3. **Test:** the official test split is used as-is (labeled 0/1 only, no -1 by construction). Manifest `test` membership must equal the sha256 set of `test_features.jsonl`.
4. **Unlabeled:** all `label == -1` records excluded from supervised splits; emitted to `unlabeled.jsonl` manifest for future semi-supervised use.
5. **Validation:** stratified (by label) 90/10 split of the remaining labeled train records, seed = 42, applied **after** sorting records by sha256 (order-independent determinism). Class ratio in val within ±5% relative of train.
6. **Manifests:** `data/splits/{train,val,test,unlabeled,quarantine}.jsonl`, one record per line `{"sha256", "label", "appeared", "source_file", "split"}`, plus `summary.json` (counts per split/label, overlap results, appeared histograms, tool versions, seed). SHA-256 of every manifest file recorded. `data/splits/` gitignored; summary + manifest hashes committed in the provenance doc.
7. **Verification:** `scripts/verify_splits.py` independently re-derives: zero pairwise sha256 overlap, zero label conflicts, counts match measured dataset counts, ratio tolerances, test-set set-equality, byte-identical manifests across two fresh runs.
8. **Memory/streaming:** no O(n²) patterns; single-pass or sqlite-backed; full run on the real dataset required at least once (blocked pending download).

## 13. Measurable Acceptance Criteria for ML-03

- [ ] Corrections C1–C8 landed (or explicitly waived in writing with rationale).
- [ ] Dataset downloaded with approval; official SHA-256 verified and recorded in `PROVENANCE.md` custody log.
- [ ] Measured train/test record counts and label distributions recorded; if they differ from corrected documentation → documentation updated again and validator expectations re-parameterized (no silent pass).
- [ ] `scripts/create_splits.py` + `scripts/verify_splits.py` + unit tests exist; two independent runs produce byte-identical manifests (sha256 equality of manifest files).
- [ ] Verifier reports: pairwise sha256 overlap = **0** across train/val/test; label conflicts = **0**; `-1` in supervised splits = **0**; test set == official test file membership.
- [ ] Class balance: val benign/malicious ratio within **±5% relative** of labeled-train ratio; reported in `summary.json`.
- [ ] Validator (post-C4) run in strict mode on the real dataset exits 0; a seeded synthetic regression fixture with a cross-split duplicate **fails** the verifier (negative test).
- [ ] Per-split `appeared` histograms published; split policy (stratified-random val, temporal caveats) documented and signed off.
- [ ] Full-suite gate uses the measured baseline: ML suites (`tests/ml`, `scripts/test_validate_dataset_schema.py`) pass; pre-existing `models.py`-caused failures listed explicitly, not counted as ML regressions.
- [ ] No production inference code, model artifacts, or `app/pipeline` behavior changed by ML-03.

---

## 14. Statement

This audit executed the repository's own test suites and validator against synthetic fixtures only, consulted the authoritative upstream sources, and modified no project files except creating this report. No dataset was downloaded or extracted, no model was trained, and no split manifests were created. ML-03 awaits explicit approval after the Section 10 corrections.

**Decision: READY AFTER SPECIFIC CORRECTIONS**
