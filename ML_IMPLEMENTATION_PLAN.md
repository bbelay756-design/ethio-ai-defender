# ETHIO-AI DEFENDER: AUDIT-DRIVEN ML IMPLEMENTATION PLAN

**Date:** 2026-10-25  
**Author:** Senior Software Architect & ML Engineering Lead  
**Source:** Milestone 00 Audit Report (verified repository state)  
**Status:** PLAN ONLY — No implementation, data download, or training performed

---

## EXECUTIVE SUMMARY

The Milestone 00 audit confirms:
- **Complete static analysis pipeline** (Modules 01-10, 19) with 10 verified analyzers producing rich PE features
- **Zero ML infrastructure** — no dataset, feature pipeline, training, evaluation, or inference integration
- **Security blockers** (P0 import error, SECRET_KEY default) must be resolved before ML integration
- **Resource constraint:** Local development machine (Windows, Python 3.14, no GPU) → first baseline must be CPU-trainable

**Strategy:** Incremental milestones with verified prerequisites. Each milestone delivers a working, tested component.

---

## SECURITY BLOCKERS (MUST RESOLVE BEFORE ML WORK)

| Blocker | Audit Ref | Impact on ML | Resolution |
|---------|-----------|--------------|------------|
| P0: `get_token_from_header` import error | SEC-01 | Breaks auth-dependent tests; cannot verify ML API endpoints | Fix import in `app/api/auth.py:23` → `get_token_from_header_or_cookie` |
| P1: SECRET_KEY development default | SEC-02 | Production deployment risk; token invalidation on rotation affects ML model serving sessions | Rotate key; document rotation procedure |
| P2: 15-min token expiry | SEC-04 | Long ML training/evaluation sessions may be interrupted | Implement refresh token or extend with sliding window |

**Decision Required:** Human approval to fix P0/P1 before proceeding. These are 5-15 minute changes.

---

## MILESTONE OVERVIEW

| ID | Goal | Prerequisites | Est. Effort |
|----|------|---------------|-------------|
| **ML-00** | Security & Environment Hardening | P0/P1/P2 fixes | 1-2 days |
| **ML-01** | Dataset Selection & Schema Definition | ML-00 complete | 2-3 days |
| **ML-02** | Feature Extraction Pipeline & Serialization | ML-01 complete | 3-5 days |
| **ML-03** | Train/Val/Test Split & Leakage Prevention | ML-02 complete | 2-3 days |
| **ML-04** | Baseline Model Training & Evaluation | ML-03 complete | 5-7 days |
| **ML-05** | Model Serialization & Inference Integration | ML-04 complete | 3-5 days |
| **ML-06** | Integration Tests & Model Versioning | ML-05 complete | 2-3 days |

---

## ML-00: SECURITY & ENVIRONMENT HARDENING

### Verified Prerequisites
- Audit confirms P0 import error blocks all auth-dependent tests (Section 7)
- Audit confirms SECRET_KEY is known default in `.env` (Section 4.2)
- Audit confirms 15-min token expiry may break long sessions (Section 4.3)

### Scope
1. Fix `app/api/auth.py:23` import → `get_token_from_header_or_cookie`
2. Rotate SECRET_KEY in `.env` (generate new 32+ char key)
3. Add token refresh endpoint or extend expiry with sliding window
4. Run full test suite to verify auth works
5. Update `requirements.txt` with missing deps (httpx2, httpcore2, websockets, watchfiles, truststore, opentelemetry-api)

### Affected Files
- `app/api/auth.py` (line 23)
- `.env` (SECRET_KEY)
- `app/auth/dependencies.py` / `app/auth/service.py` (refresh logic)
- `requirements.txt`

### Acceptance Criteria
- [ ] `python -m pytest tests/security/ -v` → 100+ tests pass
- [ ] `python -m pytest tests/ -v --tb=short` → 0 import errors
- [ ] `python verify_module_19.py` → Pass
- [ ] `python audit_security_issues.py` → Executes without import errors
- [ ] New SECRET_KEY ≥32 chars, not in git history
- [ ] Token refresh works for 60+ minute sessions

### Test Commands
```bash
python -m pytest tests/security/ -v
python -m pytest tests/ -v --tb=short 2>&1 | tail -30
python verify_module_19.py
python audit_security_issues.py
```

### Rollback Strategy
```bash
git checkout HEAD -- app/api/auth.py app/auth/dependencies.py app/auth/service.py .env requirements.txt
```

### Security Considerations
- New SECRET_KEY invalidates all existing tokens (token_version mechanism handles this)
- Refresh tokens must be stored hashed, rotate on use
- Document rotation procedure in README

---

## ML-01: DATASET SELECTION & SCHEMA DEFINITION

### Verified Prerequisites (from Audit Section 5)
- **MISSING:** Dataset acquisition & provenance docs
- **MISSING:** Dataset schema & label definitions
- **MISSING:** Data validation & duplicate detection
- **PARTIAL:** PE feature extraction pipeline exists but no unified feature vector

### Dataset Candidate Analysis

| Dataset | Source | Size | Labels | Features | License | Local Feasibility |
|---------|--------|------|--------|----------|---------|-------------------|
| **EMBER 2018** | Endgame | 1.1M samples | benign/malicious (1/0) | 2381 features (histograms, strings, imports, etc.) | BSD-3 | ✅ Pre-extracted features; no raw binaries needed |
| SOREL-20M | Sophos/ReversingLabs | 20M | benign/malicious | Raw PE features | Custom | ❌ Too large for local |
| Private corpus | Internal | Variable | Variable | Variable | Internal | ⚠️ Requires access |

**Decision:** Use **EMBER 2018** as primary dataset. Official release provides pre-extracted feature vectors (JSONL/Parquet) — no raw binary handling, no feature extraction compute required. Compatible with our static analysis philosophy.

### EMBER 2018 Specification (from official documentation)
- **Files:** `ember_dataset_2018_2.tar.bz2` (~4 GB compressed)
- **Format:** JSONL (one sample per line) + Parquet
- **Features:** 2381 dimensions (byte histograms, entropy, strings, imports, exports, header metadata)
- **Labels:** `label` ∈ {0, 1, -1} (benign, malicious, unlabeled)
- **Split:** Provided train/test split (stratified); validation split must be created
- **Hash deduplication:** SHA-256 provided for leakage prevention

### Schema Definition Task
Create `docs/data/DATASET_SCHEMA.md` documenting:
```yaml
dataset:
  name: "EMBER 2018"
  version: "2018.0"
  source: "https://github.com/elastic/ember"
  license: "BSD-3-Clause"
  size:
    total_samples: 1100000
    train: 900000
    test: 200000
  features:
    count: 2381
    types: [histogram, entropy, count, boolean]
    categories: [byte_histogram, byte_entropy_histogram, strings, imports, exports, header, section, general]
  labels:
    benign: 0
    malicious: 1
    unlabeled: -1
  splits:
    train: "provided"
    test: "provided"
    validation: "to_create_from_train_stratified"
  leakage_prevention:
    method: "sha256_deduplication"
    field: "sha256"
```

### Provenance Review
- [ ] Verify SHA-256 of downloaded archive matches official release
- [ ] Confirm no PII or sensitive data in features
- [ ] Document download URL, date, checksum in `docs/data/PROVENANCE.md`

### Acceptance Criteria
- [ ] `docs/data/DATASET_SCHEMA.md` complete and reviewed
- [ ] `docs/data/PROVENANCE.md` with checksums
- [ ] Dataset downloaded, extracted, verified (local storage ~8 GB)
- [ ] Schema validation script `scripts/validate_dataset_schema.py` passes

### Files Expected to Change
- `docs/data/DATASET_SCHEMA.md` (new)
- `docs/data/PROVENANCE.md` (new)
- `scripts/validate_dataset_schema.py` (new)

### Rollback Strategy
```bash
rm -rf docs/data/ scripts/validate_dataset_schema.py
```

---

## ML-02: FEATURE EXTRACTION PIPELINE & SERIALIZATION

### Verified Prerequisites
- Audit confirms 10 analyzers produce rich features (Section 2.4)
- Audit confirms **no unified feature vector, no serialization format** (Section 5)

### Scope
Build `app/ml/features.py` that:
1. **Maps existing analyzers to EMBER-compatible feature vector** (2381 dims)
2. **Handles variable-length outputs** (sections, imports, strings → fixed-size via padding/truncation/pooling)
3. **Serializes to efficient format** (Parquet/NPZ) for training
4. **Provides inverse mapping** for explainability (feature index → analyzer source)

### Analyzer-to-Feature Mapping

| Analyzer | Output | EMBER Feature Group | Mapping Strategy |
|----------|--------|---------------------|------------------|
| `hash_analyzer` | SHA-256, MD5, SHA-1 | — | Identifier only (not model input) |
| `pe_analyzer` | DOS/NT headers, arch, entry, subsystem, timestamp | `header`, `general` | Direct numeric/boolean mapping |
| `section_analyzer` | Sections (name, VA, VS, RS, entropy, perms) | `section` | Fixed max 10 sections; pad/truncate; aggregate stats |
| `entropy_analyzer` | File + per-section entropy | `byte_entropy_histogram`, `section` | Direct mapping |
| `string_analyzer` | URLs, IPs, registry, commands, APIs, etc. | `strings`, `imports` | Count features per category; TF-IDF on printable strings |
| `import_analyzer` | DLLs, APIs, categories, risk | `imports` | Binary presence per known API (170+); DLL count |
| `indicator_engine` | 10 correlation rules | — | Derived features (not raw input) |
| `threat_scoring` | 0-100 score | — | Target/label proxy (not input) |
| `ethiopian_context` | Sector relevance | — | Metadata (not model input) |

### Feature Vector Construction
```python
# app/ml/features.py
class PEFeatureExtractor:
    """
    Transforms Module 01-10 analyzer outputs into fixed-length feature vector.
    Compatible with EMBER 2018 feature space for transfer learning.
    """
    TARGET_DIM = 2381
    MAX_SECTIONS = 10
    MAX_IMPORTS = 200
    MAX_STRINGS = 5000
    
    def extract(self, analyzer_results: Dict) -> np.ndarray:
        # Concatenate all feature groups in deterministic order
        pass
    
    def serialize(self, features: np.ndarray, path: Path) -> None:
        # Save as NPZ (numpy) or Parquet (pandas)
        pass
```

### Serialization Format
- **Training:** Parquet (columnar, efficient for sklearn/LightGBM)
- **Inference:** NPZ (numpy binary, fast load, no pandas dependency)
- **Metadata:** JSON sidecar with feature names, versions, extraction timestamp

### Acceptance Criteria
- [ ] `app/ml/features.py` extracts 2381-dim vector from Unified Analysis Object
- [ ] Feature extraction deterministic (same input → same output)
- [ ] Serialization/deserialization round-trip preserves values (≤1e-10 error)
- [ ] Processing time < 500ms per sample on CPU
- [ ] Unit tests: `tests/ml/test_features.py` covers mapping, padding, serialization

### Files Expected to Change
- `app/ml/__init__.py` (new)
- `app/ml/features.py` (new)
- `app/ml/serialize.py` (new)
- `tests/ml/test_features.py` (new)
- `requirements.txt` (+numpy, pandas, pyarrow)

### Rollback Strategy
```bash
git checkout HEAD -- app/ml/ tests/ml/
```

---

## ML-03: TRAIN/VAL/TEST SPLIT & LEAKAGE PREVENTION

### Verified Prerequisites
- Audit confirms **MISSING:** Train/validation/test separation, leakage prevention (Section 5)

### Scope
1. **Create validation split** from EMBER training data (stratified, 10%)
2. **Implement leakage prevention:**
   - SHA-256 deduplication across all splits
   - Family-based clustering (if family labels available)
   - Temporal splits (if timestamp available)
3. **Persist split indices** for reproducibility
4. **Validate class balance** in each split

### Split Strategy
```python
# scripts/create_splits.py
def create_splits(ember_train_path, output_dir, val_ratio=0.1, seed=42):
    # 1. Load EMBER train (900k samples)
    # 2. Filter labeled samples (label != -1)
    # 3. SHA-256 deduplication within train
    # 4. Stratified split: train (90%) / val (10%)
    # 5. Verify no SHA-256 overlap between train/val/test
    # 6. Save indices as JSONL: {"sha256": "...", "split": "train|val|test"}
```

### Leakage Checks
- [ ] Zero SHA-256 overlap between any two splits
- [ ] Class distribution: benign/malicious ratio within 5% across splits
- [ ] No feature derived from test set used in training (e.g., TF-IDF vocabulary)

### Acceptance Criteria
- [ ] `scripts/create_splits.py` produces `data/splits/train.jsonl`, `val.jsonl`, `test.jsonl`
- [ ] Verification script confirms zero hash overlap
- [ ] Class balance reported and logged
- [ ] Split indices versioned with dataset schema

### Files Expected to Change
- `scripts/create_splits.py` (new)
- `scripts/verify_splits.py` (new)
- `data/splits/` (generated, gitignored)

---

## ML-04: BASELINE MODEL TRAINING & EVALUATION

### Verified Prerequisites
- Audit confirms **MISSING:** Baseline model, training script, evaluation metrics, experiment tracking (Section 5)
- Hardware: CPU-only (Windows, Python 3.14, no GPU) → LightGBM/XGBoost/HistGradientBoosting

### Model Selection Rationale
| Model | Pros | Cons | Decision |
|-------|------|------|----------|
| **LightGBM** | Fast CPU training, handles categorical, built-in CV | Extra dependency | ✅ Primary |
| **HistGradientBoosting** | Native sklearn, no extra deps | Slightly slower | ✅ Fallback |
| **Logistic Regression** | Interpretable, fast | Lower capacity | ✅ Baseline comparison |
| **MLP (sklearn)** | Neural net baseline | Slow, needs tuning | ❌ Not for first baseline |

**Primary:** LightGBM with early stopping, class weighting, calibration.

### Training Pipeline (`app/ml/train.py`)
```python
class MalwareClassifierTrainer:
    def __init__(self, config: TrainConfig):
        self.config = config
        self.model = None
        self.calibrator = None
    
    def train(self, X_train, y_train, X_val, y_val):
        # 1. Class weight computation (balanced)
        # 2. LightGBM with early stopping (val AUC)
        # 3. Calibration (isotonic regression on val)
        # 4. Threshold tuning (target FPR ≤ 1%)
        pass
    
    def evaluate(self, X_test, y_test) -> EvaluationReport:
        # ROC-AUC, PR-AUC, F1@threshold, confusion matrix
        # Per-class metrics, calibration curves
        # False positive analysis (benign samples scored high)
        pass
```

### Evaluation Metrics (Required)
| Metric | Target | Rationale |
|--------|--------|-----------|
| ROC-AUC | ≥ 0.95 | Overall discriminative ability |
| PR-AUC | ≥ 0.90 | Imbalanced class performance |
| F1 @ FPR=1% | ≥ 0.85 | Operational threshold |
| False Positive Rate @ TPR=95% | ≤ 1% | SOC operational requirement |
| Calibration (ECE) | ≤ 0.02 | Reliable probability estimates |

### Experiment Tracking
- Local JSONL run log: `mlruns/{timestamp}_run.jsonl`
- Each entry: hyperparams, metrics, seed, git commit, dataset version
- Artifacts: model file, feature names, calibration curve plots

### Acceptance Criteria
- [ ] `app/ml/train.py` trains LightGBM model on CPU in < 30 min
- [ ] ROC-AUC ≥ 0.95 on held-out test set
- [ ] Calibration ECE ≤ 0.02
- [ ] `app/ml/evaluate.py` produces full report with all required metrics
- [ ] `tests/ml/test_training.py` covers training, evaluation, determinism (fixed seed)

### Files Expected to Change
- `app/ml/train.py` (new)
- `app/ml/evaluate.py` (new)
- `app/ml/calibration.py` (new)
- `app/ml/config.py` (new)
- `tests/ml/test_training.py` (new)
- `tests/ml/test_evaluation.py` (new)
- `requirements.txt` (+lightgbm, scikit-learn, scipy)

### Rollback Strategy
```bash
git checkout HEAD -- app/ml/ tests/ml/
```

---

## ML-05: MODEL SERIALIZATION & INFERENCE INTEGRATION

### Verified Prerequisites
- Audit confirms **MISSING:** Model serialization, versioning, inference integration (Section 5)
- Pipeline orchestrator exists (Module 19) — integration point identified

### Scope
1. **Export model** to ONNX + joblib (dual format)
2. **Build inference service** `app/ml/inference.py`
3. **Integrate into Unified Analysis Object** (Module 19 pipeline)
4. **Version model** with git tag + metadata JSON

### Serialization
```python
# app/ml/serialize.py
def export_model(model, feature_names, output_dir, version):
    # 1. Export to ONNX (onnxmltools or skl2onnx)
    # 2. Export to joblib (sklearn native)
    # 3. Save metadata: version, feature_names, training_date, metrics, git_commit
    # 4. Verify ONNX inference matches Python inference (≤1e-5 diff)
```

### Inference Service
```python
# app/ml/inference.py
class MalwareInferenceService:
    def __init__(self, model_path: Path):
        # Load ONNX model (onnxruntime) or joblib
        # Warm-up inference
    
    def predict(self, features: np.ndarray) -> InferenceResult:
        # Returns: ml_score (0-100), ml_classification (BENIGN/MALICIOUS), 
        #          confidence, inference_ms
```

### Pipeline Integration (Module 19)
```python
# In app/pipeline/orchestrator.py execute_pipeline():
# After Stage 10 (Threat Scoring):
try:
    from app.ml.inference import malware_inference_service
    ml_result = malware_inference_service.predict(feature_vector)
    unified["ml_classification"] = ml_result.to_dict()
except Exception as e:
    logger.warning(f"ML inference failed: {e}")
    unified["ml_classification"] = {"status": "UNAVAILABLE", "error": str(e)}
```

### Model Versioning
```
models/
  v1.0.0/
    model.onnx
    model.joblib
    metadata.json
    feature_names.json
```

### Acceptance Criteria
- [ ] ONNX model loads and runs with onnxruntime (CPU)
- [ ] Inference latency < 50ms per sample (CPU)
- [ ] ML scores integrated into Unified Analysis Object
- [ ] `ml_classification` field present in API responses
- [ ] Model version tracked in `ml_classification.model_version`
- [ ] `tests/ml/test_inference.py` covers loading, prediction, API integration

### Files Expected to Change
- `app/ml/serialize.py` (new)
- `app/ml/inference.py` (new)
- `app/pipeline/orchestrator.py` (modify: add ML stage)
- `app/pipeline/models.py` (modify: add MLClassification to Unified Analysis Object)
- `tests/ml/test_inference.py` (new)
- `requirements.txt` (+onnxruntime, onnxmltools)

### Rollback Strategy
```bash
git checkout HEAD -- app/ml/ app/pipeline/ tests/ml/
```

---

## ML-06: INTEGRATION TESTS & MODEL VERSIONING

### Verified Prerequisites
- Audit confirms test infrastructure exists (pytest, 134+ passing tests)
- Audit confirms **MISSING:** ML tests, model versioning, CI/CD (Section 5, 6)

### Scope
1. **Integration tests** for full ML pipeline
2. **Model registry** (local filesystem + metadata)
3. **Regression test** for model upgrades
4. **Documentation** (model card, API changes)

### Integration Tests
```python
# tests/ml/test_integration.py
def test_full_ml_pipeline(sample_pe_bytes):
    # 1. Run full pipeline via UnifiedPipelineOrchestrator
    # 2. Verify ml_classification present in output
    # 3. Verify score in [0, 100], classification in {BENIGN, MALICIOUS}
    # 4. Verify inference_ms < 100

def test_model_version_tracking():
    # Verify model_version in output matches deployed model

def test_inference_fallback():
    # When model file missing → graceful degradation (UNAVAILABLE)
```

### Model Registry
```
models/
  registry.json          # Index: version → metadata
  v1.0.0/
    model.onnx
    model.joblib
    metadata.json
    feature_names.json
  v1.1.0/
    ...
```

`registry.json`:
```json
{
  "current": "v1.0.0",
  "models": {
    "v1.0.0": {"date": "2026-10-25", "roc_auc": 0.962, "git_commit": "abc123"}
  }
}
```

### Acceptance Criteria
- [ ] Integration tests pass in full test suite
- [ ] Model registry tracks versions, metrics, git commits
- [ ] API returns `ml_classification.model_version`
- [ ] Graceful degradation when model unavailable
- [ ] `docs/ml/MILESTONE_01_MODEL_CARD.md` complete (Google Model Card format)

### Files Expected to Change
- `tests/ml/test_integration.py` (new)
- `app/ml/registry.py` (new)
- `docs/ml/MILESTONE_01_MODEL_CARD.md` (new)
- `app/api/analyses.py` (verify ML field in response)

---

## DECISIONS REQUIRING HUMAN APPROVAL

| Decision | Options | Recommendation | Impact |
|----------|---------|----------------|--------|
| **Dataset:** EMBER 2018 vs. private corpus | EMBER 2018 (public, pre-extracted) / Private | EMBER 2018 — reproducible, no raw binary handling | Determines feature space, licensing |
| **Model format:** ONNX vs. joblib vs. both | ONNX + joblib / joblib only / ONNX only | Both — ONNX for production, joblib for debugging | Affects inference deps (onnxruntime) |
| **Calibration method:** Isotonic vs. Platt | Isotonic (more flexible) / Platt (fewer params) | Isotonic — better for tree ensembles | Affects probability reliability |
| **Operating threshold:** FPR=1% vs. F1-optimal | Fixed FPR / Max F1 / Cost-sensitive | FPR=1% — SOC operational requirement | Affects alert volume, analyst workload |
| **Model versioning:** Git tags vs. MLflow vs. custom registry | Git tags + JSON / MLflow / DVC | Git tags + JSON — minimal deps, auditable | Affects rollback, auditability |
| **CI/CD for ML:** GitHub Actions vs. local only | Full CI/CD / Local only for now | Local only for Milestone 1; CI/CD in ML-07 | Affects reproducibility enforcement |

---

## OUT OF SCOPE FOR MILESTONES 00-06

| Item | Deferred To | Reason |
|------|-------------|--------|
| Raw binary feature extraction (replacing EMBER features) | ML-10 | Requires large compute; current analyzers sufficient |
| Deep learning models (CNN, Transformer) | ML-15 | No GPU; diminishing returns on tabular PE features |
| Active learning / human-in-the-loop | ML-20 | Requires analyst workflow integration |
| Adversarial robustness testing | ML-25 | Research-grade; not production baseline |
| Multi-label family classification | ML-12 | Requires family-labeled dataset |
| Real-time streaming inference | Ops-05 | Requires model server (Triton/TorchServe) |
| Automated retraining pipeline | ML-30 | Requires CI/CD, data pipeline, monitoring |

---

## SUMMARY: FIRST MILESTONE (ML-00) APPROVAL REQUEST

**Request:** Approve ML-00 (Security & Environment Hardening) to unblock all downstream ML work.

**Changes:**
1. Fix `app/api/auth.py:23` import (5 min)
2. Rotate SECRET_KEY in `.env` (5 min)
3. Add token refresh endpoint (30 min)
4. Update `requirements.txt` with missing deps (5 min)

**Verification:** Full test suite passes, audit tool runs, no import errors.

**Risk:** LOW — all changes are authentication/config only; no ML code touched.

**Rollback:** Single `git checkout HEAD` command for 4 files.

**Please approve ML-00 to proceed.**

---

*End of Plan — Awaiting explicit approval for ML-00 before implementation.*