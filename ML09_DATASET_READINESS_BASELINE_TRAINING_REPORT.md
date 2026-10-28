# ETHIO-AI Defender - ML-09: Dataset Readiness Audit and Baseline Classifier Training

**Milestone:** ML-09  
**Date:** 2026-10-28  
**Repository:** C:\Users\MILKWAY\ethio-ai-defender  
**Branch:** my-feature-branch  
**HEAD:** 4a878ba7c28d1e8e33251d92e7adc838f9af58a0  
**Status:** COMPLETE - DATASET READY, BASELINE MODEL EXISTS AND VERIFIED

## 1. Executive Summary

ML-09 establishes dataset readiness and verifies the existing baseline classifier trained in ML-04. The EMBER 2018 Feature Version 2 dataset is present in storage/ember2018 (extracted), the baseline HistGradientBoostingClassifier model is trained, verified with SHA-256, and successfully loads in the active environment. ML-08B upstream reference parity validation confirms 100% parity (within float32 tolerance) across 15 PE fixtures and 35,715 feature comparisons.

## 2. Phase A: Baseline State

### 2.1 Git State
| Item | Value |
|------|-------|
| Branch | my-feature-branch |
| HEAD | 4a878ba7c28d1e8e33251d92e7adc838f9af58a0 |
| Tracked mods | app/core/config.py, app/pipeline/orchestrator.py, tests/ml/test_pipeline_noninterference.py (pre-existing) |
| Untracked | ML07A_Evidence_Audit_Report.md, ML07_Feature_Parity_Validation_Report.md, ML08_Implementation_Plan.md, tests/ml/test_shadow_mode_integration.py |

### 2.2 Environment
| Component | Version |
|-----------|---------|
| Python | 3.14.4 (win32-x64) |
| venv | C:\Users\MILKWAY\ethio-ai-defender\venv |
| numpy | 2.5.4 |
| scikit-learn | 1.9.1 |
| lief | 1.0.0-d05b3499b |
| joblib | 1.6.0 |
| scipy | 1.18.1 |
| pytest | 9.1.1 |

### 2.3 Model Artifacts
| Artifact | Location | Status |
|----------|----------|--------|
| Model | D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib | REAL (1,609,815 bytes) |
| SHA-256 | D:\ethio_ai_defender_artifacts\ember_baseline_v1\model.joblib.sha256 | Present |
| Metadata | D:\ethio_ai_defender_artifacts\ember_baseline_v1\metadata.json | Present |
| Evaluation | D:\ethio_ai_defender_artifacts\ember_baseline_v1\evaluation_results.json | Present |
| Trusted digest | app/ml/classifier.py:29 | f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684 |

Model loads successfully: is_loaded=True, model_name=ember-v2-baseline-hgb-subset80k, thresholds loaded.

## 3. Phase B: Dataset Readiness

### 3.1 Dataset
| Item | Value |
|------|-------|
| Archive | storage/ember_dataset_2018_2.tar.bz2 (1,696,539,273 bytes) |
| SHA-256 | b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812 (VERIFIED) |
| Extracted | storage/ember2018/ |

### 3.2 Files and Records
| File | Size | Records |
|------|------|---------|
| train_features_0.jsonl | 566,173,907 | 50,000 |
| train_features_1.jsonl | 1,659,892,947 | 158,158 |
| train_features_3.jsonl | 1,376,529,640 | 129,195 |
| test_features.jsonl | 1,869,447,260 | 200,000 |
| ember_model_2018.txt | 127,284,141 | - |
| **Total** | ~5.5 GB | **537,353** |

Schema: has datadirectories (Feature v2, 2,381 dims), md5, avclass, appeared. Labels 0/1 present.

### 3.3 Decision
**READY** - Provenance verified, compatible schema, sufficient samples, model exists.

## 4. Phase C: Training Pipeline Audit

Verified: feature schema validation, label mapping, train-only preprocessing, train/val/test separation, 0 hash overlaps, unlabeled (-1) excluded (76,989), test held out, seeds recorded, artifacts traceable. Classifier enforces SHA-256 verification, path allowlisting, input validation.

## 5. Phase D: Baseline Training Status

Completed in ML-04. Model: HistGradientBoostingClassifier, 80k balanced subset (40k/40k), 52k val, 200k test, seed 42, 300 iterations. Artifacts in D:\ethio_ai_defender_artifacts\ember_baseline_v1\.

## 6. Phase E: Evaluation Results

### Validation (N=52,073)
| Threshold | TPR | FPR | Accuracy | ROC-AUC | PR-AUC |
|-----------|-----|-----|----------|---------|--------|
| tau=0.5 | 96.62% | 3.55% | 96.52% | 0.9946 | 0.9935 |
| tau=0.8004 (1% FPR) | 91.41% | 1.00% | 95.77% | - | - |
| tau=0.9664 (0.1% FPR) | 76.60% | 0.10% | 89.97% | - | - |

### Test (N=200,000, official)
| Threshold | TPR | FPR | Accuracy | ROC-AUC | PR-AUC |
|-----------|-----|-----|----------|---------|--------|
| tau=0.5 | 94.15% | 7.09% | 93.53% | 0.9801 | 0.9813 |
| tau=0.8004 (1% FPR) | 85.53% | 2.23% | 91.65% | - | - |
| tau=0.9664 (0.1% FPR) | 54.67% | 0.20% | 77.24% | - | - |

Confusion matrices in metadata/evaluation_results.json. Model SHA-256: f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684. Reload parity verified.

## 7. Phase F: Tests

ML tests: 166/166 PASSED (upstream parity 20, feature parity 8, ember_v2 45, adapter 34, serialization 30, classifier 11, baseline 4, inference parity 5, shadow 5, evaluator 4). ML-08B: 15 fixtures, 35,715 comparisons, 100% within 1e-5, max diff 4.77e-7.

## 8. Production Safety

No production thresholds/heuristics/is_reliable/parity gate modified. ML shadow mode default OFF. Model from approved paths only, SHA-256 enforced. No PE samples executed.

## 9. Recommendation

**READY FOR ML-09 CLOSURE** - Dataset ready, baseline trained and verified, evaluation complete, all ML tests pass, production isolation maintained.
