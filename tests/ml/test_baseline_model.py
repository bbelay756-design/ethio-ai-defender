"""
Unit and integration tests for ML-04 trained baseline model artifact.
"""

import hashlib
import json
from pathlib import Path
import numpy as np
import pytest
import joblib
from sklearn.ensemble import HistGradientBoostingClassifier

ARTIFACT_DIR = Path(r"D:\ethio_ai_defender_artifacts\ember_baseline_v1")
STAGE_DIR = Path(r"D:\ethio_ai_defender_artifacts\staged")


@pytest.fixture(scope="module")
def model_paths():
    model_path = ARTIFACT_DIR / "model.joblib"
    sha_path = ARTIFACT_DIR / "model.joblib.sha256"
    meta_path = ARTIFACT_DIR / "metadata.json"
    results_path = ARTIFACT_DIR / "evaluation_results.json"
    return {
        "model": model_path,
        "sha": sha_path,
        "meta": meta_path,
        "results": results_path,
    }


def test_artifact_files_exist(model_paths):
    for name, path in model_paths.items():
        assert path.exists(), f"Artifact file missing: {path}"
        assert path.stat().st_size > 0, f"Artifact file is empty: {path}"


def test_model_sha256_checksum(model_paths):
    # Read recorded checksum
    with open(model_paths["sha"], "r") as f:
        recorded_line = f.read().strip()
    recorded_sha = recorded_line.split()[0]
    
    # Compute actual checksum
    hasher = hashlib.sha256()
    with open(model_paths["model"], "rb") as f:
        while chunk := f.read(1048576):
            hasher.update(chunk)
    actual_sha = hasher.hexdigest()
    
    assert actual_sha == recorded_sha, f"SHA-256 mismatch: {actual_sha} vs {recorded_sha}"


def test_metadata_contract(model_paths):
    with open(model_paths["meta"], "r") as f:
        meta = json.load(f)
    
    assert meta["model_name"] == "ember-v2-baseline-hgb-subset80k"
    assert meta["model_version"] == "1.0.0"
    assert meta["dataset"]["feature_dim"] == 2381
    assert meta["dataset"]["training_sample_count"] == 80000
    assert meta["dataset"]["training_class_distribution"] == {"0": 40000, "1": 40000}
    assert meta["dataset"]["validation_sample_count"] == 52073
    assert meta["dataset"]["test_sample_count"] == 200000
    assert "calibrated_thresholds" in meta
    assert meta["calibrated_thresholds"]["fpr_1pct_target"]["threshold"] > 0.5


def test_model_reload_and_prediction_contract(model_paths):
    clf = joblib.load(model_paths["model"])
    assert isinstance(clf, HistGradientBoostingClassifier)
    assert clf.n_features_in_ == 2381

    # Load 5 real validation samples
    x_val_path = STAGE_DIR / "X_val.mmap"
    assert x_val_path.exists()
    X_val = np.memmap(x_val_path, dtype="float32", mode="r", shape=(52073, 2381))
    
    sample = X_val[:5]
    probs = clf.predict_proba(sample)
    
    assert probs.shape == (5, 2)
    assert np.all(np.isfinite(probs))
    assert np.all(probs >= 0.0) and np.all(probs <= 1.0)
    np.testing.assert_allclose(probs.sum(axis=1), np.ones(5), atol=1e-5)
