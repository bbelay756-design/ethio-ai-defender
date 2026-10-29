"""
Unit & Integration Tests for ML-14: Modern Corpus Retraining Pipeline Infrastructure.

Verifies:
1. Passive PE parsing (pefile/lief) with zero process detonation.
2. Deduplication and hash indexing during ingestion.
3. Memory-mapped streaming feature extraction (2,381 dims, float32, all finite).
4. Candidate model output isolation (never overwrites authoritative baseline).
5. Clean BLOCKED status reporting when required modern corpus is unavailable.
"""

import json
import tempfile
import unittest
from pathlib import Path
import numpy as np
import joblib

from app.ml.ember_v2 import EMBER_V2_TOTAL_DIM
from app.ml.classifier import TRUSTED_BASELINE_MODEL_SHA256, DEFAULT_PRIMARY_MODEL_DIR
from scripts.ingest_modern_corpus import validate_pe_integrity, curate_modern_corpus, compute_sha256
from scripts.extract_features_streaming import stream_features_to_mmap
from scripts.train_modern_baseline import train_candidate_model
from tests.test_pe_analyzer import build_synthetic_pe


class TestModernTrainingPipeline(unittest.TestCase):
    """Tests ML-14 pipeline components and safety constraints."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _create_dummy_pe(self, name: str) -> Path:
        """Create a valid harmless mock PE byte sequence for passive parsing."""
        path = self.tmp_dir / name
        path.write_bytes(build_synthetic_pe(is_64bit=True, num_sections=2))
        return path

    def test_01_passive_pe_validation_no_detonation(self):
        """Passive integrity parsing inspects PE headers without execution."""
        pe_path = self._create_dummy_pe("test_passive.exe")
        info = validate_pe_integrity(pe_path)
        self.assertIsNotNone(info)
        self.assertTrue(info["is_valid_pe"])
        self.assertEqual(info["architecture"], "x64")

    def test_02_ingest_deduplication(self):
        """Duplicate PE files with identical SHA-256 are safely deduplicated."""
        pe1 = self._create_dummy_pe("sample1.exe")
        pe2 = self.tmp_dir / "sample2.exe"
        pe2.write_bytes(pe1.read_bytes())  # Identical hash

        benign_dir = self.tmp_dir / "benign"
        benign_dir.mkdir(parents=True)
        (benign_dir / "s1.exe").write_bytes(pe1.read_bytes())
        (benign_dir / "s2.exe").write_bytes(pe2.read_bytes())

        out_dir = self.tmp_dir / "corpus_out"
        manifest = curate_modern_corpus(
            benign_dir=benign_dir,
            malware_dir=None,
            ethiopian_dir=None,
            output_dir=out_dir,
        )

        self.assertEqual(manifest["counts"]["benign"], 1)
        self.assertEqual(manifest["counts"]["rejected"], 1)

    def test_03_streaming_mmap_extraction(self):
        """Streaming extractor creates valid memory-mapped arrays with correct dimensions."""
        pe = self._create_dummy_pe("extract_test.exe")
        manifest_data = {
            "dataset_name": "TEST",
            "records": [{"sha256": compute_sha256(pe), "label": 0, "source_path": str(pe)}],
        }
        manifest_file = self.tmp_dir / "test_manifest.json"
        manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

        out_mmap_dir = self.tmp_dir / "mmap_out"
        res = stream_features_to_mmap(
            manifest_path=manifest_file,
            sample_base_dir=self.tmp_dir,
            output_dir=out_mmap_dir,
        )

        self.assertEqual(res["status"], "COMPLETED")
        self.assertEqual(res["successfully_extracted"], 1)

        # Inspect resulting mmap
        x_mmap = np.memmap(out_mmap_dir / "X_modern.mmap", dtype=np.float32, mode="r", shape=(1, EMBER_V2_TOTAL_DIM))
        self.assertEqual(x_mmap.shape, (1, EMBER_V2_TOTAL_DIM))
        self.assertTrue(np.all(np.isfinite(x_mmap)))

    def test_04_candidate_training_isolated_output(self):
        """Candidate model is saved in separate directory and never overwrites authoritative model."""
        # Create synthetic staged mmap with 20 samples
        n_samples = 20
        x_path = self.tmp_dir / "X_modern.mmap"
        y_path = self.tmp_dir / "y_modern.mmap"

        X_synth = np.random.randn(n_samples, EMBER_V2_TOTAL_DIM).astype(np.float32)
        y_synth = np.array([0, 1] * 10, dtype=np.int32)

        x_mmap = np.memmap(x_path, dtype=np.float32, mode="w+", shape=(n_samples, EMBER_V2_TOTAL_DIM))
        x_mmap[:] = X_synth[:]
        x_mmap.flush()

        y_mmap = np.memmap(y_path, dtype=np.int32, mode="w+", shape=(n_samples,))
        y_mmap[:] = y_synth[:]
        y_mmap.flush()

        cand_out = self.tmp_dir / "candidate_model"
        res = train_candidate_model(
            x_mmap_path=x_path,
            y_mmap_path=y_path,
            output_dir=cand_out,
            val_ratio=0.3,
            random_seed=42,
        )

        self.assertEqual(res["status"], "PASS")
        self.assertTrue((cand_out / "model.joblib").exists())
        self.assertTrue((cand_out / "model.joblib.sha256").exists())
        self.assertTrue((cand_out / "metadata.json").exists())

        # Verify candidate metadata marks it as non-authoritative
        meta = json.loads((cand_out / "metadata.json").read_text(encoding="utf-8"))
        self.assertFalse(meta["is_authoritative_baseline"])

        # Verify authoritative model hash constant remains unchanged
        self.assertEqual(
            TRUSTED_BASELINE_MODEL_SHA256,
            "f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684",
        )

    def test_05_missing_corpus_reports_blocked(self):
        """Attempting to train without modern mmap feature arrays cleanly returns BLOCKED."""
        nonexistent_x = self.tmp_dir / "nonexistent_X.mmap"
        nonexistent_y = self.tmp_dir / "nonexistent_y.mmap"
        res = train_candidate_model(nonexistent_x, nonexistent_y)
        self.assertIn("BLOCKED", res["status"])


if __name__ == "__main__":
    unittest.main()
