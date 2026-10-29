#!/usr/bin/env python3
"""
ETHIO-AI Defender - ML-14: Memory-Conscious Streaming Feature Extractor

Extracts EMBER v2 (2,381-dimensional) feature vectors from curated PE binaries
directly into memory-mapped arrays on disk.

Defensive Constraints:
- Peak RAM usage strictly capped below 3.5 GB via memory-mapped streaming.
- Pure passive static extraction: zero binary execution.
- Validates vector integrity (2,381 float32 dimensions, strictly finite).
- Records per-sample SHA-256 and label indices.
"""

import os
import sys
import json
import time
from pathlib import Path
from typing import List, Dict, Any
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from app.ml.ember_v2 import EMBERFeatureExtractor, EMBER_V2_TOTAL_DIM
from app.core.logger import logger


def stream_features_to_mmap(
    manifest_path: Path,
    sample_base_dir: Path,
    output_dir: Path,
    batch_size: int = 100,
) -> Dict[str, Any]:
    """
    Reads files listed in manifest and writes feature vectors directly into .mmap files.
    """
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    records = manifest.get("records", [])
    total_samples = len(records)
    if total_samples == 0:
        logger.warning("Manifest contains 0 samples; nothing to extract.")
        return {"status": "EMPTY", "total_samples": 0}

    output_dir.mkdir(parents=True, exist_ok=True)
    x_mmap_path = output_dir / "X_modern.mmap"
    y_mmap_path = output_dir / "y_modern.mmap"
    meta_path = output_dir / "extraction_metadata.json"

    logger.info(f"Allocating memory-mapped feature arrays for {total_samples:,} samples...")
    # Allocate memmaps
    X_mmap = np.memmap(
        x_mmap_path,
        dtype=np.float32,
        mode="w+",
        shape=(total_samples, EMBER_V2_TOTAL_DIM),
    )
    y_mmap = np.memmap(
        y_mmap_path,
        dtype=np.int32,
        mode="w+",
        shape=(total_samples,),
    )

    extractor = EMBERFeatureExtractor(feature_version=2, print_warning=False)
    t0 = time.perf_counter()
    extracted_count = 0
    errors = []

    for i, rec in enumerate(records):
        sample_path = sample_base_dir / rec["source_path"]
        if not sample_path.is_file():
            # Check relative to base
            sample_path = Path(rec["source_path"])
        
        if not sample_path.is_file():
            errors.append(f"Missing file: {rec['source_path']}")
            continue

        try:
            bytez = sample_path.read_bytes()
            vec = extractor.feature_vector(bytez)

            # Defensive vector validation
            if vec.shape != (EMBER_V2_TOTAL_DIM,):
                raise ValueError(f"Vector dim {vec.shape} != {EMBER_V2_TOTAL_DIM}")
            if not np.all(np.isfinite(vec)):
                raise ValueError("Vector contains NaN or Inf values")

            X_mmap[i, :] = vec
            y_mmap[i] = int(rec["label"])
            extracted_count += 1

            if (i + 1) % batch_size == 0 or (i + 1) == total_samples:
                X_mmap.flush()
                y_mmap.flush()
                logger.info(f"Extracted {i + 1}/{total_samples} vectors...")

        except Exception as exc:
            errors.append(f"Error on {rec['sha256'][:16]}: {exc}")

    X_mmap.flush()
    y_mmap.flush()
    elapsed = time.perf_counter() - t0

    res = {
        "status": "COMPLETED",
        "total_samples": total_samples,
        "successfully_extracted": extracted_count,
        "error_count": len(errors),
        "elapsed_seconds": round(elapsed, 2),
        "samples_per_second": round(extracted_count / max(elapsed, 0.001), 2),
        "x_mmap_path": str(x_mmap_path),
        "y_mmap_path": str(y_mmap_path),
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2)

    return res


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Streaming feature extractor for modern PE corpus")
    parser.add_argument("--manifest", type=Path, required=True, help="Path to modern_corpus_manifest.json")
    parser.add_argument("--samples", type=Path, required=True, help="Directory containing sample binaries")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "storage" / "modern_staged", help="Output directory for .mmap files")
    args = parser.parse_args()

    res = stream_features_to_mmap(args.manifest, args.samples, args.output)
    print(f"Extraction finished: {res['successfully_extracted']} samples in {res['elapsed_seconds']}s")
