import json
import math
import sys
import time
from pathlib import Path
from collections import Counter
import numpy as np

repo_root = Path(r"C:\Users\MILKWAY\ethio-ai-defender")
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from app.ml.ember_adapter import (
    EmberDatasetAdapter,
    EMBER_TOTAL_DIM,
)

data_dir = repo_root / "storage" / "ember2018"
adapter = EmberDatasetAdapter(feature_version=2, strict=True)

# List completed files to validate
files_to_validate = [
    ("test", data_dir / "test_features.jsonl"),
    ("train", data_dir / "train_features_0.jsonl"),
    ("train", data_dir / "train_features_1.jsonl"),
    ("train", data_dir / "train_features_3.jsonl"),
]

print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting Phase D Validation on Completed Extracted Files\n")

global_sha256 = {}
results = {}

for split_type, file_path in files_to_validate:
    if not file_path.exists():
        print(f"Skipping {file_path.name} (does not exist)")
        continue
        
    f_size = file_path.stat().st_size
    print(f"{'='*70}")
    print(f"VALIDATING: {file_path.name} ({f_size:,} bytes, {f_size/(1024**2):.1f} MB) - Split: {split_type.upper()}")
    print(f"{'='*70}")
    
    t0 = time.time()
    line_count = 0
    valid_count = 0
    json_errs = 0
    schema_errs = 0
    vector_errs = 0
    sample_vectors_checked = 0
    sample_freq = 5000  # verify full 2381-dim vectorization every 5,000 records
    
    labels_counter = Counter()
    local_duplicates = set()
    local_seen = set()
    
    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_count += 1
            stripped = line.strip()
            if not stripped:
                continue
                
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as e:
                json_errs += 1
                if json_errs <= 3:
                    print(f"  Line {line_num}: JSON error: {e}")
                continue
                
            sha = record.get("sha256")
            if sha:
                if sha in local_seen:
                    local_duplicates.add(sha)
                else:
                    local_seen.add(sha)
                    
                if sha not in global_sha256:
                    global_sha256[sha] = {"splits": set(), "labels": set()}
                global_sha256[sha]["splits"].add(split_type)
                
            lbl = record.get("label")
            if lbl is not None:
                labels_counter[lbl] += 1
                if sha:
                    global_sha256[sha]["labels"].add(lbl)
                    
            errs = adapter.validate_record(record, split=split_type)
            if errs:
                schema_errs += 1
                if schema_errs <= 3:
                    print(f"  Line {line_num}: Schema error: {errs[0]}")
            else:
                valid_count += 1
                
            # Sample vectorization check
            if line_count % sample_freq == 1:
                try:
                    vec, v_lbl = adapter.parse_record(record, split=split_type)
                    if vec.shape != (EMBER_TOTAL_DIM,) or not np.all(np.isfinite(vec)):
                        vector_errs += 1
                    else:
                        sample_vectors_checked += 1
                except Exception as ex:
                    vector_errs += 1
                    if vector_errs <= 3:
                        print(f"  Line {line_num}: Vector conversion error: {ex}")
                        
            if line_count % 50000 == 0:
                elapsed = time.time() - t0
                print(f"  Progress: {line_count:,} records ({line_count/elapsed:,.0f} rec/s) - Labels: {dict(labels_counter)}")
                
    elapsed = time.time() - t0
    print(f"\nCompleted {file_path.name} in {elapsed:.1f}s ({line_count/elapsed:,.0f} rec/s):")
    print(f"  Total records:           {line_count:,}")
    print(f"  Valid records:           {valid_count:,}")
    print(f"  JSON errors:             {json_errs}")
    print(f"  Schema errors:           {schema_errs}")
    print(f"  Vector conversion errors:{vector_errs}")
    print(f"  Sample vectors checked:  {sample_vectors_checked:,} (shape 2,381, finite float32)")
    print(f"  Unique SHA-256:          {len(local_seen):,}")
    print(f"  Within-file duplicates:  {len(local_duplicates):,}")
    print(f"  Label distribution:      {dict(labels_counter)}\n")
    
    results[file_path.name] = {
        "split": split_type,
        "total": line_count,
        "valid": valid_count,
        "json_errors": json_errs,
        "schema_errors": schema_errs,
        "vector_errors": vector_errs,
        "sample_checked": sample_vectors_checked,
        "unique_sha": len(local_seen),
        "duplicates": len(local_duplicates),
        "labels": dict(labels_counter),
        "elapsed_sec": elapsed,
    }

# Check cross-split duplicates
cross_split_dups = [sha for sha, info in global_sha256.items() if len(info["splits"]) > 1]
conflicting_labels = [sha for sha, info in global_sha256.items() if len(info["labels"]) > 1]

print(f"{'='*70}")
print("CROSS-SPLIT INTEGRITY CHECK")
print(f"{'='*70}")
print(f"Total unique SHA-256 indexed:        {len(global_sha256):,}")
print(f"Cross-split duplicates (train/test): {len(cross_split_dups):,}")
print(f"Conflicting labels for same SHA:     {len(conflicting_labels):,}")

# Output summary as JSON
results_payload = {
    "files": results,
    "cross_split_duplicates": len(cross_split_dups),
    "conflicting_labels": len(conflicting_labels),
}
print(f"\n{'='*70}\nPHASE D JSON SUMMARY\n{'='*70}")
print(json.dumps(results_payload, indent=2))

out_json = repo_root / "storage" / "phase_d_validation_results.json"
try:
    with open(out_json, "w") as f:
        json.dump(results_payload, f, indent=2)
    print(f"\nPhase D Results written to {out_json}")
except Exception as e:
    print(f"\nNote: Could not write {out_json} directly ({e}), printed to stdout above.")
