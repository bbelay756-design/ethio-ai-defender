import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

repo_root = Path(r"C:\Users\MILKWAY\ethio-ai-defender")
data_dir = repo_root / "storage" / "ember2018"

files_to_check = [
    ("test", data_dir / "test_features.jsonl"),
    ("train", data_dir / "train_features_0.jsonl"),
    ("train", data_dir / "train_features_1.jsonl"),
    ("train", data_dir / "train_features_3.jsonl"),
]

re_sha = re.compile(r'"sha256":\s*"([0-9a-fA-F]{64})"')
re_label = re.compile(r'"label":\s*(-?\d+)')

print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting Fast Stream Audit on EMBER 2018 Partitions\n")

global_sha = {}  # sha -> split
cross_split_dups = []
file_stats = {}

for split_type, file_path in files_to_check:
    if not file_path.exists():
        print(f"File not found: {file_path}")
        continue
    
    t0 = time.time()
    size_bytes = file_path.stat().st_size
    print(f"Checking {file_path.name} ({size_bytes:,} bytes, split={split_type})...")
    
    line_count = 0
    labels = Counter()
    local_sha = set()
    local_dups = 0
    invalid_labels = 0
    
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line_count += 1
            m_sha = re_sha.search(line)
            m_lbl = re_label.search(line)
            
            if m_sha:
                sha = m_sha.group(1).lower()
                if sha in local_sha:
                    local_dups += 1
                else:
                    local_sha.add(sha)
                
                prev_split = global_sha.get(sha)
                if prev_split and prev_split != split_type:
                    cross_split_dups.append((sha, prev_split, split_type))
                else:
                    global_sha[sha] = split_type
            else:
                pass
                
            if m_lbl:
                lbl = int(m_lbl.group(1))
                labels[lbl] += 1
                if lbl not in (-1, 0, 1):
                    invalid_labels += 1
            else:
                invalid_labels += 1
                
    elapsed = time.time() - t0
    rate = line_count / max(0.01, elapsed)
    print(f"  Done in {elapsed:.1f}s ({rate:,.0f} lines/s)")
    print(f"  Lines: {line_count:,}")
    print(f"  Labels: {dict(labels)}")
    print(f"  Local SHA duplicates: {local_dups}")
    print(f"  Invalid labels: {invalid_labels}\n")
    
    file_stats[file_path.name] = {
        "split": split_type,
        "size_bytes": size_bytes,
        "line_count": line_count,
        "labels": dict(labels),
        "local_duplicates": local_dups,
        "invalid_labels": invalid_labels,
        "elapsed_seconds": elapsed,
    }

print("=" * 60)
print(f"Total Unique SHA-256 tracked: {len(global_sha):,}")
print(f"Cross-Split Duplicates (Train vs Test): {len(cross_split_dups)}")
if cross_split_dups:
    print(f"  Examples: {cross_split_dups[:5]}")
print("=" * 60)

summary = {
    "files": file_stats,
    "total_unique_sha": len(global_sha),
    "cross_split_duplicates": len(cross_split_dups),
}

with open(repo_root / "scratch" / "stream_audit_summary.json", "w") as out:
    json.dump(summary, out, indent=2)

print(f"\nWritten summary to scratch/stream_audit_summary.json")
