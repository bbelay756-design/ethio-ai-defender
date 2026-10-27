import json
from pathlib import Path

data_dir = Path("storage/ember2018")
files = [
    "test_features.jsonl",
    "train_features_0.jsonl",
    "train_features_1.jsonl",
    "train_features_3.jsonl",
]

for name in files:
    p = data_dir / name
    if not p.exists():
        print(f"{name}: NOT FOUND")
        continue
    with open(p, "rb") as f:
        first_line = f.readline().decode("utf-8")
        j1 = json.loads(first_line)
        f.seek(max(0, p.stat().st_size - 65536))
        tail_data = f.read().decode("utf-8", errors="ignore")
        tail_lines = [l for l in tail_data.splitlines() if l.strip()]
        last_line = tail_lines[-1] if tail_lines else ""
        j2 = json.loads(last_line)
        print(
            f"{name}: size={p.stat().st_size:,} bytes | "
            f"first_sha={j1.get('sha256')[:12]} (lbl={j1.get('label')}) | "
            f"last_sha={j2.get('sha256')[:12]} (lbl={j2.get('label')}) | Valid"
        )
