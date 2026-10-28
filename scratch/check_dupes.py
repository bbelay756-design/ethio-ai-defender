import json
from pathlib import Path
from collections import Counter
p = Path(r'C:\Users\MILKWAY\ethio-ai-defender\storage\ember2018')
files = ['train_features_0.jsonl','train_features_1.jsonl','train_features_3.jsonl','test_features.jsonl']
all_hashes={}
for f in files:
    path = p/f
    with open(path) as fh:
        for line in fh:
            try:
                o=json.loads(line)
                h=o['sha256']
                all_hashes.setdefault(h,[]).append((f,o['label']))
            except Exception as e:
                pass
dupes=[k for k,v in all_hashes.items() if len(v)>1]
print('cross_dupes', len(dupes))
for d in dupes[:10]:
    print(all_hashes[d])

