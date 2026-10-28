import json
from pathlib import Path
p = Path(r'C:\Users\MILKWAY\ethio-ai-defender\storage\ember2018')
files = ['train_features_0.jsonl','train_features_1.jsonl','train_features_3.jsonl','test_features.jsonl']
for f in files:
    path = p/f
    cnt=0
    labels={}
    dupes=0
    seen=set()
    bad=0
    with open(path) as fh:
        for line in fh:
            cnt+=1
            try:
                obj = json.loads(line)
            except:
                bad+=1
                continue
            lbl = obj.get('label')
            labels[lbl] = labels.get(lbl,0)+1
            h = obj.get('sha256')
            if h in seen:
                dupes+=1
            seen.add(h)
    print(f, cnt, labels, dupes, bad)

