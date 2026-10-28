import json, os
p = r'C:\Users\MILKWAY\ethio-ai-defender\storage\ember2018'
files = ['train_features_0.jsonl','train_features_1.jsonl','train_features_3.jsonl','test_features.jsonl']
for f in files:
    path = os.path.join(p,f)
    cnt=0
    with open(path) as fh:
        for _ in fh:
            cnt+=1
    print(f, cnt)
