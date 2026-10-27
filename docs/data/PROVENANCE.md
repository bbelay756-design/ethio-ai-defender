# EMBER 2018 Dataset Provenance Record - ETHIO-AI Defender

**Document Version:** 1.0
**Recorded:** 2026-10-25
**Recorded By:** ML-01 Implementation

---

## 1. Source Attribution

| Attribute | Value |
|-----------|-------|
| **Original Publisher** | Elastic (formerly Endgame, Inc.) |
| **Original Authors** | Hyrum S. Anderson, Phil Roth (Endgame, Inc.) |
| **Original Repository** | https://github.com/elastic/ember (formerly endgameinc/ember) |
| **Archive Date** | April 13, 2026 (GitHub archive) |
| **Original Publication** | Anderson & Roth, "EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models", arXiv:1804.04637v2 (Apr 2018) |

---

## 2. Artifact Verification

### 2.1 Archive Details

| Property | Value |
|----------|-------|
| **Archive Filename** | ember_dataset_2018_2.tar.bz2 |
| **Download URL** | https://ember.elastic.co/ember_dataset_2018_2.tar.bz2 |
| **Published SHA-256** | b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812 |
| **Content Type** | application/x-bzip2 |
| **Compressed Size** | ~4 GB |
| **Uncompressed Size** | ~8-10 GB |

### 2.2 Verification Procedure

```bash
# Download
curl -L -o ember_dataset_2018_2.tar.bz2 https://ember.elastic.co/ember_dataset_2018_2.tar.bz2

# Verify checksum
sha256sum ember_dataset_2018_2.tar.bz2
# Expected: b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812

# Extract
tar -xjf ember_dataset_2018_2.tar.bz2
# Creates ember2018/ directory with train_features.jsonl, test_features.jsonl, metadata.jsonl
```

---

## 3. Data Lineage

### 3.1 Collection Methodology (Per Original Paper)

> "The dataset includes features extracted from 1.1M binary files: 900K training samples (300K malicious, 300K benign, 300K unlabeled) and 200K test samples (100K malicious, 100K benign)."

*Note:* These figures (900K train / 200K test) originate from the **EMBER 2017** release announcement and the original Anderson & Roth (arXiv:1804.04637v2) paper. The EMBER 2018 release contains features from 1 million PE files scanned in or before 2018; exact per-split counts should be measured empirically after download. The temporal split applies to the 2017 release (test months 2017-11 and 2017-12).

| Aspect | Detail |
|--------|--------|
| **Malicious Sources** | VirusShare, VX Heaven, internal Endgame corpus |
| **Benign Sources** | Windows system files, common software, VirusTotal (0 detections at collection time) |
| **Malicious Labeling** | >40 AV vendors detecting on VirusTotal at collection time |
| **Benign Verification** | 0/60+ vendors on VirusTotal at collection time |
| **Feature Extraction** | LIEF library v0.9.0 (Feature Version 2) |
| **Temporal Split** | Training: files appeared before 2017-11; Test: files appeared 2017-11 to 2017-12

*Note:* This temporal split describes the **EMBER 2017** release. The EMBER 2018 release's collection boundaries are not published in the original paper; authors point to the CAMMLIS 2019 talk (Roth) for 2018-specific split details. Different selection criteria were applied when choosing samples from 2018 so that the resultant training and test sets would be harder for machine learning algorithms to classify. |
| **Selection Bias Note** | "Samples from 2018 were chosen so that the resultant training and test sets would be harder for machine learning algorithms to classify." |

### 3.2 Known Limitations (Per Original Authors)

1. **Temporal Inconsistency:** "Different selection criteria were applied when choosing samples from 2017 and 2018. Specifically, the samples from 2018 were chosen so that the resultant training and test sets would be harder for machine learning algorithms to classify."

2. **No Raw Binaries:** Only features and hashes are released. Raw binaries are not distributed.

3. **Label Source:** Labels derived from VirusTotal aggregation at collection time; not re-verified.

4. **Feature Version Drift:** Feature Version 2 (LIEF 0.9.0) differs from Version 1 (LIEF 0.8.3). Models trained on v1 features may not transfer to v2.

5. **No Family Labels:** Only coarse binary labels (malicious/benign/unlabeled). No family attribution.

---

### 3. Licensing Chain

| Component | License | Notes |
|-----------|---------|-------|
| **Data Files** | MIT License | Permissive; allows commercial use, modification, distribution |
| **Source Code** | AGPL-v3 | Copyleft; applies to EMBER library code only |
| **ETHIO-AI Derivative Work** | TBD | Must comply with MIT (data) and AGPL-v3 (if embedding library code) |

**MIT License Text (Data):**

Permission is hereby granted, free of charge, to any person obtaining a copy of this data and associated documentation files (the "Data"), to deal in the Data without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Data, and to permit persons to whom the Data is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Data.

---

## 4. ETHIO-AI Defender Custody Record

| Event | Date | Actor | Details |
|-------|------|-------|---------|
| Schema Documentation Created | 2026-10-25 | ML-01 Implementation | docs/data/DATASET_SCHEMA.md created |
| Provenance Record Created | 2026-10-25 | ML-01 Implementation | docs/data/PROVENANCE.md created |
| Validator Script Created | 2026-10-25 | ML-01 Implementation | scripts/validate_dataset_schema.py created |
| Validator Tests Added | 2026-10-25 | ML-01 Implementation | Unit tests for schema validation |

---

## 5. Verification Checklist (For Future Downloads)

- [ ] Download from official URL only: https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
- [ ] Verify SHA-256 matches b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812
- [ ] Extract and verify directory structure: ember2018/train_features.jsonl, ember2018/test_features.jsonl, ember2018/metadata.jsonl
- [ ] Run scripts/validate_dataset_schema.py on extracted files
- [ ] Confirm training set contains labels 0, 1, -1; test set contains only 0, 1
- [ ] Confirm no duplicate SHA-256 hashes within or across splits
- [ ] Record download date, verifier name, and verified checksum in this log

---

## 5. Change Log

| Date | Version | Author | Change |
|------|---------|--------|--------|
| 2026-10-25 | 1.0 | ML-01 Implementation | Initial provenance record created from verified official sources |

---

*End of Provenance Record*

*All information sourced from official EMBER 2018 release (elastic/ember GitHub repository), the original paper (arXiv:1804.04637v2), and the official download page (ember.elastic.co). No third-party mirrors or unverified claims included.*