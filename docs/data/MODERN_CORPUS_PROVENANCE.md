# ETHIO-AI DEFENDER — MODERN CORPUS PROVENANCE & RETRAINING SPECIFICATION

**Document Version:** 1.0  
**Date:** October 29, 2026  
**Governing Milestone:** ML-14 (Modern Corpus Retraining Pipeline)  
**Milestone Operational Status:** **`BLOCKED — REQUIRED MODERN CORPUS UNAVAILABLE`**  

---

## 1. EXECUTIVE SUMMARY & BLOCKER DECLARATION

Milestone ML-14 addresses temporal drift documented in the authoritative EMBER 2018 baseline model (where False Positive Rates surged from 1.0% to 2.235% across a 5-month temporal gap). 

### Operational Blocker Details:
- **Status:** **`BLOCKED — REQUIRED MODERN CORPUS UNAVAILABLE`**
- **Root Cause:** Neither the local workspace nor external attached artifacts contain a legally usable, verified 2024–2026 Portable Executable (PE) malware corpus or modern Ethiopian administrative/enterprise software corpus.
- **Strict Invariant Enforced:** In accordance with repository safety rules, synthetic PE binaries were not manufactured, existing historical EMBER records were not relabeled, and no false evaluation metrics were generated.
- **Completed Infrastructure:** The memory-conscious streaming ingestion, feature extraction, and isolated candidate training pipelines are fully implemented and verified via unit tests (`scripts/ingest_modern_corpus.py`, `scripts/extract_features_streaming.py`, `scripts/train_modern_baseline.py`).

---

## 2. CORPUS PROVENANCE & DATASET SPECIFICATION

When acquiring the modern corpus to unblock ML-14, the data must satisfy the following provenance and architectural standards:

### 2.1 Required Modern Datasets

| Partition | Time Boundary | Required Volume | Verification / Labeling Standard |
| :--- | :--- | :--- | :--- |
| **Modern Enterprise Benign** | 2024-01-01 to 2026-10-01 | $\ge 50,000$ PEs | Valid Authenticode signature from trusted Root CA, or clean record across $\ge 65$ VirusTotal engines with 0 detections. |
| **Modern Malware Threat Corpus** | 2024-01-01 to 2026-10-01 | $\ge 50,000$ PEs | Multi-vendor consensus ($\ge 5$ AV engines) with AVClass2 family classification. |
| **Ethiopian Institutional Software** | 2020-01-01 to 2026-10-01 | Complete available fleet | Documented chain of custody, organizational sign-off, Authenticode or custom internal trust manifest. |
| **Temporal Holdout Test Set** | 2026-06-01 to 2026-10-01 | $\ge 20,000$ PEs | Strictly disjoint from training corpus; represents latest threat posture. |

### 2.2 Prohibited Data Practices

- **Zero Detonation / Passive Static Only:** Submitted binaries must NEVER be executed or dynamic sandboxed. Feature extraction operates purely via passive static byte parsing (`pefile` and `lief`).
- **No Private Account Scraping:** Binaries must not be scraped from unauthorized operator drives or private network shares.
- **Strict Ethiopian Software Segregation:** Legitimate Ethiopian institutional binaries must remain in an audited, segregated partition (`category: ethiopian_institutional_benign`) to avoid poisoning generic enterprise models.

---

## 3. UNBLOCKING & RESUMPTION PROCEDURE

Once the curated modern PE corpus directories are populated on storage, execute the following commands to resume retraining:

### Step 1: Ingest and Validate Corpus
```powershell
python scripts/ingest_modern_corpus.py `
    --benign D:\modern_corpus\benign `
    --malware D:\modern_corpus\malware `
    --ethiopian D:\modern_corpus\ethiopian `
    --output storage/modern_corpus
```

### Step 2: Extract Streaming EMBER v2 Features (<3.5 GB RAM)
```powershell
python scripts/extract_features_streaming.py `
    --manifest storage/modern_corpus/modern_corpus_manifest.json `
    --samples D:\modern_corpus `
    --output storage/modern_staged
```

### Step 3: Train Candidate Model and Calibrate Thresholds
```powershell
python scripts/train_modern_baseline.py `
    --x-mmap storage/modern_staged/X_modern.mmap `
    --y-mmap storage/modern_staged/y_modern.mmap `
    --output storage/models/ember_modern_candidate_v1
```

### Step 4: Verify Candidate Acceptance Criteria
1. Candidate artifact saved to `storage/models/ember_modern_candidate_v1/model.joblib`.
2. Authoritative baseline model (`f2fd3ed4...`) remains bit-identical and untouched.
3. Candidate model achieves $\text{ROC-AUC} \ge 0.98$ and empirical $\text{FPR} \le 1.0\%$ at $\tau_{1\%}^*$ on the held-out temporal partition.
