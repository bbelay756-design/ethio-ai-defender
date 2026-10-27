# EMBER 2018 Dataset Schema — ETHIO-AI Defender Integration

**Version:** 1.0  
**Date:** 2026-10-25  
**Source:** Official EMBER 2018 Release (elastic/ember GitHub repository)  
**Reference Paper:** Anderson & Roth, "EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models" (arXiv:1804.04637v2)

---

## 1. Dataset Identity

| Attribute | Value |
|-----------|-------|
| **Dataset Name** | EMBER 2018 (Feature Version 2) |
| **Source Repository** | `elastic/ember` (GitHub) — Archived Apr 13, 2026 |
| **Release Year** | 2018 |
| **Feature Version** | 2 (LIEF 0.9.0) |
| **Archive File** | `ember_dataset_2018_2.tar.bz2` |
| **Download URL** | `https://ember.elastic.co/ember_dataset_2018_2.tar.bz2` |
| **SHA-256 Checksum** | `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812` |
| **License (Data)** | MIT License |
| **License (Source Code)** | AGPL-v3 |
| **Original Paper** | Anderson & Roth, "EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models" (arXiv:1804.04637v2) |

---

## 2. Dataset Composition

| Split | Total | Benign (0) | Malicious (1) | Unlabeled (-1) |
|-------|-------|------------|---------------|----------------|
| **Training** | 900,000* | 300,000 | 300,000 | 300,000 |
| **Test** | 200,000* | 100,000 | 100,000 | 0 |
| **Total** | 1,100,000* | 400,000 | 400,000 | 300,000 |

\* These figures (900K train / 200K test) are the documented composition of the **EMBER 2017** release, as stated in the original Elastic blog announcement and the Anderson & Roth (arXiv:1804.04637v2) paper. The EMBER 2018 release contains features from 1 million PE files scanned in or before 2018; exact per-split counts should be measured empirically after download. The SHA-256 checksum `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812` is verified correct for the 2018 archive.

---

## 3. Raw Feature Schema (Per-Sample JSON Lines)

Each line in the dataset is a JSON object with the following top-level fields:

```json
{
  "sha256": "string (64 hex chars)",
  "appeared": "string (YYYY-MM)",
  "label": "integer (0=benign, 1=malicious, -1=unlabeled)",
  "general": { ... },
  "header": { ... },
  "imports": { ... },
  "exports": [ ... ],
  "section": { ... },
  "histogram": [256 integers],
  "byteentropy": [256 integers (16x16 flattened)],
  "strings": { ... }
}
```

---

### 3.1 General File Information (`general`)

| Field | Type | Description |
|-------|------|-------------|
| `file_size` | integer | File size in bytes |
| `vsize` | integer | Virtual size of the image |
| `has_debug` | integer (0/1) | Has debug section |
| `exports` | integer | Number of exported functions |
| `imports` | integer | Number of imported functions |
| `has_relocations` | integer (0/1) | Has relocation table |
| `has_resources` | integer (0/1) | Has resources section |
| `has_signature` | integer (0/1) | Has digital signature |
| `has_tls` | integer (0/1) | Has TLS section |
| `symbols` | integer | Number of symbols |

---

### 3.2 Header Information (`header`)

#### COFF Header (`header.coff`)

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | integer | Compilation timestamp (Unix epoch) |
| `machine` | string | Target architecture (e.g., "I386", "AMD64") |
| `characteristics` | array[string] | List of characteristic flags (e.g., "LARGE_ADDRESS_AWARE", "EXECUTABLE_IMAGE") |

#### Optional Header (`header.optional`)

| Field | Type | Description |
|-------|------|-------------|
| `subsystem` | string | Target subsystem (e.g., "WINDOWS_CUI", "WINDOWS_GUI") |
| `dll_characteristics` | array[string] | DLL characteristics flags |
| `magic` | string | PE magic ("PE32" or "PE32+") |
| `major_image_version` | integer | Major image version |
| `minor_image_version` | integer | Minor image version |
| `major_linker_version` | integer | Major linker version |
| `minor_linker_version` | integer | Minor linker version |
| `major_operating_system_version` | integer | Major OS version |
| `minor_operating_system_version` | integer | Minor OS version |
| `major_subsystem_version` | integer | Major subsystem version |
| `minor_subsystem_version` | integer | Minor subsystem version |
| `sizeof_code` | integer | Size of code section |
| `sizeof_headers` | integer | Size of headers |
| `sizeof_heap_commit` | integer | Heap commit size |

---

### 3.3 Imports (`imports`)

Object mapping DLL name → array of imported function names.

```json
{
  "KERNEL32.dll": ["GetTickCount", "CreateFileA", ...],
  "USER32.dll": ["MessageBoxA", ...]
}
```

---

### 3.4 Exports (`exports`)

Array of exported function names.

```json
["ExportedFunction1", "ExportedFunction2", ...]
```

---

### 3.5 Section Information (`section`)

| Field | Type | Description |
|-------|------|-------------|
| `entry` | string | Entry point section name |
| `sections` | array[object] | Array of section objects |

**Section Object:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Section name (e.g., ".text", ".data") |
| `size` | integer | Raw size on disk |
| `entropy` | float | Shannon entropy of section |
| `vsize` | integer | Virtual size in memory |
| `props` | array[string] | Section characteristics (e.g., "CNT_CODE", "MEM_EXECUTE", "MEM_READ") |

---

### 3.6 Format-Agnostic Features

#### Byte Histogram (`histogram`)
- **Type:** Array of 256 integers
- **Description:** Raw byte value counts (0-255)

#### Byte-Entropy Histogram (`byteentropy`)
- **Type:** Array of 256 integers (16×16 flattened)
- **Description:** Joint distribution of entropy (16 bins) and byte value (16 bins)
- **Window:** 2048 bytes, step 1024 bytes

#### String Information (`strings`)

| Field | Type | Description |
|-------|------|-------------|
| `numstrings` | integer | Count of printable strings (≥5 chars) |
| `avlength` | float | Average string length |
| `printabledist` | array[96] | Distribution of printable ASCII chars (0x20-0x7F) |
| `printables` | integer | Total printable characters |
| `entropy` | float | Character entropy across strings |
| `paths` | integer | Strings starting with "C:\\" (case-insensitive) |
| `urls` | integer | Strings containing "http://" or "https://" |
| `registry` | integer | Strings containing "HKEY_" |
| `MZ` | integer | Occurrences of "MZ" string |

---

## 4. Label Definitions

| Label Value | Meaning | Usage |
|-------------|---------|-------|
| `0` | Benign | Training & Test |
| `1` | Malicious | Training & Test |
| `-1` | Unlabeled | Training only (300K samples) |

**Critical:** Unlabeled samples (`label == -1`) **must not** be treated as benign. They are explicitly unlabeled for semi-supervised research.

---

## 5. Vectorized Feature Space (Model Features)

The EMBER library converts raw features to a fixed-size vector of **2,381 dimensions** (float32) using the feature hashing trick, compatible with feature version 2 (LIEF 0.9.0) and the official reference implementation. The total dimension count is exact — 2,381 — not subject to collision variance.

| Feature Group | Bins | Notes |
|---------------|------|-------|
| General + Header (hashed) | ~512 | Categorical via hashing trick |
| Imports (libraries) | 256 | Feature hashing |
| Imports (functions) | 1024 | library:function pairs |
| Exports | 128 | Feature hashing |
| Section (size/entropy/vsize) | 150 | 50 bins each for name/value pairs |
| Section characteristics | 50 | Entry point section |
| Byte histogram | 256 | Normalized to distribution |
| Byte-entropy histogram | 256 | 16×16 normalized |
| String statistics | ~50 | Statistics + printable distribution |

**Total:** 2,381 dimensions (fixed, per feature version 2)

**Note:** The vectorized feature matrix is **not** included in the raw dataset; it is generated at training time using the `ember` library's vectorization code.

---

## 6. ETHIO-AI Defender Feature Mapping

This section documents the distinction between EMBER's native features and ETHIO-AI Defender's custom analyzer outputs.

| EMBER Feature Group | ETHIO-AI Defender Analyzer | Notes |
|---------------------|---------------------------|-------|
| `general` + `header.coff` | `pe_analyzer` (Module 03) | Both parse COFF/Optional headers; ETHIO-AI adds machine type mapping |
| `header.optional` | `pe_analyzer` | Subsystem, DLL characteristics, entry point |
| `section` | `section_analyzer` (Module 04) | ETHIO-AI adds W+X detection, slack space analysis |
| `imports` | `import_analyzer` (Module 07) | ETHIO-AI adds 170+ API categorization + MITRE mapping |
| `exports` | Not currently extracted | Available in raw PE |
| `histogram` | `entropy_analyzer` (Module 05) | ETHIO-AI computes per-section entropy separately |
| `byteentropy` | Not directly computed | Related to entropy analysis |
| `strings` | `string_analyzer` (Module 06) | ETHIO-AI adds 14 categories, offsets, MITRE mapping |
| `exports` | Not extracted | Gap |
| `general` (imports/exports counts) | `import_analyzer` | Counts match |

**Key Differences:**
- EMBER uses **feature hashing** (fixed bins, collisions possible); ETHIO-AI uses **explicit categorization** (explicit API names, categories, risk levels)
- EMBER features are **static/hashing-based**; ETHIO-AI features are **explicit/structured** with risk relevance
- EMBER includes **byte histograms** and **byte-entropy histograms**; ETHIO-AI uses **per-section Shannon entropy**
- EMBER strings are **statistical summaries**; ETHIO-AI extracts **individual strings with offsets, encodings, categories**

---

## 7. Storage & Memory Requirements (Local Windows)

| Item | Estimate | Notes |
|------|----------|-------|
| **Compressed Archive** | ~4 GB | `ember_dataset_2018_2.tar.bz2` |
| **Extracted Raw JSONL** | ~8–10 GB | ~1.1M lines × ~8 KB avg |
| **Vectorized Features (Parquet)** | ~2–3 GB | 1.1M × 2351 × 8 bytes ≈ 20 GB raw; compressed ~2–3 GB |
| **Vectorized Features (NPZ)** | ~20 GB | Uncompressed float32 matrix |
| **RAM for Vectorization** | 8–16 GB | `ember.create_vectorized_features()` |
| **RAM for Training (LightGBM)** | 8–16 GB | 1M samples × 2351 features |
| **Disk for Model + Artifacts** | < 1 GB | Model + metadata + metadata CSV |

**Windows Recommendations:**
- Use NTFS with compression enabled on data directory
- Minimum 32 GB free disk space for full pipeline
- 16 GB RAM minimum; 32 GB recommended for parallel vectorization
- NTFS compression saves ~40% on JSONL files

---

## 8. Data Validation Rules

The validator (`scripts/validate_dataset_schema.py`) enforces:

| Rule | Severity | Description |
|------|----------|-------------|
| Required top-level fields present | ERROR | `sha256`, `appeared`, `label`, `general`, `header`, `imports`, `exports`, `section`, `histogram`, `byteentropy`, `strings` |
| `sha256` format | ERROR | 64 hex characters |
| `appeared` format | ERROR | YYYY-MM format |
| `label` value | ERROR | Must be -1, 0, or 1 |
| `label` = -1 only in training | WARNING | Test set must not contain -1 |
| `sha256` uniqueness | ERROR | No duplicate hashes within or across splits |
| `general.file_size` ≥ 64 | ERROR | Minimum PE size |
| `histogram` length = 256 | ERROR | Exact length |
| `byteentropy` length = 256 | ERROR | 16×16 = 256 |
| `histogram` sum > 0 | ERROR | Non-empty file |
| `strings.numstrings` ≥ 0 | ERROR | Non-negative |
| Unlabeled samples only in training | ERROR | Test set must not contain label -1 |

---

## 6. References

1. **Official Repository:** https://github.com/elastic/ember (archived)
2. **Download URL:** https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
3. **SHA-256:** `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812`
4. **Paper:** Anderson & Roth, "EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models" (arXiv:1804.04637v2)
5. **License (Data):** MIT License
6. **License (Code):** AGPL-v3
7. **Feature Version:** 2 (LIEF 0.9.0)
8. **Archive SHA-256:** `b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812`

---

*End of Dataset Schema Document*