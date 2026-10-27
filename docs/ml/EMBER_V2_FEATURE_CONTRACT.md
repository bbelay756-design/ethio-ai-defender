# EMBER v2 Feature Contract

**Version:** 2.0  
**Source:** Official EMBER reference implementation (`elastic/ember` repository, `ember/features.py`)  
**LIEF Version:** 0.9.0 (reference), 1.0.0 (current, compatible)  
**Feature Version:** 2  
**Total Dimensions:** 2,381 (float32)

---

## Feature Group Order and Dimensions

The EMBER v2 feature vector is a concatenation of 9 feature groups in the following fixed order:

| Order | Feature Group | Class | Dimensions | Description |
|-------|---------------|-------|------------|-------------|
| 1 | ByteHistogram | `ByteHistogram` | 256 | Normalized byte frequency histogram |
| 2 | ByteEntropyHistogram | `ByteEntropyHistogram` | 256 | 2D byte/entropy joint histogram (16×16) |
| 3 | StringExtractor | `StringExtractor` | 104 | String statistics and printable character distribution |
| 4 | GeneralFileInfo | `GeneralFileInfo` | 10 | Basic file metadata and PE properties |
| 5 | HeaderFileInfo | `HeaderFileInfo` | 62 | COFF and Optional header fields |
| 6 | SectionInfo | `SectionInfo` | 255 | Section metadata with feature hashing |
| 7 | ImportsInfo | `ImportsInfo` | 1,280 | Imported libraries and functions (hashed) |
| 8 | ExportsInfo | `ExportsInfo` | 128 | Exported functions (hashed) |
| 9 | DataDirectories | `DataDirectories` | 30 | First 15 data directories (size + RVA) |

**Total Dimensions: 2,381**

---

## Feature Group Specifications

### 1. ByteHistogram (256 dimensions)
- **Class:** `ByteHistogram`
- **Method:** `np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)`
- **Normalization:** L1 normalization (divide by sum)
- **Output:** float32 array of length 256, sums to 1.0
- **Edge case:** Empty input → all zeros

### 2. ByteEntropyHistogram (256 dimensions)
- **Class:** `ByteEntropyHistogram`
- **Window:** 2048 bytes, **Step:** 1024 bytes
- **Entropy bins:** 16 (0-15, where 15 = entropy ≥ 8.0 bits)
- **Byte value bins:** 16 (byte >> 4)
- **Output shape:** 16×16 = 256, flattened row-major
- **Normalization:** L1 normalization (divide by sum)
- **Window stride:** 1024 bytes
- **Edge case:** File smaller than window → single entropy calculation

### 3. StringExtractor (104 dimensions)
- **Class:** `StringExtractor`
- **Min string length:** 5 characters
- **Character range:** 0x20–0x7F (printable ASCII)
- **Regex:** `[\x20-\x7f]{5,}`

**Output components (in order):**
1. `numstrings` (float) - count of strings
2. `avlength` (float) - average string length
3. `printables` (float) - total printable characters
4. `printabledist` (96 floats) - normalized histogram of printable chars (0x20-0x7F)
5. `entropy` (float) - Shannon entropy of printable characters
6. `paths` (float) - count of `c:\` (case-insensitive)
7. `urls` (float) - count of `http://` or `https://` (case-insensitive)
8. `registry` (float) - count of `HKEY_` strings
9. `MZ` (float) - count of `MZ` strings

**Total:** 1 + 1 + 1 + 96 + 1 + 1 + 1 + 1 + 1 = 104

### 4. GeneralFileInfo (10 dimensions)
- **Class:** `GeneralFileInfo`
- **Output order:**
  1. `size` (float) - file size in bytes
  2. `vsize` (float) - virtual size
  3. `has_debug` (float, 0/1)
  4. `exports` (float) - count of exported functions
  5. `imports` (float) - count of imported functions
  6. `has_relocations` (float, 0/1)
  6. `has_resources` (float, 0/1)
  7. `has_signature` (float, 0/1)
  7. `has_tls` (float, 0/1)
  8. `symbols` (float)

**Edge case (lief_binary is None):** Returns zeros for all except `size` = len(bytez)

### 5. HeaderFileInfo (62 dimensions)
- **Class:** `HeaderFileInfo`
- **Uses FeatureHasher(10) for categorical fields**

**Output order (concatenated):**
1. `coff.timestamp` (float)
2. `coff.machine` (10-dim hashed)
3. `coff.characteristics` (10-dim hashed)
4. `optional.subsystem` (10-dim hashed)
4. `optional.dll_characteristics` (10-dim hashed)
5. `optional.magic` (10-dim hashed)
6. `optional.major_image_version` (float)
7. `optional.minor_image_version` (float)
7. `optional.major_linker_version` (float)
8. `optional.minor_linker_version` (float)
8. `optional.major_operating_system_version` (float)
9. `optional.minor_operating_system_version` (float)
9. `optional.major_subsystem_version` (float)
10. `optional.minor_subsystem_version` (float)
10. `optional.sizeof_code` (float)
10. `optional.sizeof_headers` (float)
11. `optional.sizeof_heap_commit` (float)

**Total:** 1 + 10 + 10 + 10 + 10 + 10 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 = 62

**Edge case (lief_binary is None):** All zeros

### 6. SectionInfo (255 dimensions)
- **Class:** `SectionInfo`
- **Uses FeatureHasher for section attributes**

**Output order (concatenated):**
1. `general` (5 floats): [num_sections, zero_size_count, empty_name_count, rx_count, w_count]
2. `section_sizes_hashed` (50-dim) - FeatureHasher(50) on (name, size) pairs
3. `section_entropy_hashed` (50-dim) - FeatureHasher(50) on (name, entropy) pairs
4. `section_vsize_hashed` (50-dim) - FeatureHasher(50) on (name, vsize) pairs
4. `entry_name_hashed` (50-dim) - FeatureHasher(50) on entry section name
5. `characteristics_hashed` (50-dim) - FeatureHasher(50) on entry section characteristics

**Total:** 5 + 50 + 50 + 50 + 50 + 50 = 255

**Edge case (lief_binary is None):** All zeros, empty entry name

### 7. ImportsInfo (1,280 dimensions)
- **Class:** `ImportsInfo`
- **Uses FeatureHasher**

**Output order:**
1. `libraries_hashed` (256-dim) - FeatureHasher(256) on unique library names (lowercase)
2. `imports_hashed` (1024-dim) - FeatureHasher(1024) on "library:function" pairs

**Processing details:**
- Library names lowercased
- Function names clipped to 10,000 chars
- Ordinal imports encoded as "ordinal{N}"
- Duplicate libraries merged

**Total:** 256 + 1024 = 1,280

**Edge case (lief_binary is None):** All zeros

### 8. ExportsInfo (128 dimensions)
- **Class:** `ExportsInfo`
- **FeatureHasher(128)** on export names

**Processing:**
- LIEF ≥ 0.10: export objects with `.name` attribute
- LIEF < 0.10: export names are strings
- Names clipped to 10,000 chars

**Total:** 128

**Edge case (lief_binary is None):** All zeros

### 9. DataDirectories (30 dimensions)
- **Class:** `DataDirectories` (Feature Version 2 only)
- **15 data directories × 2 fields = 30**

**Order (fixed):**
1. EXPORT_TABLE
2. IMPORT_TABLE
3. RESOURCE_TABLE
4. EXCEPTION_TABLE
5. CERTIFICATE_TABLE
6. BASE_RELOCATION_TABLE
7. DEBUG
8. ARCHITECTURE
9. GLOBAL_PTR
10. TLS_TABLE
11. LOAD_CONFIG_TABLE
11. BOUND_IMPORT
12. IAT
12. DELAY_IMPORT_DESCRIPTOR
13. CLR_RUNTIME_HEADER

**Per directory:** [size, virtual_address] (float32)

**Total:** 15 × 2 = 30

**Edge case (lief_binary is None):** All zeros

---

## Feature Vector Construction

```python
# Exact concatenation order:
feature_vector = np.hstack([
    byte_histogram,           # 256
    byte_entropy_histogram,   # 256
    string_features,          # 104
    general_info,             # 10
    header_info,              # 62
    section_info,             # 255
    imports_info,             # 1280
    exports_info,             # 128
    data_directories          # 30
]).astype(np.float32)
```

**Total:** 2,381 dimensions (float32)

---

## Feature Version Handling

| Version | DataDirectories | LIEF Version | Warning |
|---------|----------------|--------------|---------|
| 1 | Excluded | 0.8.3 | Warn if not 0.8.3 |
| 2 | Included | 0.9.0 | Warn if not 0.9.0 |

Current LIEF version: 1.0.0 (compatible with v2)

---

## Reference Implementation Compatibility

**Source:** `elastic/ember/blob/master/ember/features.py`  
**Reference commit:** Verified against master branch  
**Feature version:** 2  
**LIEF reference:** 0.9.0 (current: 1.0.0 - compatible)  
**sklearn:** 1.9.1 (FeatureHasher API stable)  
**numpy:** 2.5.4 (compatible)

---

## Compatibility Requirements

1. **Exact dimension match:** 2,381 float32 elements
2. **Exact order match:** 9 groups in specified order
3. **Feature hashing:** Must use sklearn's FeatureHasher with same parameters
4. **LIEF parsing:** Must handle same edge cases
5. **Normalization:** L1 normalization for histograms
6. **Float32 output:** Final vector must be float32
6. **Ordering:** Exact concatenation order as specified

---

## Version Information

- **Contract Version:** 2.0
- **EMBER Feature Version:** 2
- **LIEF Version:** 1.0.0 (reference: 0.9.0)
- **sklearn Version:** 1.9.1
- **numpy Version:** 2.5.4
- **Python Version:** 3.14.4
- **Platform:** Windows (win_amd64)