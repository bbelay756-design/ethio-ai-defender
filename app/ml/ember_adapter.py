"""
EMBER 2018 JSONL Dataset Adapter for ETHIO-AI Defender ML Pipeline.

Implements official EMBER 2018 Feature Version 2 JSONL schema parsing,
validation, and conversion into 2,381-dimensional float32 feature vectors
conforming to the EMBER v2 Feature Contract.

Contract & Schema Reference:
- docs/data/DATASET_SCHEMA.md
- docs/ml/EMBER_V2_FEATURE_CONTRACT.md
- ML03B_Schema_Adapter_Implementation_Plan.md
"""

import json
import math
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple, Union

import numpy as np
from sklearn.feature_extraction import FeatureHasher

# EMBER Feature Version 2 Constants
EMBER_FEATURE_VERSION = 2
EMBER_TOTAL_DIM = 2381

# Exact Feature Group Ordering and Dimensions per Contract
FEATURE_GROUP_NAMES = [
    "histogram",
    "byteentropy",
    "strings",
    "general",
    "header",
    "section",
    "imports",
    "exports",
    "datadirectories",
]

FEATURE_GROUP_DIMS = {
    "histogram": 256,
    "byteentropy": 256,
    "strings": 104,
    "general": 10,
    "header": 62,
    "section": 255,
    "imports": 1280,
    "exports": 128,
    "datadirectories": 30,
}

# Label Definitions
LABEL_UNLABELED = -1
LABEL_BENIGN = 0
LABEL_MALICIOUS = 1
VALID_LABELS: Set[int] = {LABEL_UNLABELED, LABEL_BENIGN, LABEL_MALICIOUS}

# Required Schema Fields per docs/data/DATASET_SCHEMA.md
REQUIRED_TOP_LEVEL_FIELDS = {
    "sha256",
    "appeared",
    "label",
    "general",
    "header",
    "imports",
    "exports",
    "section",
    "histogram",
    "byteentropy",
    "strings",
}

REQUIRED_GENERAL_FIELDS = {
    "vsize",
    "has_debug",
    "exports",
    "imports",
    "has_relocations",
    "has_resources",
    "has_tls",
    "symbols",
}

REQUIRED_STRINGS_FIELDS = {
    "numstrings",
    "avlength",
    "printables",
    "printabledist",
    "entropy",
    "paths",
    "urls",
    "registry",
    "MZ",
}

_HEX_64_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
_APPEARED_PATTERN = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")


class EmberAdapterError(ValueError):
    """Exception raised for errors during EMBER JSON record validation or conversion."""
    pass


class EmberDatasetAdapter:
    """
    Adapter that validates and converts official EMBER 2018 Feature Version 2 JSONL
    records into 2,381-dimensional float32 feature vectors.
    """

    def __init__(self, feature_version: int = 2, strict: bool = True):
        """
        Initialize the EMBER dataset adapter.

        Args:
            feature_version: Must be 2 (EMBER Feature Version 2).
            strict: If True, validate full record schema before extraction.
        """
        if feature_version != 2:
            raise EmberAdapterError(
                f"Unsupported feature version: {feature_version}. "
                f"Only EMBER Feature Version 2 is supported."
            )
        self.feature_version = feature_version
        self.strict = strict

        # Initialize FeatureHasher instances with alternate_sign=True
        # strictly adhering to the official elastic/ember reference contract.
        self._hashers = {
            "libraries": FeatureHasher(256, input_type="string", alternate_sign=True),
            "imports": FeatureHasher(1024, input_type="string", alternate_sign=True),
            "exports": FeatureHasher(128, input_type="string", alternate_sign=True),
            "section_sizes": FeatureHasher(50, input_type="pair", alternate_sign=True),
            "section_entropy": FeatureHasher(50, input_type="pair", alternate_sign=True),
            "section_vsize": FeatureHasher(50, input_type="pair", alternate_sign=True),
            "entry_name": FeatureHasher(50, input_type="string", alternate_sign=True),
            "characteristics": FeatureHasher(50, input_type="string", alternate_sign=True),
            "coff_machine": FeatureHasher(10, input_type="string", alternate_sign=True),
            "coff_characteristics": FeatureHasher(10, input_type="string", alternate_sign=True),
            "optional_subsystem": FeatureHasher(10, input_type="string", alternate_sign=True),
            "optional_dll_characteristics": FeatureHasher(10, input_type="string", alternate_sign=True),
            "optional_magic": FeatureHasher(10, input_type="string", alternate_sign=True),
        }

    @property
    def total_dim(self) -> int:
        return EMBER_TOTAL_DIM

    def validate_record(self, record: Any, split: Optional[str] = None) -> List[str]:
        """
        Validate record schema against documented EMBER 2018 specification.

        Args:
            record: The parsed JSON object to validate.
            split: Optional dataset split name ('train', 'test').

        Returns:
            List of error description strings. An empty list indicates a valid record.
        """
        errors: List[str] = []

        if not isinstance(record, dict):
            return ["Record must be a JSON dictionary"]

        # Check unsupported / incompatible schema flags
        if "feature_version" in record and record["feature_version"] != self.feature_version:
            errors.append(
                f"Incompatible schema feature_version {record['feature_version']}; expected {self.feature_version}"
            )

        # 1. Required top-level fields
        missing_fields = REQUIRED_TOP_LEVEL_FIELDS - set(record.keys())
        for mf in sorted(missing_fields):
            errors.append(f"Missing required top-level field: '{mf}'")

        # 2. SHA-256 validation
        sha256 = record.get("sha256")
        if sha256 is not None:
            if not isinstance(sha256, str) or not _HEX_64_PATTERN.match(sha256):
                errors.append(f"Field 'sha256' must be a 64-character hex string, got {sha256!r}")

        # 3. Appeared validation
        appeared = record.get("appeared")
        if appeared is not None:
            if not isinstance(appeared, str) or not _APPEARED_PATTERN.match(appeared):
                errors.append(f"Field 'appeared' must be in 'YYYY-MM' format (2000-2100), got {appeared!r}")

        # 4. Label validation (strict boolean filter: bool is a subclass of int in Python)
        label = record.get("label")
        if label is not None:
            if isinstance(label, bool) or not isinstance(label, (int, np.integer)):
                errors.append(f"Field 'label' must be an integer, got {type(label).__name__}")
            elif int(label) not in VALID_LABELS:
                errors.append(f"Field 'label' must be one of {-1, 0, 1}, got {label}")
            elif split and "test" in split.lower() and int(label) == LABEL_UNLABELED:
                errors.append("Unlabeled record (label=-1) is not permitted in test split")

        # 5. General validation
        general = record.get("general")
        if general is not None:
            if not isinstance(general, dict):
                errors.append("Field 'general' must be a dictionary")
            else:
                has_size = "file_size" in general or "size" in general
                if not has_size:
                    errors.append("Field 'general' missing required size field ('file_size' or 'size')")
                else:
                    sz = general.get("file_size", general.get("size"))
                    if isinstance(sz, bool) or not isinstance(sz, (int, float, np.number)):
                        errors.append(f"Field 'general' size must be numeric, got {type(sz).__name__}")
                    elif not math.isfinite(sz) or sz < 0:
                        errors.append(f"Field 'general' size must be a non-negative finite number, got {sz}")

                for req_g in sorted(REQUIRED_GENERAL_FIELDS):
                    if req_g not in general:
                        errors.append(f"Missing required field 'general.{req_g}'")
                    else:
                        val = general[req_g]
                        if isinstance(val, bool) or not isinstance(val, (int, float, np.number)):
                            errors.append(f"Field 'general.{req_g}' must be numeric, got {type(val).__name__}")
                        elif not math.isfinite(val):
                            errors.append(f"Field 'general.{req_g}' has non-finite value: {val}")

        # 6. Header validation
        header = record.get("header")
        if header is not None:
            if not isinstance(header, dict):
                errors.append("Field 'header' must be a dictionary")
            else:
                coff = header.get("coff")
                if coff is not None and not isinstance(coff, dict):
                    errors.append("Field 'header.coff' must be a dictionary")
                optional = header.get("optional")
                if optional is not None and not isinstance(optional, dict):
                    errors.append("Field 'header.optional' must be a dictionary")

        # 7. Section validation
        section = record.get("section")
        if section is not None:
            if not isinstance(section, dict):
                errors.append("Field 'section' must be a dictionary")
            else:
                if "entry" not in section:
                    errors.append("Missing required field 'section.entry'")
                if "sections" not in section:
                    errors.append("Missing required field 'section.sections'")
                elif not isinstance(section["sections"], list):
                    errors.append("Field 'section.sections' must be a list")
                else:
                    for i, s in enumerate(section["sections"]):
                        if not isinstance(s, dict):
                            errors.append(f"Section element {i} must be a dictionary")
                        else:
                            for num_f in ("size", "entropy", "vsize"):
                                if num_f in s:
                                    val = s[num_f]
                                    if isinstance(val, bool) or not isinstance(val, (int, float, np.number)):
                                        errors.append(f"Section {i} field '{num_f}' must be numeric, got {type(val).__name__}")
                                    elif not math.isfinite(val):
                                        errors.append(f"Section {i} field '{num_f}' has non-finite value: {val}")

        # 8. Imports validation
        imports = record.get("imports")
        if imports is not None:
            if not isinstance(imports, dict):
                errors.append("Field 'imports' must be a dictionary")
            else:
                for lib, funcs in imports.items():
                    if not isinstance(funcs, list):
                        errors.append(f"Imports for library '{lib}' must be a list of functions")

        # 9. Exports validation
        exports = record.get("exports")
        if exports is not None and not isinstance(exports, list):
            errors.append("Field 'exports' must be a list")

        # 10. Histogram validation
        histogram = record.get("histogram")
        if histogram is not None:
            if not isinstance(histogram, list):
                errors.append("Field 'histogram' must be a list")
            elif len(histogram) != 256:
                errors.append(f"Histogram dimension mismatch: expected 256 elements, got {len(histogram)}")
            else:
                for i, v in enumerate(histogram):
                    if isinstance(v, bool) or not isinstance(v, (int, float, np.number)):
                        errors.append(f"Histogram[{i}] must be numeric, got {type(v).__name__}")
                        break
                    elif not math.isfinite(v):
                        errors.append(f"Histogram[{i}] has non-finite value: {v}")
                        break
                    elif v < 0:
                        errors.append(f"Histogram[{i}] cannot be negative, got {v}")
                        break

        # 11. Byteentropy validation
        byteentropy = record.get("byteentropy")
        if byteentropy is not None:
            if not isinstance(byteentropy, list):
                errors.append("Field 'byteentropy' must be a list")
            elif len(byteentropy) != 256:
                errors.append(f"Byteentropy dimension mismatch: expected 256 elements, got {len(byteentropy)}")
            else:
                for i, v in enumerate(byteentropy):
                    if isinstance(v, bool) or not isinstance(v, (int, float, np.number)):
                        errors.append(f"Byteentropy[{i}] must be numeric, got {type(v).__name__}")
                        break
                    elif not math.isfinite(v):
                        errors.append(f"Byteentropy[{i}] has non-finite value: {v}")
                        break
                    elif v < 0:
                        errors.append(f"Byteentropy[{i}] cannot be negative, got {v}")
                        break

        # 12. Strings validation
        strings = record.get("strings")
        if strings is not None:
            if not isinstance(strings, dict):
                errors.append("Field 'strings' must be a dictionary")
            else:
                for sf in sorted(REQUIRED_STRINGS_FIELDS):
                    if sf not in strings:
                        errors.append(f"Missing required field 'strings.{sf}'")
                    elif sf == "printabledist":
                        pdist = strings["printabledist"]
                        if not isinstance(pdist, list):
                            errors.append("Field 'strings.printabledist' must be a list")
                        elif len(pdist) != 96:
                            errors.append(f"printabledist dimension mismatch: expected 96 elements, got {len(pdist)}")
                        else:
                            for idx, pv in enumerate(pdist):
                                if isinstance(pv, bool) or not isinstance(pv, (int, float, np.number)):
                                    errors.append(f"printabledist[{idx}] must be numeric, got {type(pv).__name__}")
                                    break
                                elif not math.isfinite(pv):
                                    errors.append(f"printabledist[{idx}] has non-finite value: {pv}")
                                    break
                                elif pv < 0:
                                    errors.append(f"printabledist[{idx}] cannot be negative, got {pv}")
                                    break
                    else:
                        sv = strings[sf]
                        if isinstance(sv, bool) or not isinstance(sv, (int, float, np.number)):
                            errors.append(f"Field 'strings.{sf}' must be numeric, got {type(sv).__name__}")
                        elif not math.isfinite(sv):
                            errors.append(f"Field 'strings.{sf}' has non-finite value: {sv}")

        # 13. DataDirectories validation (if present)
        datadirectories = record.get("datadirectories")
        if datadirectories is not None:
            if not isinstance(datadirectories, list):
                errors.append("Field 'datadirectories' must be a list")
            elif datadirectories and isinstance(datadirectories[0], (int, float, np.number)):
                if len(datadirectories) != 30:
                    errors.append(f"DataDirectories numeric list mismatch: expected 30 elements, got {len(datadirectories)}")
                for idx, dv in enumerate(datadirectories):
                    if isinstance(dv, bool) or not isinstance(dv, (int, float, np.number)):
                        errors.append(f"datadirectories[{idx}] must be numeric, got {type(dv).__name__}")
                        break
                    elif not math.isfinite(dv):
                        errors.append(f"datadirectories[{idx}] has non-finite value: {dv}")
                        break

        return errors

    # ==================== Feature Group Extraction ====================

    def _process_histogram(self, raw_hist: list) -> np.ndarray:
        """Extract and normalize 256-dim byte histogram."""
        arr = np.asarray(raw_hist, dtype=np.float32)
        if arr.shape != (256,):
            raise EmberAdapterError(f"Histogram dimension mismatch: expected (256,), got {arr.shape}")
        if not np.all(np.isfinite(arr)):
            raise EmberAdapterError("Histogram contains non-finite values (NaN or Inf)")
        total = arr.sum()
        if total > 0:
            arr = arr / total
        else:
            arr = np.zeros(256, dtype=np.float32)
        return arr.astype(np.float32)

    def _process_byteentropy(self, raw_be: list) -> np.ndarray:
        """Extract and normalize 256-dim 16x16 byte-entropy histogram."""
        arr = np.asarray(raw_be, dtype=np.float32)
        if arr.shape != (256,):
            raise EmberAdapterError(f"Byteentropy dimension mismatch: expected (256,), got {arr.shape}")
        if not np.all(np.isfinite(arr)):
            raise EmberAdapterError("Byteentropy contains non-finite values (NaN or Inf)")
        total = arr.sum()
        if total > 0:
            arr = arr / total
        else:
            arr = np.zeros(256, dtype=np.float32)
        return arr.astype(np.float32)

    def _process_strings(self, raw_strings: dict) -> np.ndarray:
        """Extract 104-dim string statistics and printable distribution."""
        for req in REQUIRED_STRINGS_FIELDS:
            if req not in raw_strings:
                raise EmberAdapterError(f"Missing required strings field: '{req}'")

        pdist = np.asarray(raw_strings["printabledist"], dtype=np.float32)
        if pdist.shape != (96,):
            raise EmberAdapterError(f"Strings printabledist dimension mismatch: expected (96,), got {pdist.shape}")
        if not np.all(np.isfinite(pdist)):
            raise EmberAdapterError("Strings printabledist contains non-finite values")

        csum = pdist.sum()
        if csum > 0:
            printable_dist = (pdist / csum).astype(np.float32)
        else:
            printable_dist = np.zeros(96, dtype=np.float32)

        scalars = [
            float(raw_strings["numstrings"]),
            float(raw_strings["avlength"]),
            float(raw_strings["printables"]),
            float(raw_strings["entropy"]),
            float(raw_strings["paths"]),
            float(raw_strings["urls"]),
            float(raw_strings["registry"]),
            float(raw_strings["MZ"]),
        ]
        for v in scalars:
            if not math.isfinite(v):
                raise EmberAdapterError(f"Strings contains non-finite scalar: {v}")

        return np.hstack([
            np.float32(scalars[0]),  # numstrings
            np.float32(scalars[1]),  # avlength
            np.float32(scalars[2]),  # printables
            printable_dist,          # 96 dims
            np.float32(scalars[3]),  # entropy
            np.float32(scalars[4]),  # paths
            np.float32(scalars[5]),  # urls
            np.float32(scalars[6]),  # registry
            np.float32(scalars[7]),  # MZ
        ]).astype(np.float32)

    def _process_general(self, raw_general: dict) -> np.ndarray:
        """Extract 10-dim general file metadata."""
        size_val = raw_general.get("file_size", raw_general.get("size", 0))
        fields = [
            float(size_val),
            float(raw_general.get("vsize", 0)),
            float(raw_general.get("has_debug", 0)),
            float(raw_general.get("exports", 0)),
            float(raw_general.get("imports", 0)),
            float(raw_general.get("has_relocations", 0)),
            float(raw_general.get("has_resources", 0)),
            float(raw_general.get("has_signature", raw_general.get("has_signatures", 0))),
            float(raw_general.get("has_tls", 0)),
            float(raw_general.get("symbols", 0)),
        ]
        for idx, f in enumerate(fields):
            if not math.isfinite(f):
                raise EmberAdapterError(f"General field index {idx} has non-finite value: {f}")
        return np.array(fields, dtype=np.float32)

    def _process_header(self, raw_header: dict) -> np.ndarray:
        """Extract 62-dim COFF and Optional header features via hashing."""
        coff = raw_header.get("coff", {})
        opt = raw_header.get("optional", {})

        coff_timestamp = float(coff.get("timestamp", 0))
        if not math.isfinite(coff_timestamp):
            raise EmberAdapterError(f"COFF timestamp has non-finite value: {coff_timestamp}")

        coff_machine = str(coff.get("machine", "")).split('.')[-1]
        coff_chars = [str(c).split('.')[-1] for c in coff.get("characteristics", [])]

        opt_subsystem = str(opt.get("subsystem", "")).split('.')[-1]
        opt_dll_chars = [str(c).split('.')[-1] for c in opt.get("dll_characteristics", [])]
        opt_magic = str(opt.get("magic", "")).split('.')[-1]

        # Categorical hashing (10 dims each = 50 dims total)
        machine_hashed = self._hashers["coff_machine"].transform([[coff_machine]]).toarray()[0]
        chars_hashed = self._hashers["coff_characteristics"].transform([coff_chars]).toarray()[0]
        subsystem_hashed = self._hashers["optional_subsystem"].transform([[opt_subsystem]]).toarray()[0]
        dll_chars_hashed = self._hashers["optional_dll_characteristics"].transform([opt_dll_chars]).toarray()[0]
        magic_hashed = self._hashers["optional_magic"].transform([[opt_magic]]).toarray()[0]

        numeric_opt = [
            float(opt.get("major_image_version", 0)),
            float(opt.get("minor_image_version", 0)),
            float(opt.get("major_linker_version", 0)),
            float(opt.get("minor_linker_version", 0)),
            float(opt.get("major_operating_system_version", 0)),
            float(opt.get("minor_operating_system_version", 0)),
            float(opt.get("major_subsystem_version", 0)),
            float(opt.get("minor_subsystem_version", 0)),
            float(opt.get("sizeof_code", 0)),
            float(opt.get("sizeof_headers", 0)),
            float(opt.get("sizeof_heap_commit", 0)),
        ]
        for idx, nf in enumerate(numeric_opt):
            if not math.isfinite(nf):
                raise EmberAdapterError(f"Optional header numeric field {idx} has non-finite value: {nf}")

        return np.hstack([
            coff_timestamp,
            machine_hashed,
            chars_hashed,
            subsystem_hashed,
            dll_chars_hashed,
            magic_hashed,
            numeric_opt,
        ]).astype(np.float32)

    def _process_section(self, raw_section: dict) -> np.ndarray:
        """Extract 255-dim section statistics and hashed properties."""
        entry = str(raw_section.get("entry", ""))
        sections = raw_section.get("sections", [])
        if not isinstance(sections, list):
            sections = []

        general_sec = np.array([
            len(sections),
            sum(1 for s in sections if s.get('size', 0) == 0),
            sum(1 for s in sections if s.get('name', '') == ""),
            sum(1 for s in sections if 'MEM_READ' in s.get('props', []) and 'MEM_EXECUTE' in s.get('props', [])),
            sum(1 for s in sections if 'MEM_WRITE' in s.get('props', [])),
        ], dtype=np.float32)

        section_sizes = []
        section_entropy = []
        section_vsize = []
        for s in sections:
            s_name = str(s.get('name', ''))
            s_size = float(s.get('size', 0))
            s_ent = float(s.get('entropy', 0.0))
            s_vsz = float(s.get('vsize', 0))
            if not (math.isfinite(s_size) and math.isfinite(s_ent) and math.isfinite(s_vsz)):
                raise EmberAdapterError(f"Section '{s_name}' contains non-finite properties")
            section_sizes.append((s_name, s_size))
            section_entropy.append((s_name, s_ent))
            section_vsize.append((s_name, s_vsz))

        sizes_hashed = self._hashers["section_sizes"].transform([section_sizes]).toarray()[0]
        entropy_hashed = self._hashers["section_entropy"].transform([section_entropy]).toarray()[0]
        vsize_hashed = self._hashers["section_vsize"].transform([section_vsize]).toarray()[0]
        entry_hashed = self._hashers["entry_name"].transform([[entry]]).toarray()[0]

        entry_props = []
        for s in sections:
            if s.get('name') == entry:
                entry_props = [str(p).split('.')[-1] for p in s.get('props', [])]
                break
        chars_hashed = self._hashers["characteristics"].transform([entry_props]).toarray()[0]

        return np.hstack([
            general_sec,
            sizes_hashed,
            entropy_hashed,
            vsize_hashed,
            entry_hashed,
            chars_hashed,
        ]).astype(np.float32)

    def _process_imports(self, raw_imports: dict) -> np.ndarray:
        """Extract 1,280-dim hashed imported libraries and functions."""
        if not isinstance(raw_imports, dict):
            raise EmberAdapterError("Field 'imports' must be a dictionary")

        libraries = list(set([str(l).lower() for l in raw_imports.keys()]))
        import_pairs = [
            str(lib).lower() + ':' + str(e)[:10000]
            for lib, elist in raw_imports.items()
            for e in elist
        ]

        lib_hashed = self._hashers["libraries"].transform([libraries]).toarray()[0]
        imports_hashed = self._hashers["imports"].transform([import_pairs]).toarray()[0]

        return np.hstack([lib_hashed, imports_hashed]).astype(np.float32)

    def _process_exports(self, raw_exports: list) -> np.ndarray:
        """Extract 128-dim hashed export symbols."""
        if not isinstance(raw_exports, list):
            raise EmberAdapterError("Field 'exports' must be a list")

        exports = [str(exp)[:10000] for exp in raw_exports]
        exports_hashed = self._hashers["exports"].transform([exports]).toarray()[0]
        return exports_hashed.astype(np.float32)

    def _process_datadirectories(self, raw_dd: Any) -> np.ndarray:
        """Extract 30-dim DataDirectories (size + RVA for first 15 directories)."""
        if raw_dd is None or (isinstance(raw_dd, list) and len(raw_dd) == 0):
            return np.zeros(30, dtype=np.float32)

        if isinstance(raw_dd, list):
            if raw_dd and isinstance(raw_dd[0], (int, float, np.number)):
                if len(raw_dd) != 30:
                    raise EmberAdapterError(f"DataDirectories numeric list mismatch: expected 30, got {len(raw_dd)}")
                arr = np.asarray(raw_dd, dtype=np.float32)
                if not np.all(np.isfinite(arr)):
                    raise EmberAdapterError("DataDirectories contains non-finite values")
                return arr

            dd_arr = np.zeros(30, dtype=np.float32)
            for i, d in enumerate(raw_dd[:15]):
                if isinstance(d, dict):
                    sz = float(d.get("size", 0.0))
                    rva = float(d.get("virtual_address", d.get("rva", 0.0)))
                    if not (math.isfinite(sz) and math.isfinite(rva)):
                        raise EmberAdapterError("DataDirectories contains non-finite entries")
                    dd_arr[2 * i] = sz
                    dd_arr[2 * i + 1] = rva
            return dd_arr

        return np.zeros(30, dtype=np.float32)

    # ==================== Public Interface ====================

    def parse_record(
        self,
        record: Dict[str, Any],
        split: Optional[str] = None
    ) -> Tuple[np.ndarray, int]:
        """
        Parse a single EMBER JSON record.

        Args:
            record: Dict representation of an EMBER JSONL record.
            split: Optional dataset split name ('train', 'test', etc.).

        Returns:
            Tuple of (feature_vector: np.ndarray[2381], label: int)
            where label is -1 (unlabeled), 0 (benign), or 1 (malicious).

        Raises:
            EmberAdapterError: If record fails validation, contains NaN/Inf, or has dimension mismatch.
        """
        vector, label, _ = self.parse_record_with_sha(record, split=split)
        return vector, label

    def parse_record_with_sha(
        self,
        record: Dict[str, Any],
        split: Optional[str] = None
    ) -> Tuple[np.ndarray, int, str]:
        """
        Parse a single EMBER JSON record and return vector, label, and SHA-256.

        Returns:
            Tuple of (feature_vector: np.ndarray[2381], label: int, sha256: str)
        """
        if self.strict:
            errors = self.validate_record(record, split=split)
            if errors:
                raise EmberAdapterError(f"Record validation failed: {'; '.join(errors)}")

        if not isinstance(record, dict):
            raise EmberAdapterError("Record must be a JSON dictionary")

        # Explicit label extraction & preservation
        raw_label = record.get("label")
        if raw_label is None:
            raise EmberAdapterError("Missing required field: 'label'")
        if isinstance(raw_label, bool) or not isinstance(raw_label, (int, np.integer)):
            raise EmberAdapterError(f"Field 'label' must be integer, got {type(raw_label).__name__}")
        label = int(raw_label)
        if label not in VALID_LABELS:
            raise EmberAdapterError(f"Invalid label value {label}; must be -1, 0, or 1")
        if split and "test" in split.lower() and label == LABEL_UNLABELED:
            raise EmberAdapterError("Unlabeled sample (label=-1) found in test split")

        sha256 = str(record.get("sha256", ""))

        # Transform each feature group in strict contract order
        vec_parts = [
            self._process_histogram(record["histogram"]),
            self._process_byteentropy(record["byteentropy"]),
            self._process_strings(record["strings"]),
            self._process_general(record["general"]),
            self._process_header(record["header"]),
            self._process_section(record["section"]),
            self._process_imports(record["imports"]),
            self._process_exports(record["exports"]),
            self._process_datadirectories(record.get("datadirectories")),
        ]

        feature_vector = np.hstack(vec_parts).astype(np.float32)

        # Validate total dimensions and finiteness
        if feature_vector.shape != (EMBER_TOTAL_DIM,):
            raise EmberAdapterError(
                f"Feature vector dimension mismatch: expected {EMBER_TOTAL_DIM}, got {feature_vector.shape}"
            )
        if not np.all(np.isfinite(feature_vector)):
            raise EmberAdapterError("Feature vector contains non-finite values (NaN or Inf)")

        return feature_vector, label, sha256

    def parse_jsonl(
        self,
        file_path: Union[str, Path],
        split: Optional[str] = None,
        max_records: Optional[int] = None,
    ) -> Iterator[Tuple[np.ndarray, int, str]]:
        """
        Stream-parse a JSONL file with bounded memory.

        Yields:
            Tuple of (feature_vector: np.ndarray[2381], label: int, sha256: str)
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"JSONL file not found: {path}")

        records_count = 0
        with open(path, "r", encoding="utf-8") as f:
            for line_idx, line in enumerate(f, start=1):
                stripped = line.strip()
                if not stripped:
                    continue  # Skip empty lines

                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError as e:
                    raise EmberAdapterError(f"Malformed JSON on line {line_idx} in {path}: {e}") from e

                vector, label, sha = self.parse_record_with_sha(record, split=split)
                yield vector, label, sha

                records_count += 1
                if max_records is not None and records_count >= max_records:
                    break

    def parse_jsonl_batches(
        self,
        file_path: Union[str, Path],
        batch_size: int = 1000,
        split: Optional[str] = None,
        max_records: Optional[int] = None,
    ) -> Iterator[Tuple[np.ndarray, np.ndarray, List[str]]]:
        """
        Stream-parse a JSONL file in bounded batches for streaming ML training.

        Yields:
            Tuple of (X_batch: np.ndarray[B, 2381], y_batch: np.ndarray[B], sha256_batch: List[str])
        """
        if batch_size <= 0:
            raise ValueError(f"batch_size must be positive, got {batch_size}")

        current_vectors: List[np.ndarray] = []
        current_labels: List[int] = []
        current_shas: List[str] = []

        for vector, label, sha in self.parse_jsonl(file_path, split=split, max_records=max_records):
            current_vectors.append(vector)
            current_labels.append(label)
            current_shas.append(sha)

            if len(current_vectors) >= batch_size:
                X_batch = np.vstack(current_vectors).astype(np.float32)
                y_batch = np.array(current_labels, dtype=np.int32)
                yield X_batch, y_batch, list(current_shas)
                current_vectors.clear()
                current_labels.clear()
                current_shas.clear()

        if current_vectors:
            X_batch = np.vstack(current_vectors).astype(np.float32)
            y_batch = np.array(current_labels, dtype=np.int32)
            yield X_batch, y_batch, list(current_shas)


# Convenience functions
def parse_ember_record(
    record: Dict[str, Any],
    split: Optional[str] = None,
    strict: bool = True
) -> Tuple[np.ndarray, int]:
    """Parse a single EMBER JSON record into (feature_vector, label)."""
    adapter = EmberDatasetAdapter(strict=strict)
    return adapter.parse_record(record, split=split)


def validate_ember_record(
    record: Dict[str, Any],
    split: Optional[str] = None
) -> List[str]:
    """Validate a single EMBER JSON record schema; returns list of errors."""
    adapter = EmberDatasetAdapter(strict=False)
    return adapter.validate_record(record, split=split)
