#!/usr/bin/env python3
"""
EMBER 2018 Dataset Schema Validator

Validates EMBER 2018 dataset (train_features.jsonl, test_features.jsonl, metadata.jsonl)
against the documented schema in docs/data/DATASET_SCHEMA.md.

Usage:
    python scripts/validate_dataset_schema.py --data-dir /path/to/ember2018
    python scripts/validate_dataset_schema.py --data-dir /path/to/ember2018 --split train
    python scripts/validate_dataset_schema.py --data-dir /path/to/ember2018 --strict
    python scripts/validate_dataset_schema.py --data-dir /path/to/ember2018 --max-records 1000
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class ValidationResult:
    severity: Severity
    message: str
    file_path: str
    line_number: int
    record_sha256: Optional[str] = None
    field_path: Optional[str] = None


@dataclass
class ValidationSummary:
    total_records: int = 0
    valid_records: int = 0
    errors: int = 0
    warnings: int = 0
    results: List[ValidationResult] = field(default_factory=list)
    sha256_seen: Set[str] = field(default_factory=set)
    duplicate_sha256: Set[str] = field(default_factory=set)
    sha256_labels: Dict[str, Set[int]] = field(default_factory=dict)  # sha256 -> set of labels seen
    sha256_labels: Dict[str, Set[int]] = field(default_factory=dict)  # sha256 -> set of labels seen


class EmberSchemaValidator:
    """Validates EMBER 2018 dataset records against the documented schema."""

    REQUIRED_TOP_LEVEL_FIELDS = {
        "sha256", "appeared", "label", "general", "header",
        "imports", "exports", "section", "histogram", "byteentropy", "strings"
    }

    VALID_LABELS = {-1, 0, 1}
    REQUIRED_GENERAL_FIELDS = {
        "file_size", "vsize", "has_debug", "exports", "imports",
        "has_relocations", "has_resources", "has_signature", "has_tls", "symbols"
    }
    REQUIRED_COFF_FIELDS = {"timestamp", "machine", "characteristics"}
    REQUIRED_OPTIONAL_FIELDS = {
        "subsystem", "dll_characteristics", "magic",
        "major_image_version", "minor_image_version",
        "major_linker_version", "minor_linker_version",
        "major_operating_system_version", "minor_operating_system_version",
        "major_subsystem_version", "minor_subsystem_version",
        "sizeof_code", "sizeof_headers", "sizeof_heap_commit"
    }
    REQUIRED_SECTION_FIELDS = {"entry", "sections"}

    def __init__(self, strict: bool = False):
        self.strict = strict
        self.summary = ValidationSummary()

    def validate_file(self, file_path: Path, split_name: str) -> ValidationSummary:
        """Validate a single JSONL file."""
        self.summary = ValidationSummary()
        line_number = 0

        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line_number += 1
                line = line.strip()
                if not line:
                    continue

                self.summary.total_records += 1

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as e:
                    self._add_result(ValidationResult(
                        severity=Severity.ERROR,
                        message=f"Invalid JSON: {e}",
                        file_path=str(file_path),
                        line_number=line_number
                    ))
                    continue

                self._validate_record(record, file_path, line_number, split_name)

        return self.summary

    def _validate_record(self, record: Dict, file_path: Path, line_number: int, split_name: str):
        sha256 = record.get("sha256")

        # Track SHA-256 for duplicate detection and conflict detection
        if sha256:
            if sha256 in self.summary.sha256_seen:
                self.summary.duplicate_sha256.add(sha256)
                self._add_result(ValidationResult(
                    severity=Severity.ERROR,
                    message=f"Duplicate SHA-256: {sha256}",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path="sha256"
                ))
            else:
                self.summary.sha256_seen.add(sha256)

            # Track labels per SHA-256 for conflict detection
            label = record.get("label")
            if label is not None:
                if sha256 not in self.summary.sha256_labels:
                    self.summary.sha256_labels[sha256] = set()
                self.summary.sha256_labels[sha256].add(label)
                # Check for conflicting labels (same SHA-256, different labels)
                if len(self.summary.sha256_labels[sha256]) > 1:
                    self._add_result(ValidationResult(
                        severity=Severity.ERROR,
                        message=f"Conflicting labels for SHA-256 {sha256}: {sorted(self.summary.sha256_labels[sha256])}",
                        file_path=str(file_path),
                        line_number=line_number,
                        record_sha256=sha256,
                        field_path="label"
                    ))

        # 1. Required top-level fields
        missing_fields = self.REQUIRED_TOP_LEVEL_FIELDS - set(record.keys())
        for field in missing_fields:
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message=f"Missing required top-level field: {field}",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path=field
            ))

        # 2. SHA-256 format
        if sha256:
            if not isinstance(sha256, str) or len(sha256) != 64 or not all(c in "0123456789abcdefABCDEF" for c in sha256):
                self._add_result(ValidationResult(
                    severity=Severity.ERROR,
                    message=f"Invalid SHA-256 format: must be 64 hex characters",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path="sha256"
                ))

        # 3. Appeared format (YYYY-MM)
        appeared = record.get("appeared")
        if appeared:
            if not isinstance(appeared, str) or not self._validate_appeared_format(appeared):
                self._add_result(ValidationResult(
                    severity=Severity.ERROR,
                    message=f"Invalid appeared format (expected YYYY-MM): {appeared}",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path="appeared"
                ))

        # 3. Label validation
        label = record.get("label")
        if label is not None:
            if label not in self.VALID_LABELS:
                self._add_result(ValidationResult(
                    severity=Severity.ERROR,
                    message=f"Invalid label value: {label} (must be -1, 0, or 1)",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path="label"
                ))
            elif label == -1 and "test" in split_name.lower():
                self._add_result(ValidationResult(
                    severity=Severity.ERROR,
                    message=f"Unlabeled sample (label=-1) found in test split",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path="label"
                ))

        # 4. General file information
        self._validate_general(record.get("general", {}), file_path, line_number, sha256)

        # 5. Header information
        self._validate_header(record.get("header", {}), file_path, line_number, sha256)

        # 6. Section information
        self._validate_section(record.get("section", {}), file_path, line_number, sha256)

        # 6. Imports (must be dict)
        imports = record.get("imports")
        if imports is not None and not isinstance(imports, dict):
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message="Imports must be a dictionary",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="imports"
            ))

        # 7. Exports (must be list)
        exports = record.get("exports")
        if exports is not None and not isinstance(exports, list):
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message="Exports must be a list",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="exports"
            ))

        # 8. Histogram (256 integers)
        self._validate_histogram(record.get("histogram"), file_path, line_number, sha256)

        # 9. Byteentropy (256 integers = 16x16)
        self._validate_byteentropy(record.get("byteentropy"), file_path, line_number, sha256)

        # 10. Strings
        self._validate_strings(record.get("strings", {}), file_path, line_number, sha256)

        # If we got here without errors, count as valid
        if not any(r.severity == Severity.ERROR for r in self.summary.results if r.line_number == line_number):
            self.summary.valid_records += 1

    def _validate_appeared_format(self, appeared: str) -> bool:
        """Validate YYYY-MM format."""
        if not isinstance(appeared, str) or len(appeared) != 7:
            return False
        try:
            year = int(appeared[:4])
            month = int(appeared[5:7])
            return 2000 <= year <= 2100 and 1 <= month <= 12 and appeared[4] == '-'
        except (ValueError, IndexError):
            return False

    def _validate_general(self, general: Dict, file_path: Path, line_number: int, sha256: Optional[str]):
        if not isinstance(general, dict):
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message="General must be a dictionary",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="general"
            ))
            return

        missing = self.REQUIRED_GENERAL_FIELDS - set(general.keys())
        for field in missing:
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message=f"Missing required general field: {field}",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path=f"general.{field}"
            ))

        # file_size >= 64 (minimum PE size)
        file_size = general.get("file_size")
        if file_size is not None:
            if not isinstance(file_size, int) or file_size < 64:
                self._add_result(ValidationResult(
                    severity=Severity.ERROR,
                    message=f"file_size must be integer >= 64, got {file_size}",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path="general.file_size"
                ))

        # Boolean-like fields (0/1)
        for field in ["has_debug", "has_relocations", "has_resources", "has_signature", "has_tls"]:
            val = general.get(field)
            if val is not None and val not in (0, 1):
                self._add_result(ValidationResult(
                    severity=Severity.WARNING,
                    message=f"general.{field} should be 0 or 1, got {val}",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path=f"general.{field}"
                ))

    def _validate_header(self, header: Dict, file_path: Path, line_number: int, sha256: Optional[str]):
        if not isinstance(header, dict):
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message="Header must be a dictionary",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="header"
            ))
            return

        # COFF header
        coff = header.get("coff", {})
        if isinstance(coff, dict):
            missing = self.REQUIRED_COFF_FIELDS - set(coff.keys())
            for field in missing:
                self._add_result(ValidationResult(
                    severity=Severity.WARNING,
                    message=f"Missing COFF field: {field}",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path=f"header.coff.{field}"
                ))
            if "characteristics" in coff and not isinstance(coff["characteristics"], list):
                self._add_result(ValidationResult(
                    severity=Severity.WARNING,
                    message="COFF characteristics must be a list",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path="header.coff.characteristics"
                ))

        # Optional header
        optional = header.get("optional", {})
        if isinstance(optional, dict):
            missing = self.REQUIRED_OPTIONAL_FIELDS - set(optional.keys())
            for field in missing:
                self._add_result(ValidationResult(
                    severity=Severity.WARNING,
                    message=f"Missing optional header field: {field}",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path=f"header.optional.{field}"
                ))
            if "dll_characteristics" in optional and not isinstance(optional["dll_characteristics"], list):
                self._add_result(ValidationResult(
                    severity=Severity.WARNING,
                    message="DLL characteristics must be a list",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path="header.optional.dll_characteristics"
                ))

    def _validate_section(self, section: Dict, file_path: Path, line_number: int, sha256: Optional[str]):
        if not isinstance(section, dict):
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message="Section must be a dictionary",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="section"
            ))
            return

        missing = self.REQUIRED_SECTION_FIELDS - set(section.keys())
        for field in missing:
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message=f"Missing required section field: {field}",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path=f"section.{field}"
            ))

        # Validate sections array
        sections = section.get("sections", [])
        if not isinstance(sections, list):
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message="Section.sections must be a list",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="section.sections"
            ))
        else:
            for i, sec in enumerate(sections):
                if not isinstance(sec, dict):
                    self._add_result(ValidationResult(
                        severity=Severity.ERROR,
                        message=f"Section[{i}] must be a dictionary",
                        file_path=str(file_path),
                        line_number=line_number,
                        record_sha256=sha256,
                        field_path=f"section.sections[{i}]"
                    ))
                else:
                    required_sec_fields = {"name", "size", "entropy", "vsize", "props"}
                    missing = required_sec_fields - set(sec.keys())
                    for field in missing:
                        self._add_result(ValidationResult(
                            severity=Severity.WARNING,
                            message=f"Section[{i}] missing field: {field}",
                            file_path=str(file_path),
                            line_number=line_number,
                            record_sha256=sha256,
                            field_path=f"section.sections[{i}].{field}"
                        ))
                    if "props" in sec and not isinstance(sec["props"], list):
                        self._add_result(ValidationResult(
                            severity=Severity.WARNING,
                            message=f"Section[{i}].props must be a list",
                            file_path=str(file_path),
                            line_number=line_number,
                            record_sha256=sha256,
                            field_path=f"section.sections[{i}].props"
                        ))

    def _validate_histogram(self, histogram: Any, file_path: Path, line_number: int, sha256: Optional[str]):
        if histogram is None:
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message="Missing histogram field",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="histogram"
            ))
            return

        if not isinstance(histogram, list):
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message="Histogram must be a list",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="histogram"
            ))
            return

        if len(histogram) != 256:
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message=f"Histogram must have exactly 256 elements, got {len(histogram)}",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="histogram"
            ))
            return

        if sum(histogram) == 0:
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message="Histogram sum is zero (empty file?)",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="histogram"
            ))

        for i, val in enumerate(histogram):
            if not isinstance(val, int) or val < 0:
                self._add_result(ValidationResult(
                    severity=Severity.ERROR,
                    message=f"Histogram[{i}] must be non-negative integer, got {val}",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path=f"histogram[{i}]"
                ))

    def _validate_byteentropy(self, byteentropy: Any, file_path: Path, line_number: int, sha256: Optional[str]):
        if byteentropy is None:
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message="Missing byteentropy field",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="byteentropy"
            ))
            return

        if not isinstance(byteentropy, list):
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message="Byteentropy must be a list",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="byteentropy"
            ))
            return

        if len(byteentropy) != 256:
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message=f"Byteentropy must have exactly 256 elements (16x16), got {len(byteentropy)}",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="byteentropy"
            ))
            return

        for i, val in enumerate(byteentropy):
            if not isinstance(val, int) or val < 0:
                self._add_result(ValidationResult(
                    severity=Severity.ERROR,
                    message=f"Byteentropy[{i}] must be non-negative integer, got {val}",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path=f"byteentropy[{i}]"
                ))

    def _validate_strings(self, strings: Dict, file_path: Path, line_number: int, sha256: Optional[str]):
        if not isinstance(strings, dict):
            self._add_result(ValidationResult(
                severity=Severity.ERROR,
                message="Strings must be a dictionary",
                file_path=str(file_path),
                line_number=line_number,
                record_sha256=sha256,
                field_path="strings"
            ))
            return

        # numstrings >= 0
        numstrings = strings.get("numstrings")
        if numstrings is not None:
            if not isinstance(numstrings, int) or numstrings < 0:
                self._add_result(ValidationResult(
                    severity=Severity.ERROR,
                    message=f"numstrings must be non-negative integer, got {numstrings}",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path="strings.numstrings"
                ))

        # printabledist length should be 96 (0x20-0x7F)
        printabledist = strings.get("printabledist")
        if printabledist is not None:
            if not isinstance(printabledist, list):
                self._add_result(ValidationResult(
                    severity=Severity.WARNING,
                    message="printabledist must be a list",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path="strings.printabledist"
                ))
            elif len(printabledist) != 96:
                self._add_result(ValidationResult(
                    severity=Severity.WARNING,
                    message=f"printabledist should have 96 elements (ASCII 0x20-0x7F), got {len(printabledist)}",
                    file_path=str(file_path),
                    line_number=line_number,
                    record_sha256=sha256,
                    field_path="strings.printabledist"
                ))

    def _add_result(self, result: ValidationResult):
        self.summary.results.append(result)
        if result.severity == Severity.ERROR:
            self.summary.errors += 1
        elif result.severity == Severity.WARNING:
            self.summary.warnings += 1

    def print_summary(self, split_name: str):
        print(f"\n{'='*60}")
        print(f"VALIDATION SUMMARY: {split_name.upper()} SPLIT")
        print(f"{'='*60}")
        print(f"Total records:      {self.summary.total_records}")
        print(f"Valid records:      {self.summary.valid_records}")
        print(f"Errors:             {self.summary.errors}")
        print(f"Warnings:           {self.summary.warnings}")
        print(f"Unique SHA-256:     {len(self.summary.sha256_seen)}")
        print(f"Duplicate SHA-256:  {len(self.summary.duplicate_sha256)}")

        if self.summary.duplicate_sha256:
            print(f"\nDuplicate SHA-256 hashes ({len(self.summary.duplicate_sha256)}):")
            for sha in sorted(self.summary.duplicate_sha256)[:10]:
                print(f"  {sha}")
            if len(self.summary.duplicate_sha256) > 10:
                print(f"  ... and {len(self.summary.duplicate_sha256) - 10} more")

        if self.summary.errors > 0:
            print(f"\nFirst 10 errors:")
            for r in [r for r in self.summary.results if r.severity == Severity.ERROR][:10]:
                loc = f"{r.file_path}:{r.line_number}" if r.line_number else r.file_path
                print(f"  [{r.severity.value}] {loc}: {r.message}")
                if r.record_sha256:
                    print(f"    SHA-256: {r.record_sha256}")
                if r.field_path:
                    print(f"    Field: {r.field_path}")

    def has_errors(self) -> bool:
        return self.summary.errors > 0


def main():
    parser = argparse.ArgumentParser(description="Validate EMBER 2018 dataset schema")
    parser.add_argument("--data-dir", required=True, help="Path to ember2018 directory")
    parser.add_argument("--split", choices=["train", "test", "both"], default="both", help="Which split to validate")
    parser.add_argument("--strict", action="store_true", help="Treat errors as fatal (exit non-zero on any ERROR); warnings are always reported")
    parser.add_argument("--max-records", type=int, help="Maximum records to validate (for quick testing); applies per-split within the shared validator run")

    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"ERROR: Data directory not found: {data_dir}")
        sys.exit(1)

    # Single validator instance across all splits — enables cross-split dedup + conflict detection
    validator = EmberSchemaValidator(strict=args.strict)

    # Global SHA-256 tracking: detect duplicates and conflicting labels across splits
    global_sha256: Dict[str, Dict[str, Any]] = {}  # sha256 -> {"labels": set, "splits": set}

    splits = []
    if args.split in ("train", "both"):
        splits.append(("train", "train_features.jsonl"))
    if args.split in ("test", "both"):
        splits.append(("test", "test_features.jsonl"))

    overall_errors = 0
    overall_warnings = 0
    overall_total = 0
    overall_valid = 0

    for split_name, filename in splits:
        file_path = data_dir / filename
        if not file_path.exists():
            print(f"ERROR: File not found: {file_path}")
            sys.exit(1)

        print(f"\nValidating {split_name} split: {file_path}")

        split_errors = 0
        split_warnings = 0
        split_total = 0
        split_valid = 0

        with open(file_path, 'r', encoding='utf-8') as f:
            for line_number, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                split_total += 1

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as e:
                    validator._add_result(ValidationResult(
                        severity=Severity.ERROR,
                        message=f"Invalid JSON: {e}",
                        file_path=str(file_path),
                        line_number=line_number
                    ))
                    split_errors += 1
                    continue

                # --- Global SHA-256 duplicate & conflict detection ---
                sha256 = record.get("sha256")
                if sha256:
                    if sha256 in global_sha256:
                        # Within-split duplicate
                        validator.duplicate_sha256.add(sha256)
                        validator._add_result(ValidationResult(
                            severity=Severity.ERROR,
                            message=f"Duplicate SHA-256: {sha256}",
                            file_path=str(file_path),
                            line_number=line_number,
                            record_sha256=sha256,
                            field_path="sha256"
                        ))
                    else:
                        global_sha256[sha256] = {"labels": set(), "splits": set()}

                    # Track label and split for conflict detection
                    label = record.get("label")
                    if label is not None:
                        global_sha256[sha256]["labels"].add(label)
                        global_sha256[sha256]["splits"].add(split_name)

                    # Conflicting label detection: same sha256 with different labels
                    if len(global_sha256[sha256]["labels"]) > 1:
                        validator._add_result(ValidationResult(
                            severity=Severity.ERROR,
                            message=f"Conflicting labels for SHA-256 {sha256}: {sorted(global_sha256[sha256]['labels'])}",
                            file_path=str(file_path),
                            line_number=line_number,
                            record_sha256=sha256,
                            field_path="label"
                        ))

                # --- Per-record schema validation (existing logic) ---
                self._validate_record(record, file_path, line_number, split_name)

                # Count as valid only if no ERROR at this line number
                if not any(r.severity == Severity.ERROR for r in validator.summary.results if r.line_number == line_number):
                    split_valid += 1

        # After processing the file, report per-split summary
        validator.print_summary(filename)

        # Accumulate totals
        overall_errors += validator.summary.errors
        overall_warnings += validator.summary.warnings
        overall_total += validator.summary.total_records
        overall_valid += validator.summary.valid_records

        if args.strict and validator.has_errors():
            print(f"  FAILED: {validator.summary.errors} errors found (strict mode on)")

    # Cross-split duplicate & conflict summary
    print(f"\n{'='*60}")
    print("CROSS-SPLIT DUPLICATE & CONFLICT SUMMARY")
    print(f"{'='*60}")
    dup_count = len(validator.duplicate_sha256)
    conflict_count = sum(
        1 for sha, info in global_sha256.items()
        if len(info["labels"]) > 1
    )
    print(f"Duplicate SHA-256 across splits: {dup_count}")
    print(f"SHA-256 with conflicting labels: {conflict_count}")
    if dup_count:
        print(f"  Duplicate hashes: {sorted(validator.duplicate_sha256)[:10]}")
        if len(validator.duplicate_sha256) > 10:
            print(f"  ... and {len(validator.duplicate_sha256) - 10} more")
    if conflict_count:
        for sha in sorted(global_sha256.keys()):
            if len(global_sha256[sha]["labels"]) > 1:
                print(f"  Conflicting: {sha} -> labels {global_sha256[sha]['labels']} in splits {global_sha256[sha]['splits']}")
                break

    print(f"\n{'='*60}")
    print("OVERALL SUMMARY")
    print(f"{'='*60}")
    print(f"Total records:     {overall_total}")
    print(f"Valid records:     {overall_valid}")
    print(f"Total errors:      {overall_errors}")
    print(f"Total warnings:    {overall_warnings}")

    if overall_errors > 0:
        print(f"\nFirst 10 errors:")
        errs = [r for r in validator.summary.results if r.severity == Severity.ERROR][:10]
        for r in errs:
            loc = f"{r.file_path}:{r.line_number}" if r.line_number else r.file_path
            print(f"  [{r.severity.value}] {loc}: {r.message}")
            if r.record_sha256:
                print(f"    SHA-256: {r.record_sha256}")
            if r.field_path:
                print(f"    Field: {r.field_path}")

    if overall_errors > 0:
        print(f"\nFAILED: Errors found.")
        sys.exit(1)
    else:
        print("\nSUCCESS: All validations passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()