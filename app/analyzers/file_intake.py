"""
Module 01: Secure File Intake and Validation

Core Functional & Security Features:
1. File extension validation (strictly .exe and .dll).
2. Size validation (max 50MB, configurable).
3. File type validation (DOS 'MZ' magic bytes & PE signature offset verification).
4. Empty file detection (0-byte rejection).
5. Filename sanitization & path traversal prevention (../../, ..\\, absolute paths).
6. Null-byte injection rejection.
7. Unique internal filename generation in isolated quarantine storage.
8. Analysis ID generation (e.g. ANL-000001).
9. Cryptographic hash calculation (SHA-256, MD5, SHA-1).
10. Basic metadata collection.
"""

import struct
from enum import Enum
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Tuple, Union, Any
from dataclasses import dataclass, field

from app.core.config import settings
from app.core.logger import logger
from app.core.storage import FileRecord, analysis_store, AnalysisStore
from app.utils.sanitizer import sanitize_filename, generate_secure_storage_name
from app.utils.hashing import compute_hashes_from_bytes, compute_hashes_from_file


class IntakeStatus(str, Enum):
    """Enumeration of possible intake status codes."""
    READY = "READY"
    REJECTED_EMPTY = "REJECTED_EMPTY"
    REJECTED_OVERSIZED = "REJECTED_OVERSIZED"
    REJECTED_INVALID_EXTENSION = "REJECTED_INVALID_EXTENSION"
    REJECTED_INVALID_PE = "REJECTED_INVALID_PE"
    REJECTED_DANGEROUS_NAME = "REJECTED_DANGEROUS_NAME"
    ERROR = "ERROR"


@dataclass
class IntakeResult:
    """
    Structured outcome of the Secure File Intake process.
    """
    status: IntakeStatus
    message: str
    analysis_id: Optional[str] = None
    filename: str = ""
    original_filename: str = ""
    size: int = 0
    sha256: str = ""
    md5: str = ""
    sha1: str = ""
    secure_storage_path: Optional[Path] = None
    is_pe_candidate: bool = False
    validation_notes: List[str] = field(default_factory=list)

    @property
    def is_success(self) -> bool:
        """Returns True if the file was accepted and ready for downstream analysis."""
        return self.status == IntakeStatus.READY

    def to_api_response(self) -> Dict[str, Any]:
        """Converts result to the exact API response contract."""
        return {
            "analysis_id": self.analysis_id or "",
            "filename": self.filename,
            "size": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
            "status": self.status.value,
        }


class SecureFileIntake:
    """
    Secure File Intake and Validation Service.
    Enforces security perimeter checks before any static analysis begins.
    """

    # DOS Header Magic bytes: 'MZ' (0x4D, 0x5A)
    DOS_MZ_MAGIC: bytes = b"MZ"
    # PE Header Signature: 'PE\0\0'
    PE_SIGNATURE: bytes = b"PE\x00\x00"

    def __init__(
        self,
        max_file_size: Optional[int] = None,
        quarantine_dir: Optional[Path] = None,
        store: Optional[AnalysisStore] = None,
        enforce_pe_check: bool = True
    ):
        self.max_file_size = max_file_size or settings.MAX_FILE_SIZE_BYTES
        self.quarantine_dir = quarantine_dir or settings.QUARANTINE_DIR
        self.store = store or analysis_store
        self.enforce_pe_check = enforce_pe_check
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def validate_filename_security(self, raw_filename: str) -> Tuple[bool, str, str]:
        """
        Validates the filename against dangerous injection patterns and sanitizes it.

        Checks:
        - Null-byte injection (%00, \\x00)
        - Empty or whitespace-only names
        - Path traversal patterns (../../, ..\\..)
        - Supported extensions (.exe, .dll)

        Returns:
            Tuple of (is_valid: bool, sanitized_name: str, reason: str)
        """
        if not raw_filename or not isinstance(raw_filename, str):
            return False, "unnamed_sample.bin", "Filename cannot be empty."

        # 1. Reject explicit null-byte injections
        if "\x00" in raw_filename:
            return False, "unnamed_sample.bin", "Null-byte injection detected in filename."

        # 2. Extract base extension safely
        raw_clean = raw_filename.strip()
        lower_name = raw_clean.lower()

        # Check extension against allowed list (.exe, .dll)
        has_valid_ext = any(lower_name.endswith(ext) for ext in settings.ALLOWED_EXTENSIONS)
        if not has_valid_ext:
            allowed = ", ".join(sorted(settings.ALLOWED_EXTENSIONS))
            return False, sanitize_filename(raw_clean), f"Unsupported file extension. Allowed extensions are: {allowed}"

        # 3. Sanitize filename to prevent path traversal
        sanitized = sanitize_filename(raw_clean)

        return True, sanitized, "Filename validated successfully."

    def verify_pe_header(self, data: bytes) -> Tuple[bool, str]:
        """
        Performs static byte-level verification of Windows PE headers without execution.

        Checks:
        1. Minimum file length for DOS header (at least 64 bytes).
        2. 'MZ' signature at byte 0.
        3. e_lfanew pointer at offset 0x3C pointing to 'PE\\0\\0'.

        Returns:
            Tuple of (is_valid_pe: bool, reason: str)
        """
        if len(data) < 64:
            return False, f"File size ({len(data)} bytes) is smaller than the minimum DOS header (64 bytes)."

        # Check DOS MZ signature
        if data[:2] != self.DOS_MZ_MAGIC:
            return False, f"Missing DOS 'MZ' header signature (Found: {data[:2]!r})."

        # Read e_lfanew offset to the PE signature
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        except struct.error as err:
            return False, f"Failed to parse DOS header e_lfanew offset: {err}"

        # Ensure e_lfanew points to a valid offset within file boundaries
        if e_lfanew < 64 or e_lfanew + 4 > len(data):
            return False, f"Invalid PE signature offset (e_lfanew = {e_lfanew}) outside file boundaries."

        # Verify PE\0\0 signature
        pe_sig = data[e_lfanew : e_lfanew + 4]
        if pe_sig != self.PE_SIGNATURE:
            return False, f"Invalid PE signature at offset {hex(e_lfanew)} (Found: {pe_sig!r}, expected b'PE\\x00\\x00')."

        return True, "Valid DOS 'MZ' and PE header structure verified."

    def process_bytes(
        self,
        data: bytes,
        raw_filename: str = "sample.exe"
    ) -> IntakeResult:
        """
        Processes uploaded binary data through the complete intake and validation pipeline.

        Args:
            data: Raw file byte stream.
            raw_filename: Client-supplied untrusted filename.

        Returns:
            IntakeResult object with status, analysis_id, hashes, and storage details.
        """
        notes: List[str] = []

        # 1. Filename & Extension Validation
        valid_name, sanitized_name, name_reason = self.validate_filename_security(raw_filename)
        notes.append(name_reason)

        if not valid_name:
            if "Null-byte" in name_reason:
                status = IntakeStatus.REJECTED_DANGEROUS_NAME
            elif "Unsupported file extension" in name_reason:
                status = IntakeStatus.REJECTED_INVALID_EXTENSION
            else:
                status = IntakeStatus.REJECTED_DANGEROUS_NAME

            logger.warning(f"Intake rejected for '{raw_filename}': {name_reason}")
            return IntakeResult(
                status=status,
                message=name_reason,
                filename=sanitized_name,
                original_filename=raw_filename,
                size=len(data) if data else 0,
                validation_notes=notes
            )

        # 2. Validate Non-Empty
        if not data or len(data) == 0:
            logger.warning(f"Intake rejected: Empty payload received for '{sanitized_name}'.")
            return IntakeResult(
                status=IntakeStatus.REJECTED_EMPTY,
                message="Uploaded file is empty (0 bytes).",
                filename=sanitized_name,
                original_filename=raw_filename,
                size=0,
                validation_notes=["Empty payload rejected."]
            )

        file_size = len(data)

        # 3. Validate Size Bounds
        if file_size > self.max_file_size:
            max_mb = self.max_file_size // (1024 * 1024)
            msg = f"File size ({file_size} bytes) exceeds maximum limit of {max_mb} MB."
            logger.warning(f"Intake rejected: {msg}")
            return IntakeResult(
                status=IntakeStatus.REJECTED_OVERSIZED,
                message=msg,
                filename=sanitized_name,
                original_filename=raw_filename,
                size=file_size,
                validation_notes=[msg]
            )

        # 4. Static PE Header Validation
        is_pe, pe_reason = self.verify_pe_header(data)
        notes.append(pe_reason)

        if self.enforce_pe_check and not is_pe:
            logger.warning(f"Intake rejected: Non-PE structure in '{sanitized_name}' ({pe_reason}).")
            return IntakeResult(
                status=IntakeStatus.REJECTED_INVALID_PE,
                message=f"File is not a valid Windows PE binary: {pe_reason}",
                filename=sanitized_name,
                original_filename=raw_filename,
                size=file_size,
                is_pe_candidate=False,
                validation_notes=notes
            )

        # 5. Calculate Hashes
        hashes = compute_hashes_from_bytes(data)
        sha256_val = hashes["sha256"]
        md5_val = hashes["md5"]
        sha1_val = hashes["sha1"]
        notes.append(f"SHA-256: {sha256_val}")
        notes.append(f"MD5: {md5_val}")

        # 6. Generate Analysis ID
        analysis_id = self.store.generate_analysis_id()

        # 7. Quarantined Isolated Storage
        secure_name = generate_secure_storage_name(sanitized_name, sha256_hash=sha256_val)
        dest_path = self.quarantine_dir / secure_name

        try:
            with open(dest_path, "wb") as f:
                f.write(data)
            notes.append(f"Quarantined as: {secure_name}")
        except Exception as err:
            logger.error(f"Failed writing quarantine file: {err}")
            return IntakeResult(
                status=IntakeStatus.ERROR,
                message=f"Storage error while saving sample: {str(err)}",
                filename=sanitized_name,
                original_filename=raw_filename,
                size=file_size,
                validation_notes=notes
            )

        # 8. Create and Save Analysis Record
        ext = Path(sanitized_name).suffix.lower()
        file_type = "PE Executable (.exe)" if ext == ".exe" else "PE Dynamic Link Library (.dll)"

        record = FileRecord(
            analysis_id=analysis_id,
            filename=sanitized_name,
            original_filename=raw_filename,
            size=file_size,
            sha256=sha256_val,
            md5=md5_val,
            sha1=sha1_val,
            status=IntakeStatus.READY.value,
            uploaded_at=datetime.now(timezone.utc).isoformat(),
            file_type=file_type,
            quarantined_path=str(dest_path),
            metadata={
                "is_pe": is_pe,
                "sanitized_from": raw_filename,
                "quarantine_filename": secure_name,
            }
        )
        self.store.save_record(record)

        logger.info(f"Accepted sample: {sanitized_name} -> {analysis_id} (SHA-256: {sha256_val})")

        return IntakeResult(
            status=IntakeStatus.READY,
            message="File successfully validated and quarantined.",
            analysis_id=analysis_id,
            filename=sanitized_name,
            original_filename=raw_filename,
            size=file_size,
            sha256=sha256_val,
            md5=md5_val,
            sha1=sha1_val,
            secure_storage_path=dest_path,
            is_pe_candidate=is_pe,
            validation_notes=notes
        )


# Global default instance
secure_intake_service = SecureFileIntake()
