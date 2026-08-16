"""
Input and Filename Sanitization Utilities.

Protects against:
- Directory / Path Traversal attacks (e.g., ../../../evil.exe)
- Windows Reserved Device Filenames (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
- Null-byte and control character injections
- Filename length overflows
"""

import re
import uuid
from pathlib import Path
from typing import Tuple

# Windows reserved device names that cannot be used as filenames
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
}

# Regex to strip non-whitelisted characters from user-provided filename
# Allows letters, digits, underscores, dashes, and periods.
SAFE_CHAR_REGEX = re.compile(r"[^a-zA-Z0-9._-]")


def sanitize_filename(raw_filename: str, fallback_name: str = "unnamed_sample.bin") -> str:
    """
    Sanitizes an untrusted user-supplied filename into a safe, path-traversal-free string.

    Args:
        raw_filename: The raw filename string received from client upload.
        fallback_name: Default name used if raw_filename is empty or stripped away entirely.

    Returns:
        A sanitized, safe base filename string (never containing directory separators).
    """
    if not raw_filename or not isinstance(raw_filename, str):
        return fallback_name

    # 1. Strip null bytes and control characters
    cleaned = raw_filename.replace("\x00", "").strip()

    # 2. Extract only the base name (prevents ../, ..\, C:\, /etc/ traversal)
    base_name = Path(cleaned).name

    # 3. Replace any unapproved characters with underscores
    sanitized = SAFE_CHAR_REGEX.sub("_", base_name)

    # 4. Remove leading/trailing periods or spaces
    sanitized = sanitized.strip(". ")

    # 5. Check if the name matches a Windows reserved keyword
    stem = sanitized.split(".")[0].upper()
    if stem in WINDOWS_RESERVED_NAMES:
        sanitized = f"safe_{sanitized}"

    # 6. Fallback if the string became empty after filtering
    if not sanitized:
        sanitized = fallback_name

    # 7. Restrict maximum length to 100 characters to prevent buffer/path limits
    if len(sanitized) > 100:
        parts = sanitized.rsplit(".", 1)
        if len(parts) == 2:
            ext = "." + parts[1][:10]
            stem_allowed = 100 - len(ext)
            sanitized = parts[0][:stem_allowed] + ext
        else:
            sanitized = sanitized[:100]

    return sanitized


def generate_secure_storage_name(sanitized_filename: str, sha256_hash: str = "") -> str:
    """
    Generates an isolated, non-colliding internal storage filename.
    Never stores the file under its raw user-supplied name on disk.

    Args:
        sanitized_filename: The sanitized name for reference.
        sha256_hash: Optional SHA-256 hash prefix for deterministic identification.

    Returns:
        A unique internal filename (e.g. 'sample_a3f8c1..._3fa85f64.bin').
    """
    unique_token = uuid.uuid4().hex[:12]
    if sha256_hash:
        prefix = sha256_hash[:16]
    else:
        prefix = uuid.uuid4().hex[:16]

    return f"sample_{prefix}_{unique_token}.bin"
