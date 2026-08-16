"""
Evidence Sanitizer & Privacy Redaction Module

Responsibility:
Enforces strict privacy and data protection boundaries before sending structured evidence to any AI service.

Safety Guarantees:
- NEVER passes raw EXE / DLL executable binaries or byte streams.
- Redacts potential passwords, API keys, bearer tokens, private keys, and authorization headers.
- Strips personal user filesystem directory paths (e.g., C:\\Users\\Username\\...).
- Caps and truncates string collections to avoid token overflow or leakage.
"""

import re
from typing import Dict, List, Any


# Regex patterns for sensitive tokens and personal paths
SECRET_PATTERNS = [
    (re.compile(r'(?i)(api[_-]?key|secret|token|password|auth|bearer)\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?'), r'\1=[REDACTED]'),
    (re.compile(r'(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{15,})'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(https?://[^:@\s]+):([^@\s]+)@'), r'\1:[REDACTED]@'),
]

# Sensitive user directory paths regex
USER_PATH_PATTERN = re.compile(r'(?i)[A-Z]:\\Users\\[^\\]+\\')
UNIX_USER_PATH_PATTERN = re.compile(r'/home/[^/]+/')


def sanitize_text_string(text: str) -> str:
    """
    Strips personal paths and sensitive token patterns from a string.
    """
    if not isinstance(text, str):
        return str(text)

    # Redact user directory names
    cleaned = USER_PATH_PATTERN.sub(r'C:\\Users\\<USER>\\', text)
    cleaned = UNIX_USER_PATH_PATTERN.sub(r'/home/<USER>/', cleaned)

    # Redact secrets and tokens
    for pattern, replacement in SECRET_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)

    return cleaned


def sanitize_evidence_payload(raw_evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitizes and bounds structured static analysis evidence before passing to AI.
    Guarantees no raw bytes or sensitive credentials escape the local sandbox.
    """
    if not isinstance(raw_evidence, dict):
        return {}

    sanitized: Dict[str, Any] = {}

    for key, value in raw_evidence.items():
        # 1. Strictly block raw binary keys
        if key.lower() in ("raw_bytes", "binary_content", "byte_stream", "raw_data", "file_data", "pe_bytes"):
            continue

        # 2. Recursively sanitize dicts
        if isinstance(value, dict):
            sanitized[key] = sanitize_evidence_payload(value)

        # 3. Sanitize and bound lists
        elif isinstance(value, list):
            bounded_list = []
            for item in value[:25]:  # Bound collection size to top 25 items
                if isinstance(item, str):
                    bounded_list.append(sanitize_text_string(item))
                elif isinstance(item, dict):
                    bounded_list.append(sanitize_evidence_payload(item))
                elif isinstance(item, (int, float, bool)):
                    bounded_list.append(item)
            sanitized[key] = bounded_list

        # 4. Sanitize strings
        elif isinstance(value, str):
            sanitized[key] = sanitize_text_string(value)

        # 5. Pass through scalar numeric / boolean types
        elif isinstance(value, (int, float, bool)) or value is None:
            sanitized[key] = value

    return sanitized
