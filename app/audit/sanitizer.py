"""
Audit Data Sanitizer and Sensitive Field Scrubber for ETHIO-AI Defender.

Strict Security Invariant:
DO NOT LOG:
- passwords (plain or hashed)
- API keys
- authentication tokens (JWT tokens, bearer tokens)
- unnecessary personal information (PII, session secrets, private keys)
"""

import re
from typing import Any, Dict, List, Union, Set

# Key names that must NEVER be written to audit logs (case-insensitive exact or compound matches)
FORBIDDEN_KEY_PATTERNS: Set[str] = {
    "password",
    "pass",
    "pwd",
    "passwd",
    "hashed_password",
    "salt",
    "token",
    "access_token",
    "refresh_token",
    "jwt",
    "bearer",
    "authorization",
    "secret",
    "secret_key",
    "api_key",
    "apikey",
    "gemini_api_key",
    "private_key",
    "privkey",
    "credit_card",
    "ssn",
    "cookie",
    "session_id",
}

# Regex heuristics for detecting embedded tokens, secrets, or bearer headers in arbitrary strings
JWT_PATTERN = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
BEARER_PATTERN = re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]{10,}", re.IGNORECASE)
API_KEY_PATTERN = re.compile(r"(AIza[0-9A-Za-z-_]{15,}|sk-[a-zA-Z0-9]{15,}|ghp_[a-zA-Z0-9]{15,})")


def scrub_string_secrets(value: str) -> str:
    """
    Sanitizes string values to redact JWTs, Bearer headers, and API key patterns.
    """
    if not isinstance(value, str):
        return str(value)

    # Redact JWT tokens
    scrubbed = JWT_PATTERN.sub("[REDACTED_JWT_TOKEN]", value)
    # Redact Bearer authorization values
    scrubbed = BEARER_PATTERN.sub("Bearer [REDACTED_TOKEN]", scrubbed)
    # Redact API Keys
    scrubbed = API_KEY_PATTERN.sub("[REDACTED_API_KEY]", scrubbed)

    return scrubbed


def is_sensitive_key(key: str) -> bool:
    """
    Checks if a dictionary key name suggests sensitive credentials or secrets.
    """
    normalized = str(key).strip().lower().replace("-", "_")
    if normalized in FORBIDDEN_KEY_PATTERNS:
        return True

    # Check suffix/prefix patterns like `user_password`, `client_secret`, `auth_token`
    for forbidden in ["password", "secret", "token", "passwd", "api_key", "apikey", "privkey"]:
        if forbidden in normalized:
            return True

    return False


def scrub_audit_data(data: Any, max_depth: int = 5) -> Any:
    """
    Recursively scrubs arbitrary data structures, stripping all sensitive keys,
    passwords, tokens, API keys, and personal identifiers.
    """
    if max_depth <= 0:
        return "[MAX_DEPTH_REACHED]"

    if data is None or isinstance(data, (int, float, bool)):
        return data

    if isinstance(data, str):
        return scrub_string_secrets(data)

    if isinstance(data, dict):
        sanitized_dict: Dict[str, Any] = {}
        for k, v in data.items():
            str_key = str(k)
            if isinstance(v, dict):
                # Recurse into nested dictionary
                sanitized_dict[str_key] = scrub_audit_data(v, max_depth=max_depth - 1)
            elif is_sensitive_key(str_key):
                sanitized_dict[str_key] = "[REDACTED]"
            else:
                sanitized_dict[str_key] = scrub_audit_data(v, max_depth=max_depth - 1)
        return sanitized_dict

    if isinstance(data, (list, tuple, set)):
        return [scrub_audit_data(item, max_depth=max_depth - 1) for item in data]

    # For objects with __dict__
    if hasattr(data, "__dict__"):
        return scrub_audit_data(vars(data), max_depth=max_depth - 1)

    return scrub_string_secrets(str(data))
