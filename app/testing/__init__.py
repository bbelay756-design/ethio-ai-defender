"""
Module 18: Security Testing Framework Package.
Provides safe synthetic PE generators and attack payload test matrices.
"""

from app.testing.synthetic_pe import SyntheticPEBuilder
from app.testing.attack_payloads import (
    PATH_TRAVERSAL_FILENAMES,
    DANGEROUS_FILENAMES,
    SQL_INJECTION_PAYLOADS,
    XSS_PAYLOADS,
    INVALID_AUTH_HEADERS,
    MALFORMED_JSON_PAYLOADS,
)

__all__ = [
    "SyntheticPEBuilder",
    "PATH_TRAVERSAL_FILENAMES",
    "DANGEROUS_FILENAMES",
    "SQL_INJECTION_PAYLOADS",
    "XSS_PAYLOADS",
    "INVALID_AUTH_HEADERS",
    "MALFORMED_JSON_PAYLOADS",
]
