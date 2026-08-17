"""
Audit Event Types and Result Enums for ETHIO-AI Defender Security Audit System.
"""

from enum import Enum


class AuditEventType(str, Enum):
    """
    Standardized security audit event types.
    Strictly covers platform authentication, intake, static analysis, reporting, and administration.
    """
    LOGIN = "login"
    LOGOUT = "logout"
    UPLOAD = "upload"
    ANALYSIS_START = "analysis start"
    ANALYSIS_COMPLETION = "analysis completion"
    ANALYSIS_FAILURE = "analysis failure"
    REPORT_GENERATION = "report generation"
    ADMINISTRATIVE_CHANGES = "administrative changes"
    SECURITY_ALERT = "security alert"


class AuditResult(str, Enum):
    """
    Standardized audit event outcomes.
    """
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"
    LOCKED = "LOCKED"
    ERROR = "ERROR"
