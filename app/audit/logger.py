"""
Structured JSON Security Logging and Audit System for ETHIO-AI Defender (Module 17).

Provides:
- Structured JSON log formatting
- Log rotation via RotatingFileHandler
- Zero-leakage sensitive data scrubbing
- Dual persistence: Rotating JSONL file on disk + SQLite ORM for Administrator Audit Viewer
"""

import json
import logging
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional, Union

from app.core.config import settings
from app.audit.events import AuditEventType, AuditResult
from app.audit.sanitizer import scrub_audit_data


class StructuredJsonFormatter(logging.Formatter):
    """
    Serializes audit log records into strict single-line JSON format.
    """
    def format(self, record: logging.LogRecord) -> str:
        # If the record already carries structured audit data, dump it as JSON
        if hasattr(record, "audit_payload"):
            payload = record.audit_payload
        else:
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_id": getattr(record, "user_id", None),
                "event": getattr(record, "event", "system_log"),
                "analysis_id": getattr(record, "analysis_id", None),
                "result": getattr(record, "result", record.levelname),
                "message": record.getMessage(),
            }

        return json.dumps(payload, ensure_ascii=False, default=str)


class SecurityAuditLogger:
    """
    Thread-safe structured audit logger with automated rotation and sanitization.
    """
    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path or settings.AUDIT_LOG_FILE
        self._lock = threading.Lock()
        self._logger = self._setup_internal_logger()

    def _setup_internal_logger(self) -> logging.Logger:
        audit_logger = logging.getLogger("ethio_audit_engine")
        audit_logger.setLevel(logging.INFO)
        audit_logger.propagate = False

        # Clear existing handlers to prevent duplication
        for h in list(audit_logger.handlers):
            try:
                h.close()
            except Exception:
                pass
            audit_logger.removeHandler(h)

        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                filename=str(self.log_path),
                maxBytes=settings.AUDIT_LOG_MAX_BYTES,
                backupCount=settings.AUDIT_LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
            handler.setFormatter(StructuredJsonFormatter())
            handler.setLevel(logging.INFO)
            audit_logger.addHandler(handler)
        except Exception as e:
            # Fallback to standard error output if file handler creation fails
            fallback = logging.StreamHandler()
            fallback.setFormatter(StructuredJsonFormatter())
            audit_logger.addHandler(fallback)
            audit_logger.warning(f"Could not setup audit log file handler at {self.log_path}: {e}")

        return audit_logger

    def close(self) -> None:
        """Closes and flushes internal logging handlers."""
        with self._lock:
            for handler in list(self._logger.handlers):
                try:
                    handler.flush()
                    handler.close()
                except Exception:
                    pass
                self._logger.removeHandler(handler)

    def log_event(
        self,
        event: Union[AuditEventType, str],
        result: Union[AuditResult, str],
        user_id: Optional[int] = None,
        analysis_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        db: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Emits a structured JSON audit event to the rotated log file and persists to DB.
        Guarantees strict stripping of passwords, tokens, API keys, and sensitive secrets.
        """
        event_str = event.value if isinstance(event, AuditEventType) else str(event)
        result_str = result.value if isinstance(result, AuditResult) else str(result)
        iso_timestamp = datetime.now(timezone.utc).isoformat()

        # Sanitize details to guarantee zero leakage of sensitive data
        sanitized_details = scrub_audit_data(details) if details else {}
        if ip_address:
            sanitized_details["ip_address"] = ip_address

        # Build standardized event payload
        audit_payload: Dict[str, Any] = {
            "timestamp": iso_timestamp,
            "user_id": user_id,
            "event": event_str,
            "analysis_id": analysis_id,
            "result": result_str,
            "details": sanitized_details,
        }

        # Write to rotated file handler
        with self._lock:
            extra = {"audit_payload": audit_payload}
            self._logger.info("", extra=extra)

        # Persist to SQLite Database if session is available
        self._persist_to_db(
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            event=event_str,
            analysis_id=analysis_id,
            result=result_str,
            details=sanitized_details,
            ip_address=ip_address,
            db=db,
        )

        return audit_payload

    def _persist_to_db(
        self,
        timestamp: datetime,
        user_id: Optional[int],
        event: str,
        analysis_id: Optional[str],
        result: str,
        details: Dict[str, Any],
        ip_address: Optional[str],
        db: Optional[Any] = None,
    ) -> None:
        """
        Persists audit record to the SQLite audit_logs table.
        """
        try:
            from app.db.models import AuditLogModel
            from app.db.session import SessionLocal

            should_close = False
            session = db
            if session is None:
                session = SessionLocal()
                should_close = True

            try:
                record = AuditLogModel(
                    timestamp=timestamp,
                    user_id=user_id,
                    event=event,
                    analysis_id=analysis_id,
                    result=result,
                    details_json=json.dumps(details, ensure_ascii=False, default=str),
                    ip_address=ip_address,
                )
                session.add(record)
                session.commit()
            except Exception:
                session.rollback()
            finally:
                if should_close:
                    session.close()
        except Exception:
            # DB logging failure must never crash core application operations
            pass

    # Convenience Methods for Required Security Events
    def log_login(
        self,
        result: Union[AuditResult, str],
        username: str,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        db: Optional[Any] = None,
    ) -> Dict[str, Any]:
        d = {"username": username}
        if details:
            d.update(details)
        return self.log_event(
            event=AuditEventType.LOGIN,
            result=result,
            user_id=user_id,
            details=d,
            ip_address=ip_address,
            db=db,
        )

    def log_logout(
        self,
        user_id: Optional[int],
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        db: Optional[Any] = None,
    ) -> Dict[str, Any]:
        d = {}
        if username:
            d["username"] = username
        return self.log_event(
            event=AuditEventType.LOGOUT,
            result=AuditResult.SUCCESS,
            user_id=user_id,
            details=d,
            ip_address=ip_address,
            db=db,
        )

    def log_upload(
        self,
        result: Union[AuditResult, str],
        filename: str,
        user_id: Optional[int] = None,
        analysis_id: Optional[str] = None,
        size: Optional[int] = None,
        sha256: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        db: Optional[Any] = None,
    ) -> Dict[str, Any]:
        d = {"filename": filename}
        if size is not None:
            d["size_bytes"] = size
        if sha256:
            d["sha256"] = sha256
        if details:
            d.update(details)
        return self.log_event(
            event=AuditEventType.UPLOAD,
            result=result,
            user_id=user_id,
            analysis_id=analysis_id,
            details=d,
            ip_address=ip_address,
            db=db,
        )

    def log_analysis_start(
        self,
        analysis_id: str,
        filename: Optional[str] = None,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        db: Optional[Any] = None,
    ) -> Dict[str, Any]:
        d = {}
        if filename:
            d["filename"] = filename
        if details:
            d.update(details)
        return self.log_event(
            event=AuditEventType.ANALYSIS_START,
            result=AuditResult.SUCCESS,
            user_id=user_id,
            analysis_id=analysis_id,
            details=d,
            db=db,
        )

    def log_analysis_completion(
        self,
        analysis_id: str,
        filename: Optional[str] = None,
        user_id: Optional[int] = None,
        risk_level: Optional[str] = None,
        threat_score: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        db: Optional[Any] = None,
    ) -> Dict[str, Any]:
        d = {}
        if filename:
            d["filename"] = filename
        if risk_level:
            d["risk_level"] = risk_level
        if threat_score is not None:
            d["threat_score"] = threat_score
        if details:
            d.update(details)
        return self.log_event(
            event=AuditEventType.ANALYSIS_COMPLETION,
            result=AuditResult.SUCCESS,
            user_id=user_id,
            analysis_id=analysis_id,
            details=d,
            db=db,
        )

    def log_analysis_failure(
        self,
        analysis_id: str,
        filename: Optional[str] = None,
        error: Optional[str] = None,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        db: Optional[Any] = None,
    ) -> Dict[str, Any]:
        d = {}
        if filename:
            d["filename"] = filename
        if error:
            d["error_message"] = error
        if details:
            d.update(details)
        return self.log_event(
            event=AuditEventType.ANALYSIS_FAILURE,
            result=AuditResult.FAILURE,
            user_id=user_id,
            analysis_id=analysis_id,
            details=d,
            db=db,
        )

    def log_report_generation(
        self,
        analysis_id: str,
        report_format: str,
        user_id: Optional[int] = None,
        result: Union[AuditResult, str] = AuditResult.SUCCESS,
        details: Optional[Dict[str, Any]] = None,
        db: Optional[Any] = None,
    ) -> Dict[str, Any]:
        d = {"report_format": report_format.upper()}
        if details:
            d.update(details)
        return self.log_event(
            event=AuditEventType.REPORT_GENERATION,
            result=result,
            user_id=user_id,
            analysis_id=analysis_id,
            details=d,
            db=db,
        )

    def log_admin_change(
        self,
        action: str,
        target_user_id: Optional[int] = None,
        target_username: Optional[str] = None,
        admin_user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        result: Union[AuditResult, str] = AuditResult.SUCCESS,
        db: Optional[Any] = None,
    ) -> Dict[str, Any]:
        d = {"action": action}
        if target_user_id is not None:
            d["target_user_id"] = target_user_id
        if target_username:
            d["target_username"] = target_username
        if details:
            d.update(details)
        return self.log_event(
            event=AuditEventType.ADMINISTRATIVE_CHANGES,
            result=result,
            user_id=admin_user_id,
            details=d,
            db=db,
        )

    def log_error(
        self,
        event_name: str,
        error_message: str,
        user_id: Optional[int] = None,
        analysis_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        db: Optional[Any] = None,
    ) -> Dict[str, Any]:
        d = {"error_message": error_message}
        if details:
            d.update(details)
        return self.log_event(
            event=event_name,
            result=AuditResult.ERROR,
            user_id=user_id,
            analysis_id=analysis_id,
            details=d,
            db=db,
        )

    def log_security_alert(
        self,
        alert_type: str,
        description: str,
        user_id: Optional[int] = None,
        analysis_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        db: Optional[Any] = None,
    ) -> Dict[str, Any]:
        d = {"alert_type": alert_type, "description": description}
        if details:
            d.update(details)
        return self.log_event(
            event=AuditEventType.SECURITY_ALERT,
            result=AuditResult.DENIED,
            user_id=user_id,
            analysis_id=analysis_id,
            details=d,
            db=db,
        )


# Global singleton instance
audit_logger = SecurityAuditLogger()
