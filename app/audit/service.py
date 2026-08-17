"""
Audit Query and Reporting Service for Administrator Audit Viewer (Module 17).
"""

import json
import csv
import io
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.db.models import AuditLogModel, UserModel
from app.audit.events import AuditEventType, AuditResult
from app.audit.sanitizer import scrub_audit_data


class AuditService:
    """
    Manages querying, filtering, statistics aggregation, and export
    for security audit events.
    """

    @staticmethod
    def get_logs(
        db: Session,
        event: Optional[str] = None,
        result: Optional[str] = None,
        user_id: Optional[int] = None,
        analysis_id: Optional[str] = None,
        search: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Queries audit records from the database with multi-field filtering and pagination.
        Returns a tuple of (serialized_records_list, total_matching_count).
        """
        query = db.query(AuditLogModel)

        if event:
            query = query.filter(AuditLogModel.event == event.lower())
        if result:
            query = query.filter(AuditLogModel.result == result.upper())
        if user_id is not None:
            query = query.filter(AuditLogModel.user_id == user_id)
        if analysis_id:
            query = query.filter(AuditLogModel.analysis_id == analysis_id)
        if date_from:
            query = query.filter(AuditLogModel.timestamp >= date_from)
        if date_to:
            query = query.filter(AuditLogModel.timestamp <= date_to)
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                (AuditLogModel.event.ilike(search_pattern)) |
                (AuditLogModel.analysis_id.ilike(search_pattern)) |
                (AuditLogModel.result.ilike(search_pattern)) |
                (AuditLogModel.details_json.ilike(search_pattern))
            )

        total_count = query.count()
        records = (
            query.order_by(desc(AuditLogModel.timestamp), desc(AuditLogModel.id))
            .offset(offset)
            .limit(min(limit, 500))
            .all()
        )

        formatted: List[Dict[str, Any]] = []
        for r in records:
            details_dict = {}
            if r.details_json:
                try:
                    details_dict = json.loads(r.details_json)
                except Exception:
                    details_dict = {"raw": str(r.details_json)}

            formatted.append({
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else "",
                "user_id": r.user_id,
                "username": r.user.username if r.user else None,
                "event": r.event,
                "analysis_id": r.analysis_id,
                "result": r.result,
                "ip_address": r.ip_address,
                "details": scrub_audit_data(details_dict),
            })

        return formatted, total_count

    @staticmethod
    def get_statistics(db: Session) -> Dict[str, Any]:
        """
        Calculates aggregate statistics and metrics for the SOC administrator dashboard.
        """
        total_events = db.query(func.count(AuditLogModel.id)).scalar() or 0
        success_count = db.query(func.count(AuditLogModel.id)).filter(AuditLogModel.result == AuditResult.SUCCESS.value).scalar() or 0
        failure_count = db.query(func.count(AuditLogModel.id)).filter(AuditLogModel.result.in_([AuditResult.FAILURE.value, AuditResult.ERROR.value])).scalar() or 0
        lockout_count = db.query(func.count(AuditLogModel.id)).filter(AuditLogModel.result == AuditResult.LOCKED.value).scalar() or 0
        denied_count = db.query(func.count(AuditLogModel.id)).filter(AuditLogModel.result == AuditResult.DENIED.value).scalar() or 0

        # Distribution by event type
        event_counts_query = (
            db.query(AuditLogModel.event, func.count(AuditLogModel.id))
            .group_by(AuditLogModel.event)
            .all()
        )
        event_distribution = {event: count for event, count in event_counts_query}

        # Recent alerts (failures, locks, denied access)
        recent_alerts_records = (
            db.query(AuditLogModel)
            .filter(AuditLogModel.result.in_([
                AuditResult.FAILURE.value,
                AuditResult.DENIED.value,
                AuditResult.LOCKED.value,
                AuditResult.ERROR.value
            ]))
            .order_by(desc(AuditLogModel.timestamp))
            .limit(5)
            .all()
        )

        recent_alerts = []
        for r in recent_alerts_records:
            details_dict = {}
            if r.details_json:
                try:
                    details_dict = json.loads(r.details_json)
                except Exception:
                    details_dict = {}

            recent_alerts.append({
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else "",
                "user_id": r.user_id,
                "username": r.user.username if r.user else None,
                "event": r.event,
                "result": r.result,
                "details": scrub_audit_data(details_dict),
            })

        return {
            "total_events": total_events,
            "success_count": success_count,
            "failure_count": failure_count,
            "lockout_count": lockout_count,
            "denied_count": denied_count,
            "event_distribution": event_distribution,
            "recent_alerts": recent_alerts,
        }

    @staticmethod
    def export_logs_csv(db: Session, limit: int = 1000) -> str:
        """
        Exports sanitized audit logs in CSV format.
        """
        records, _ = AuditService.get_logs(db, limit=limit, offset=0)
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow(["ID", "Timestamp", "User ID", "Username", "Event", "Analysis ID", "Result", "IP Address", "Details"])

        for r in records:
            writer.writerow([
                r["id"],
                r["timestamp"],
                r["user_id"] or "",
                r["username"] or "Anonymous",
                r["event"],
                r["analysis_id"] or "",
                r["result"],
                r["ip_address"] or "",
                json.dumps(r["details"], ensure_ascii=False),
            ])

        return output.getvalue()


audit_service = AuditService()
