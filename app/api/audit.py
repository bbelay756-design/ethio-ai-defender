"""
Security Audit Log and SOC Monitoring API Endpoints (Module 17).
Strictly protected by Role-Based Access Control (Admin only).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.auth.roles import UserRole, Permission
from app.auth.dependencies import require_roles, require_permissions
from app.auth.service import UserModel
from app.audit.events import AuditEventType, AuditResult
from app.audit.service import audit_service
from app.audit.logger import audit_logger

router = APIRouter(prefix="/api/audit", tags=["Security Audit & SOC"])


class AuditLogItemResponse(BaseModel):
    id: int
    timestamp: str
    user_id: Optional[int]
    username: Optional[str]
    event: str
    analysis_id: Optional[str]
    result: str
    ip_address: Optional[str]
    details: Dict[str, Any]


class AuditLogListResponse(BaseModel):
    items: List[AuditLogItemResponse]
    total: int
    page: int
    page_size: int
    pages: int


class AuditStatsResponse(BaseModel):
    total_events: int
    success_count: int
    failure_count: int
    lockout_count: int
    denied_count: int
    event_distribution: Dict[str, int]
    recent_alerts: List[Dict[str, Any]]


@router.get(
    "/logs",
    response_model=AuditLogListResponse,
    summary="Query structured security audit logs (Admin only)",
    description="Returns filtered and paginated audit records. Guarantees zero secret exposure.",
)
def get_audit_logs(
    event: Optional[str] = Query(None, description="Filter by event type (e.g. login, upload, analysis start)"),
    result: Optional[str] = Query(None, description="Filter by result (e.g. SUCCESS, FAILURE, LOCKED, DENIED)"),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    analysis_id: Optional[str] = Query(None, description="Filter by analysis ID"),
    search: Optional[str] = Query(None, description="Free-text search in details and metadata"),
    date_from: Optional[datetime] = Query(None, description="ISO starting datetime"),
    date_to: Optional[datetime] = Query(None, description="ISO ending datetime"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    db: Session = Depends(get_db),
    admin_user: UserModel = Depends(require_roles([UserRole.ADMIN])),
):
    """
    Administrator Audit Viewer API endpoint for SOC investigation.
    """
    offset = (page - 1) * page_size
    records, total = audit_service.get_logs(
        db=db,
        event=event,
        result=result,
        user_id=user_id,
        analysis_id=analysis_id,
        search=search,
        date_from=date_from,
        date_to=date_to,
        limit=page_size,
        offset=offset,
    )

    pages = max(1, (total + page_size - 1) // page_size)

    return {
        "items": records,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


@router.get(
    "/stats",
    response_model=AuditStatsResponse,
    summary="Audit log summary statistics for SOC dashboard (Admin only)",
)
def get_audit_statistics(
    db: Session = Depends(get_db),
    admin_user: UserModel = Depends(require_roles([UserRole.ADMIN])),
):
    """
    Returns aggregated metrics and high-priority alert summaries.
    """
    return audit_service.get_statistics(db=db)


@router.get(
    "/export/csv",
    summary="Export sanitized audit log records to CSV (Admin only)",
)
def export_audit_csv(
    limit: int = Query(1000, ge=1, le=5000),
    db: Session = Depends(get_db),
    admin_user: UserModel = Depends(require_roles([UserRole.ADMIN])),
):
    """
    Generates sanitized CSV audit export for compliance and auditing.
    """
    csv_data = audit_service.export_logs_csv(db=db, limit=limit)
    filename = f"security_audit_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
