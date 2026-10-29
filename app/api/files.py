"""
File Management and Secure Intake API Endpoints.
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, status, Depends
from pydantic import BaseModel
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logger import logger
from app.core.storage import analysis_store
from app.analyzers.file_intake import secure_intake_service, IntakeStatus
from app.audit.logger import audit_logger
from app.audit.events import AuditResult
from app.auth.dependencies import require_permissions
from app.auth.roles import Permission, UserRole
from app.db.session import get_db
from app.db.models import UserModel
from app.db.repository import SampleRepository
from app.utils.upload_guard import read_upload_bounded

router = APIRouter(prefix="/api/files", tags=["File Intake"])


class FileUploadResponse(BaseModel):
    """Standard API response model for file intake."""
    analysis_id: str
    filename: str
    size: int
    sha256: str
    md5: str
    status: str


@router.post(
    "/upload",
    response_model=FileUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Securely upload a Windows PE file (.exe, .dll)",
    description="Accepts and validates a binary without executing it. Returns an analysis ID and hashes.",
)
async def upload_file(
    file: UploadFile = File(...),
    current_user: UserModel = Depends(require_permissions(Permission.UPLOAD_FILES)),
):
    """
    Handles secure upload and perimeter validation for Windows PE executables.

    Requires authentication and the UPLOAD_FILES permission (ADMIN / ANALYST).
    """
    raw_filename = file.filename or "unnamed_sample.bin"
    logger.info(f"Incoming upload request from '{current_user.username}' for file: '{raw_filename}'")

    try:
        content = await read_upload_bounded(
            file, settings.MAX_FILE_SIZE_BYTES, settings.UPLOAD_CHUNK_SIZE
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to read incoming file stream: {e}")
        audit_logger.log_upload(
            result=AuditResult.ERROR,
            filename=raw_filename,
            details={"error": str(e)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not read uploaded file stream: {str(e)}"
        )

    # Process through Secure Intake Engine
    result = secure_intake_service.process_bytes(content, raw_filename=raw_filename)

    if not result.is_success:
        # Determine appropriate HTTP status code based on rejection reason
        if result.status == IntakeStatus.REJECTED_OVERSIZED:
            status_code = status.HTTP_413_CONTENT_TOO_LARGE
        elif result.status in (
            IntakeStatus.REJECTED_EMPTY,
            IntakeStatus.REJECTED_INVALID_EXTENSION,
            IntakeStatus.REJECTED_INVALID_PE,
            IntakeStatus.REJECTED_DANGEROUS_NAME,
        ):
            status_code = status.HTTP_400_BAD_REQUEST
        else:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

        logger.warning(f"Upload rejected: {result.message} (Status: {result.status.value})")
        audit_logger.log_upload(
            result=AuditResult.FAILURE,
            filename=raw_filename,
            details={"status": result.status.value, "reason": result.message},
        )
        raise HTTPException(
            status_code=status_code,
            detail={
                "status": result.status.value,
                "message": result.message,
                "filename": result.filename,
                "validation_notes": result.validation_notes
            }
        )

    # Log successful file intake
    audit_logger.log_upload(
        result=AuditResult.SUCCESS,
        filename=result.filename,
        analysis_id=result.analysis_id,
        size=result.size,
        sha256=result.sha256,
        details={"status": result.status.value},
    )

    return FileUploadResponse(
        analysis_id=result.analysis_id or "",
        filename=result.filename,
        size=result.size,
        sha256=result.sha256,
        md5=result.md5,
        status=result.status.value,
    )


@router.get(
    "/{analysis_id}",
    response_model=FileUploadResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve file intake status and metadata",
    description="Returns metadata and current status for a previously submitted analysis ID.",
)
async def get_file_record(
    analysis_id: str,
    current_user: UserModel = Depends(require_permissions(Permission.VIEW_AUTHORIZED_ANALYSES)),
    db: Session = Depends(get_db)
):
    """
    Fetches the intake record and hashes for a given analysis ID with RBAC and object-level scoping.
    """
    sample = SampleRepository.get_by_analysis_id(db, analysis_id)
    record = analysis_store.get_record(analysis_id)

    if not sample and not record:
        logger.warning(f"File lookup failed: Analysis ID '{analysis_id}' not found.")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis record '{analysis_id}' not found."
        )

    if sample is not None and sample.user_id is not None:
        if current_user.role != UserRole.ADMIN.value and sample.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not have permission to view file metadata for this analysis."
            )

    if record:
        return FileUploadResponse(
            analysis_id=record.analysis_id,
            filename=record.filename,
            size=record.size,
            sha256=record.sha256,
            md5=record.md5,
            status=record.status,
        )

    return FileUploadResponse(
        analysis_id=sample.analysis_id,
        filename=sample.filename,
        size=sample.size,
        sha256=sample.sha256,
        md5=sample.md5 or "",
        status=sample.status,
    )
