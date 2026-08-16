"""
File Management and Secure Intake API Endpoints.
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, status
from pydantic import BaseModel
from typing import Dict, Any, Optional

from app.core.logger import logger
from app.core.storage import analysis_store
from app.analyzers.file_intake import secure_intake_service, IntakeStatus

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
async def upload_file(file: UploadFile = File(...)):
    """
    Handles secure upload and perimeter validation for Windows PE executables.
    """
    raw_filename = file.filename or "unnamed_sample.bin"
    logger.info(f"Incoming upload request for file: '{raw_filename}'")

    try:
        content = await file.read()
    except Exception as e:
        logger.error(f"Failed to read incoming file stream: {e}")
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
        raise HTTPException(
            status_code=status_code,
            detail={
                "status": result.status.value,
                "message": result.message,
                "filename": result.filename,
                "validation_notes": result.validation_notes
            }
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
async def get_file_record(analysis_id: str):
    """
    Fetches the intake record and hashes for a given analysis ID.
    """
    record = analysis_store.get_record(analysis_id)
    if not record:
        logger.warning(f"File lookup failed: Analysis ID '{analysis_id}' not found.")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis record '{analysis_id}' not found."
        )

    return FileUploadResponse(
        analysis_id=record.analysis_id,
        filename=record.filename,
        size=record.size,
        sha256=record.sha256,
        md5=record.md5,
        status=record.status,
    )
