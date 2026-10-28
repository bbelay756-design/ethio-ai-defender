"""
Dashboard API Endpoints for ETHIO-AI Defender

Provides endpoints for:
- Uploading and running full static analysis pipeline across Modules 01 to 14
- Retrieving full multi-section analysis details for the 8 dashboard views
- Listing analyzed samples
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, Query, Depends, status
from typing import Dict, List, Optional, Any
from pathlib import Path

from app.core.logger import logger
from app.core.storage import analysis_store
from app.analyzers.file_intake import secure_intake_service, IntakeStatus
from app.analyzers.hash_analyzer import hash_analyzer_service
from app.analyzers.pe_analyzer import pe_static_analyzer_service
from app.analyzers.section_analyzer import pe_section_analyzer_service
from app.analyzers.entropy_analyzer import entropy_analyzer_service
from app.analyzers.string_analyzer import string_analyzer_service
from app.analyzers.import_analyzer import windows_api_import_analyzer_service
from app.analyzers.indicator_engine import suspicious_indicator_engine_service
from app.analyzers.threat_scoring import threat_scoring_engine_service
from app.analyzers.ethiopian_context import ethiopian_context_engine_service
from app.ai.analyst import ai_security_analyst_service
from app.education.learning_mode import learning_mode_service
from app.reports.generator import security_report_generator_service
from app.audit.logger import audit_logger
from app.audit.events import AuditResult, AuditEventType

from app.db.session import SessionLocal, get_db
from app.db.models import UserModel
from app.db.repository import SampleRepository
from app.auth.roles import UserRole, Permission
from app.auth.dependencies import get_current_user, get_optional_current_user, require_permissions
from app.core.config import settings
from app.utils.upload_guard import read_upload_bounded
from app.db.schemas import (
    SampleCreate,
    SectionCreate,
    ImportCreate,
    StringCreate,
    IndicatorCreate,
    AnalysisResultCreate,
)

from app.pipeline import unified_pipeline_service

router = APIRouter(prefix="/api/dashboard", tags=["Defensive Dashboard"])


def run_full_analysis_pipeline(
    content: bytes,
    filename: str,
    language: str = "en",
    user_id: Optional[int] = None
) -> Dict[str, Any]:
    """
    Orchestrates the complete deterministic analysis, AI assessment, learning lessons,
    and database persistence across all modules via Module 19 Unified Pipeline Orchestrator.
    """
    return unified_pipeline_service.execute_pipeline(
        content=content,
        filename=filename,
        language=language,
        user_id=user_id
    )


@router.post("/analyze", summary="Upload and execute complete defensive analysis")
async def analyze_upload(
    file: UploadFile = File(...),
    language: str = Query("en", description="'en' for English, 'am' for Amharic"),
    current_user: UserModel = Depends(require_permissions(Permission.UPLOAD_FILES))
):
    """
    Accepts PE binary, validates perimeter, orchestrates full multi-module analysis,
    and returns comprehensive results for the 8 dashboard views.

    Requires authentication and the UPLOAD_FILES permission (ADMIN / ANALYST).
    """
    raw_filename = file.filename or "sample.exe"
    logger.info(f"Incoming dashboard analysis request from '{current_user.username}' for '{raw_filename}' (Lang: {language})")

    try:
        content = await read_upload_bounded(
            file, settings.MAX_FILE_SIZE_BYTES, settings.UPLOAD_CHUNK_SIZE
        )
    except HTTPException:
        raise
    except Exception as e:
        audit_logger.log_analysis_failure(
            analysis_id="UNKNOWN",
            filename=raw_filename,
            error=f"Upload read error: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not read upload payload: {e}"
        )

    try:
        result = run_full_analysis_pipeline(
            content,
            filename=raw_filename,
            language=language,
            user_id=current_user.id
        )
        return result
    except ValueError as ve:
        audit_logger.log_analysis_failure(
            analysis_id="UNKNOWN",
            filename=raw_filename,
            error=str(ve),
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as ex:
        audit_logger.log_analysis_failure(
            analysis_id="UNKNOWN",
            filename=raw_filename,
            error=str(ex),
        )
        logger.error(f"Analysis pipeline error: {ex}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))


@router.get("/samples", summary="List analyzed samples")
def list_samples(skip: int = 0, limit: int = 20):
    """Lists analyzed samples from database."""
    db = SessionLocal()
    try:
        samples = SampleRepository.list_samples(db, skip=skip, limit=limit)
        return [
            {
                "id": s.id,
                "analysis_id": s.analysis_id,
                "filename": s.filename,
                "size": s.size,
                "file_type": s.file_type,
                "architecture": s.architecture,
                "sha256": s.sha256,
                "status": s.status,
                "created_at": s.created_at.isoformat() if s.created_at else None
            }
            for s in samples
        ]
    finally:
        db.close()


@router.get("/samples/{analysis_id}/full", summary="Get full analysis details by analysis ID")
def get_sample_full(
    analysis_id: str,
    language: str = "en",
    current_user: Optional[UserModel] = Depends(get_optional_current_user)
):
    """Fetches full analysis details for a given analysis ID with object-level authorization."""
    db = SessionLocal()
    try:
        sample = SampleRepository.get_by_analysis_id(db, analysis_id)
        if not sample:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sample '{analysis_id}' not found.")

        # Object-level authorization (IDOR protection):
        if sample.user_id is not None and current_user is not None:
            if current_user.role != UserRole.ADMIN.value and sample.user_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You do not have permission to access this sample."
                )

        # Reconstruct response payload
        return {
            "analysis_id": sample.analysis_id,
            "filename": sample.filename,
            "file_information": {
                "filename": sample.filename,
                "file_size": sample.size,
                "file_kind": sample.file_type,
                "machine_type": sample.architecture,
            },
            "hashes": {
                "md5": sample.md5,
                "sha256": sample.sha256
            },
            "sections": {
                "total_sections": len(sample.sections),
                "sections": [
                    {
                        "name": s.name,
                        "virtual_address": s.virtual_address,
                        "virtual_size": s.virtual_size,
                        "raw_size": s.raw_size,
                        "entropy": s.entropy,
                        "characteristics": s.characteristics
                    }
                    for s in sample.sections
                ]
            },
            "imports": {
                "total_imports": len(sample.imports),
                "imports": [
                    {"dll": i.dll, "api": i.api, "category": i.category, "risk_relevance": i.risk_relevance}
                    for i in sample.imports
                ]
            },
            "strings": {
                "urls": [s.value for s in sample.strings if s.type == "URL"],
                "ip_addresses": [s.value for s in sample.strings if s.type == "IP_ADDRESS"],
                "registry_paths": [s.value for s in sample.strings if s.type == "REGISTRY_PATH"],
            },
            "indicators": {
                "total_indicators": len(sample.indicators),
                "indicators": [
                    {"name": ind.name, "category": ind.category, "severity": ind.severity, "evidence": ind.evidence}
                    for ind in sample.indicators
                ]
            },
            "threat_score": {
                "score": sample.analysis_results.risk_score if sample.analysis_results else 0,
                "risk_level": sample.analysis_results.risk_level if sample.analysis_results else "LOW"
            },
            "ai_assessment": {
                "assessment": sample.analysis_results.risk_level if sample.analysis_results else "LOW",
                "summary": sample.analysis_results.ai_summary if sample.analysis_results else "",
                "confidence": sample.analysis_results.ai_confidence if sample.analysis_results else "MEDIUM"
            },
            "ml_analysis": {
                "available": False,
                "status": "UNAVAILABLE",
                "message": "ML advisory signal is not available for this historical record.",
                "malicious_score": None,
                "is_malicious": None,
                "is_malicious_1pct_fpr": None,
                "is_malicious_01pct_fpr": None,
                "active_threshold": 0.800395,
                "thresholds": {"default_05": 0.500000, "target_1pct_fpr": 0.800395, "target_01pct_fpr": 0.966365},
                "model_name": "ember-v2-baseline-hgb-subset80k",
                "model_version": "1.0.0",
                "model_sha256": "f2fd3ed4e4fc0b482600bb92fe24e36d23a93617bf214f62019def5c352bd684",
                "feature_parity_status": "EXPERIMENTAL_UNVERIFIED_PARITY",
                "is_reliable": False,
                "advisory_only": True,
                "advisory_label": "EXPERIMENTAL_ADVISORY_PRIORITY",
                "review_priority": "NOT_EVALUATED",
                "disclaimer": (
                    "Advisory-only analyst prioritization signal. Experimental model score is not a confirmed "
                    "malware verdict and does not alter heuristic risk scores or trigger autonomous actions."
                ),
            }
        }
    finally:
        db.close()


@router.delete("/samples/{analysis_id}", summary="Delete analyzed sample (Object Authorization Protected)")
def delete_sample(
    analysis_id: str,
    current_user: UserModel = Depends(get_current_user)
):
    """Deletes an analyzed sample. Enforces that only sample owner or ADMIN can delete."""
    db = SessionLocal()
    try:
        sample = SampleRepository.get_by_analysis_id(db, analysis_id)
        if not sample:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sample '{analysis_id}' not found.")

        # Object-level authorization (IDOR protection):
        if current_user.role != UserRole.ADMIN.value and sample.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not have permission to delete this sample."
            )

        SampleRepository.delete_sample(db, sample.id)
        return {"message": f"Sample '{analysis_id}' successfully deleted.", "analysis_id": analysis_id}
    finally:
        db.close()


@router.get("/samples/{analysis_id}/report", summary="Generate and export security report with audit logging")
def generate_sample_report(
    analysis_id: str,
    format: str = Query("json", description="Report format: json, markdown, html, text"),
    language: str = Query("en", description="Report language: en, am"),
    current_user: Optional[UserModel] = Depends(get_optional_current_user)
):
    """
    Generates security analysis report in requested format and logs the audit event.
    """
    data = get_sample_full(analysis_id, language=language, current_user=current_user)
    if not data:
        audit_logger.log_report_generation(
            analysis_id=analysis_id,
            report_format=format,
            result=AuditResult.FAILURE,
            details={"error": "Sample not found"}
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Analysis '{analysis_id}' not found.")

    # Log report generation event
    audit_logger.log_report_generation(
        analysis_id=analysis_id,
        report_format=format,
        result=AuditResult.SUCCESS,
        details={"format": format.upper(), "language": language}
    )

    return {
        "analysis_id": analysis_id,
        "format": format.upper(),
        "language": language,
        "data": data
    }

