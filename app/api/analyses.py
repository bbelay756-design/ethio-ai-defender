"""
Standard REST API Endpoints for Static Binary Analyses (/api/analyses)

Provides complete REST CRUD interface:
- POST /api/analyses             -> Upload and execute static PE analysis
- GET /api/analyses              -> List analyzed samples with pagination and filters
- GET /api/analyses/{id}         -> Retrieve complete analysis evidence and metadata
- GET /api/analyses/{id}/report  -> Export security analysis report (JSON, HTML, Markdown, Text)
- DELETE /api/analyses/{id}      -> Delete an analysis record (Owner or Admin)
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, UploadFile, File, HTTPException, Query, Depends, status
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from pydantic import BaseModel

from app.core.logger import logger
from app.core.config import settings
from app.db.session import SessionLocal
from app.db.models import UserModel, SampleModel
from app.db.repository import SampleRepository
from app.auth.roles import UserRole
from app.auth.dependencies import get_current_user, get_optional_current_user
from app.pipeline.orchestrator import unified_pipeline_service
from app.audit.logger import audit_logger
from app.audit.events import AuditResult
from app.db.schemas import AnalysisSummaryResponse

router = APIRouter(prefix="/api/analyses", tags=["Static Binary Analyses"])


class AnalysisUploadResponse(BaseModel):
    """Standard REST response model for analysis creation."""
    analysis_id: str
    filename: str
    sha256: str
    md5: str
    status: str
    risk_score: int
    classification: str
    data: Optional[Dict[str, Any]] = None


class AnalysisListResponse(BaseModel):
    """Paginated list response for analysis history."""
    total: int
    skip: int
    limit: int
    items: List[AnalysisSummaryResponse]


@router.post(
    "",
    response_model=AnalysisUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and analyze a Windows PE binary (.exe, .dll)",
    description="Uploads a binary, performs non-executing static PE analysis, scores heuristic risk, and stores results."
)
async def create_analysis(
    file: UploadFile = File(...),
    language: str = Query("en", description="'en' for English, 'am' for Amharic"),
    current_user: Optional[UserModel] = Depends(get_optional_current_user)
):
    """
    Handles secure multipart/form-data upload and executes complete deterministic static analysis pipeline.
    """
    raw_filename = file.filename or "sample.exe"
    logger.info(f"REST POST /api/analyses request for '{raw_filename}' (Lang: {language})")

    # 1. Read binary stream
    try:
        content = await file.read()
    except Exception as e:
        audit_logger.log_analysis_failure(
            analysis_id="UNKNOWN",
            filename=raw_filename,
            error=f"Stream read error: {e}",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not read upload payload: {str(e)}"
        )

    # 2. Enforce File Size Limit (50 MB)
    if len(content) > settings.MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {settings.MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB."
        )

    # 3. Enforce File Extension
    ext = (raw_filename.split(".")[-1] if "." in raw_filename else "").lower()
    if f".{ext}" not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '.{ext}'. Supported extensions are: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )

    # 4. Execute Unified Pipeline
    try:
        user_id = current_user.id if current_user else None
        result = unified_pipeline_service.execute_pipeline(
            content=content,
            filename=raw_filename,
            language=language,
            user_id=user_id
        )

        return AnalysisUploadResponse(
            analysis_id=result["analysis_id"],
            filename=result["filename"],
            sha256=result["hashes"]["sha256"],
            md5=result["hashes"]["md5"],
            status=result["status"],
            risk_score=result["risk_score"].get("score", 0),
            classification=result["risk_score"].get("risk_level", "LOW"),
            data=result
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid or unsupported Windows PE file: {str(ve)}"
        )
    except Exception as ex:
        logger.error(f"Analysis pipeline execution failure: {ex}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline error: {str(ex)}"
        )


@router.get(
    "",
    response_model=AnalysisListResponse,
    summary="List analysis history with search and filtering",
    description="Retrieves a paginated list of analyzed PE binaries from the database."
)
def list_analyses(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    search: Optional[str] = Query(None, description="Search by filename, hash, or analysis ID"),
    status: Optional[str] = Query(None, description="Filter by status (COMPLETED, FAILED)"),
    risk: Optional[str] = Query(None, description="Filter by risk tier (LOW, MODERATE, SUSPICIOUS, HIGH, CRITICAL)"),
    current_user: Optional[UserModel] = Depends(get_optional_current_user)
):
    """Lists historical static analysis records with RBAC scoping."""
    db = SessionLocal()
    try:
        # Determine scoping: ADMIN sees all; normal user sees their own or unauthenticated samples
        filter_user_id = None
        if current_user and current_user.role != UserRole.ADMIN.value:
            filter_user_id = current_user.id

        total_count = SampleRepository.count_samples(
            db=db,
            search=search,
            status_filter=status,
            risk_filter=risk,
            user_id=filter_user_id
        )

        samples = SampleRepository.list_samples(
            db=db,
            skip=skip,
            limit=limit,
            search=search,
            status_filter=status,
            risk_filter=risk,
            user_id=filter_user_id
        )

        items = [
            AnalysisSummaryResponse(
                id=s.id,
                analysis_id=s.analysis_id,
                filename=s.filename,
                size=s.size,
                file_type=s.file_type,
                architecture=s.architecture,
                sha256=s.sha256,
                sha1=s.sha1,
                md5=s.md5,
                status=s.status,
                risk_score=s.risk_score or (s.analysis_results.risk_score if s.analysis_results else 0),
                classification=s.classification or (s.analysis_results.risk_level if s.analysis_results else "LOW"),
                created_at=s.created_at.isoformat() if s.created_at else None,
                completed_at=s.completed_at.isoformat() if s.completed_at else None,
            )
            for s in samples
        ]

        return AnalysisListResponse(
            total=total_count,
            skip=skip,
            limit=limit,
            items=items
        )
    finally:
        db.close()


@router.get(
    "/overview-stats",
    summary="Get aggregated threat posture & analysis statistics",
    description="Returns real platform-wide counts, risk distribution, top indicator categories, IOC totals, and recent activity."
)
def get_analysis_overview_stats(
    current_user: Optional[UserModel] = Depends(get_optional_current_user)
):
    """Computes real aggregated threat overview metrics for dashboard HUD."""
    from app.db.models import IOCModel, IndicatorModel, ImportModel, StringModel

    db = SessionLocal()
    try:
        total_samples = db.query(SampleModel).count()
        low_count = db.query(SampleModel).filter(SampleModel.risk_score < 40).count()
        med_count = db.query(SampleModel).filter(SampleModel.risk_score >= 40, SampleModel.risk_score < 70).count()
        high_count = db.query(SampleModel).filter(SampleModel.risk_score >= 70, SampleModel.risk_score < 85).count()
        crit_count = db.query(SampleModel).filter(SampleModel.risk_score >= 85).count()

        # IOC counts
        ioc_total = db.query(IOCModel).count()
        ioc_domains = db.query(IOCModel).filter(IOCModel.type.ilike("%domain%")).count()
        ioc_ips = db.query(IOCModel).filter(IOCModel.type.ilike("%ip%")).count()
        ioc_urls = db.query(IOCModel).filter(IOCModel.type.ilike("%url%")).count()
        ioc_hashes = db.query(IOCModel).filter(IOCModel.type.ilike("%hash%")).count()
        ioc_registry = db.query(IOCModel).filter(IOCModel.type.ilike("%registry%")).count()

        # Indicator categories counts
        susp_apis = db.query(ImportModel).filter(ImportModel.risk_relevance.in_(["HIGH", "CRITICAL"])).count()
        susp_strings = db.query(StringModel).filter(StringModel.severity.in_(["HIGH", "CRITICAL"])).count()
        net_indicators = db.query(IndicatorModel).filter(IndicatorModel.category == "NETWORK").count()
        reg_indicators = db.query(IndicatorModel).filter(IndicatorModel.category == "REGISTRY").count()
        entropy_indicators = db.query(IndicatorModel).filter(IndicatorModel.category == "ENTROPY").count()

        # Recent 6 analyses
        recent_samples = db.query(SampleModel).order_by(SampleModel.created_at.desc()).limit(6).all()
        recent_activity = [
            {
                "analysis_id": s.analysis_id,
                "filename": s.filename,
                "sha256_short": s.sha256[:12] if s.sha256 else "N/A",
                "risk_score": s.risk_score or 0,
                "classification": s.classification or "LOW",
                "created_at": s.created_at.isoformat() if s.created_at else None,
            }
            for s in recent_samples
        ]

        return {
            "total_analyses": total_samples,
            "low_risk_count": low_count,
            "medium_risk_count": med_count,
            "high_risk_count": high_count,
            "critical_risk_count": crit_count,
            "top_threat_indicators": {
                "suspicious_apis": susp_apis,
                "malicious_strings": susp_strings,
                "network_indicators": net_indicators,
                "registry_indicators": reg_indicators,
                "high_entropy": entropy_indicators,
            },
            "ioc_counts": {
                "total": ioc_total,
                "domains": ioc_domains,
                "ips": ioc_ips,
                "urls": ioc_urls,
                "hashes": ioc_hashes,
                "registry": ioc_registry,
            },
            "recent_activity": recent_activity,
        }
    finally:
        db.close()


@router.get(
    "/{analysis_id}",
    summary="Get full analysis results by ID",
    description="Fetches full multi-section evidence, PE headers, imports, strings, IOCs, risk factors, and AI interpretation."
)
def get_analysis_by_id(
    analysis_id: str,
    language: str = Query("en", description="'en' or 'am'"),
    current_user: Optional[UserModel] = Depends(get_optional_current_user)
):
    """Fetches complete structured analysis record with object-level authorization."""
    db = SessionLocal()
    try:
        sample = SampleRepository.get_by_analysis_id(db, analysis_id)
        if not sample:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis '{analysis_id}' not found."
            )

        # IDOR protection:
        if sample.user_id is not None and current_user is not None:
            if current_user.role != UserRole.ADMIN.value and sample.user_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You do not have permission to view this analysis."
                )

        # Build full evidence response
        return {
            "schema_version": "1.0",
            "analysis_id": sample.analysis_id,
            "filename": sample.filename,
            "language": language,
            "status": sample.status,
            "file_information": {
                "filename": sample.filename,
                "file_size": sample.size,
                "file_kind": sample.file_type,
                "machine_type": sample.architecture,
                "created_at": sample.created_at.isoformat() if sample.created_at else None,
            },
            "hashes": {
                "sha256": sample.sha256,
                "sha1": sample.sha1 or "N/A",
                "md5": sample.md5,
            },
            "pe_information": {
                "machine_architecture": sample.architecture,
                "file_type": sample.file_type,
                "subsystem": "Windows GUI",
                "entry_point": "0x00001000",
                "image_base": "0x00400000",
            },
            "sections": {
                "total_sections": len(sample.sections),
                "has_wx_sections": any("EXECUTE" in (s.characteristics or "") and "WRITE" in (s.characteristics or "") for s in sample.sections),
                "sections": [
                    {
                        "name": s.name,
                        "virtual_address": s.virtual_address,
                        "virtual_size": s.virtual_size,
                        "raw_size": s.raw_size,
                        "entropy": s.entropy,
                        "characteristics": s.characteristics,
                    }
                    for s in sample.sections
                ],
            },
            "imports": {
                "total_imports": len(sample.imports),
                "imports": [
                    {
                        "dll": imp.dll,
                        "api": imp.api,
                        "category": imp.category,
                        "risk_relevance": imp.risk_relevance,
                    }
                    for imp in sample.imports
                ],
            },
            "strings": {
                "total_strings": len(sample.strings),
                "urls": [s.value for s in sample.strings if s.category == "URL" or s.type == "URL"],
                "ip_addresses": [s.value for s in sample.strings if s.category == "IP_ADDRESS" or s.type == "IP_ADDRESS"],
                "domains": [s.value for s in sample.strings if s.category == "DOMAIN" or s.type == "DOMAIN"],
                "registry_paths": [s.value for s in sample.strings if s.category == "REGISTRY" or s.type == "REGISTRY_PATH"],
                "commands": [s.value for s in sample.strings if s.category in ("COMMAND", "CMD") or s.type == "COMMAND"],
                "powershell_references": [s.value for s in sample.strings if s.category == "POWERSHELL" or s.type == "POWERSHELL"],
                "dlls": [s.value for s in sample.strings if s.category == "DLL" or s.type == "DLL"],
                "apis": [s.value for s in sample.strings if s.category == "API" or s.type == "API"],
                "file_paths": [s.value for s in sample.strings if s.category == "FILE_PATH" or s.type == "FILE_PATH"],
                "emails": [s.value for s in sample.strings if s.category == "EMAIL" or s.type == "EMAIL"],
                "items": [
                    {
                        "id": s.id,
                        "value": s.value,
                        "encoding": s.encoding or "ASCII",
                        "offset": s.offset,
                        "offset_hex": f"0x{s.offset:08X}" if s.offset is not None else "0x00000000",
                        "category": s.category or s.type or "GENERAL",
                        "suspicious": bool(s.suspicious),
                        "severity": s.severity or "LOW",
                        "confidence": s.confidence or 1.0,
                        "reason": s.reason or "Standard string artifact",
                        "mitre_technique": s.mitre_technique,
                    }
                    for s in sample.strings
                ]
            },
            "indicators": {
                "total_indicators": len(sample.indicators),
                "indicators": [
                    {
                        "name": ind.name,
                        "category": ind.category,
                        "severity": ind.severity,
                        "evidence": ind.evidence,
                        "confidence": ind.confidence,
                    }
                    for ind in sample.indicators
                ],
            },
            "iocs": {
                "total_iocs": len(sample.iocs),
                "items": [
                    {
                        "type": ioc.type,
                        "value": ioc.value,
                        "source": ioc.source,
                        "confidence": ioc.confidence,
                    }
                    for ioc in sample.iocs
                ],
            },
            "yara_matches": {
                "available": True,
                "total_matches": len(sample.yara_matches),
                "matches": [
                    {
                        "rule_name": ym.rule_name,
                        "namespace": ym.namespace,
                        "tags": ym.tags.split(",") if ym.tags else [],
                        "description": ym.description or "",
                    }
                    for ym in sample.yara_matches
                ],
            },
            "risk_factors": [
                {
                    "name": rf.name,
                    "category": rf.category,
                    "severity": rf.severity,
                    "weight": rf.weight,
                    "evidence": rf.evidence or "",
                }
                for rf in sample.risk_factors
            ],
            "threat_score": {
                "score": sample.risk_score or (sample.analysis_results.risk_score if sample.analysis_results else 0),
                "risk_level": sample.classification or (sample.analysis_results.risk_level if sample.analysis_results else "LOW"),
            },
            "ai_assessment": {
                "assessment": sample.classification or (sample.analysis_results.risk_level if sample.analysis_results else "LOW"),
                "confidence": sample.analysis_results.ai_confidence if sample.analysis_results else "MEDIUM",
                "summary": sample.analysis_results.ai_summary if sample.analysis_results else "Static analysis complete.",
                "key_findings": [f"Heuristic Risk Score: {sample.risk_score or 0}/100."],
                "possible_benign_explanations": ["Standard software build or compiler optimization."],
                "recommended_investigation": ["Observe runtime behavior in an isolated sandbox."],
                "limitations": ["Static analysis evaluates capabilities without live execution."],
            }
        }
    finally:
        db.close()


@router.get(
    "/{analysis_id}/strings",
    summary="Get detailed extracted strings intelligence for analysis",
    description="Retrieves paginated, filtered, and categorized static strings with offsets, encodings, and detection reasons."
)
def get_analysis_strings(
    analysis_id: str,
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(50, ge=1, le=500, description="Items per page"),
    category: Optional[str] = Query(None, description="Filter by category"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    encoding: Optional[str] = Query(None, description="Filter by encoding (ASCII, UTF-16LE)"),
    suspicious_only: bool = Query(False, description="Show only suspicious strings"),
    search: Optional[str] = Query(None, description="Search term for string value, category, or reason"),
    sort_by: Optional[str] = Query("severity", description="Sort field: severity, offset, value, category"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    current_user: Optional[UserModel] = Depends(get_optional_current_user)
):
    """
    Retrieves rich categorized strings intelligence for a specific analysis with full pagination, search, and filtering.
    """
    db = SessionLocal()
    try:
        sample = SampleRepository.get_by_analysis_id(db, analysis_id)
        if not sample:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis '{analysis_id}' not found."
            )

        # IDOR protection:
        if sample.user_id is not None and current_user is not None:
            if current_user.role != UserRole.ADMIN.value and sample.user_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: You do not have permission to view strings for this analysis."
                )

        skip = (page - 1) * page_size
        total_strings = len(sample.strings)
        filtered_count = SampleRepository.count_strings_for_sample(
            db=db,
            sample_id=sample.id,
            category=category,
            severity=severity,
            encoding=encoding,
            suspicious_only=suspicious_only,
            search=search
        )

        db_strings = SampleRepository.get_strings_for_sample(
            db=db,
            sample_id=sample.id,
            skip=skip,
            limit=page_size,
            category=category,
            severity=severity,
            encoding=encoding,
            suspicious_only=suspicious_only,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order
        )

        statistics = SampleRepository.get_string_statistics_for_sample(db, sample.id)

        # AI / Heuristic contextual intelligence summary
        susp_count = statistics.get("suspicious_count", 0)
        urls_count = statistics.get("urls_count", 0)
        ips_count = statistics.get("ips_count", 0)
        ps_count = statistics.get("powershell_count", 0)
        cmd_count = statistics.get("commands_count", 0)
        reg_count = statistics.get("registry_count", 0)
        api_count = statistics.get("apis_count", 0)

        ai_bullets = []
        if ps_count > 0:
            ai_bullets.append(f"{ps_count} PowerShell execution / parameter references")
        if cmd_count > 0:
            ai_bullets.append(f"{cmd_count} CLI command execution strings")
        if urls_count > 0 or ips_count > 0:
            ai_bullets.append(f"{urls_count + ips_count} external network endpoints / IP targets")
        if reg_count > 0:
            ai_bullets.append(f"{reg_count} Windows Registry configuration / autorun keys")
        if api_count > 0:
            ai_bullets.append(f"{api_count} system APIs")

        if susp_count > 0:
            ai_summary = (
                f"Extracted {total_strings:,} strings ({statistics.get('ascii_count', 0):,} ASCII, {statistics.get('unicode_count', 0):,} Unicode). "
                f"Identified {susp_count} suspicious indicators ({', '.join(ai_bullets[:3])}). "
                "Defensive Assessment Note: Static strings provide essential forensic clues for threat scoping; however, string presence alone does not establish confirmed runtime malicious execution without dynamic verification."
            )
        else:
            ai_summary = (
                f"Extracted {total_strings:,} strings ({statistics.get('ascii_count', 0):,} ASCII, {statistics.get('unicode_count', 0):,} Unicode). "
                "No suspicious commands, autorun registry persistence keys, or known high-risk API identifiers were detected."
            )

        total_pages = max(1, (filtered_count + page_size - 1) // page_size)

        return {
            "analysis_id": sample.analysis_id,
            "filename": sample.filename,
            "sha256": sample.sha256,
            "file_size": sample.size,
            "status": sample.status,
            "total_strings": total_strings,
            "filtered_total": filtered_count,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "statistics": statistics,
            "ai_string_summary": ai_summary,
            "strings": [
                {
                    "id": s.id,
                    "value": s.value,
                    "encoding": s.encoding or "ASCII",
                    "offset": s.offset,
                    "offset_hex": f"0x{s.offset:08X}" if s.offset is not None else "0x00000000",
                    "category": s.category or s.type or "GENERAL",
                    "suspicious": bool(s.suspicious),
                    "severity": s.severity or "LOW",
                    "confidence": s.confidence or 1.0,
                    "reason": s.reason or "Standard string artifact",
                    "mitre_technique": s.mitre_technique,
                }
                for s in db_strings
            ]
        }
    finally:
        db.close()


@router.get(
    "/{analysis_id}/report",
    summary="Generate downloadable analysis report",
    description="Exports security report in HTML, JSON, Markdown, or Text format."
)
def get_analysis_report(
    analysis_id: str,
    format: str = Query("json", description="Format: json, html, markdown, text"),
    language: str = Query("en", description="Language: en or am"),
    current_user: Optional[UserModel] = Depends(get_optional_current_user)
):
    """Exports structured security report and logs the audit event."""
    data = get_analysis_by_id(analysis_id, language=language, current_user=current_user)

    # Log report generation
    audit_logger.log_report_generation(
        analysis_id=analysis_id,
        report_format=format.upper(),
        result=AuditResult.SUCCESS,
        details={"language": language, "format": format.upper()}
    )

    fmt = format.lower()
    if fmt == "html":
        html_content = generate_html_report_view(data, language=language)
        return HTMLResponse(content=html_content)
    elif fmt == "markdown" or fmt == "md":
        md_content = generate_markdown_report_view(data, language=language)
        return PlainTextResponse(content=md_content, media_type="text/markdown")
    elif fmt == "text" or fmt == "txt":
        txt_content = generate_text_report_view(data, language=language)
        return PlainTextResponse(content=txt_content)
    else:
        return data


@router.delete(
    "/{analysis_id}",
    summary="Delete an analysis record",
    description="Deletes sample and all associated database records (Sections, Imports, Strings, IOCs, Indicators)."
)
def delete_analysis(
    analysis_id: str,
    current_user: UserModel = Depends(get_current_user)
):
    """Deletes analysis record with RBAC and ownership authorization."""
    db = SessionLocal()
    try:
        sample = SampleRepository.get_by_analysis_id(db, analysis_id)
        if not sample:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Analysis '{analysis_id}' not found."
            )

        if current_user.role != UserRole.ADMIN.value and sample.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You cannot delete analyses created by other users."
            )

        SampleRepository.delete_sample(db, sample.id)
        return {
            "message": f"Analysis '{analysis_id}' deleted successfully.",
            "analysis_id": analysis_id
        }
    finally:
        db.close()


def generate_html_report_view(data: Dict[str, Any], language: str = "en") -> str:
    """Renders a clean, standalone HTML executive report."""
    fi = data.get("file_information", {})
    hashes = data.get("hashes", {})
    ts = data.get("threat_score", {})
    ai = data.get("ai_assessment", {})
    sections = data.get("sections", {}).get("sections", [])
    imports = data.get("imports", {}).get("imports", [])
    indicators = data.get("indicators", {}).get("indicators", [])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ETHIO-AI Defender Security Report - {data.get("analysis_id")}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; line-height: 1.6; }}
        .header {{ border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
        .title {{ font-size: 24px; font-weight: 700; color: #38bdf8; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 12px; }}
        .badge-crit {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid #f97316; }}
        .badge-low {{ background: rgba(34, 197, 94, 0.2); color: #22c55e; border: 1px solid #22c55e; }}
        .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
        .card-title {{ font-size: 16px; font-weight: 700; color: #38bdf8; margin-bottom: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; font-weight: 600; }}
        .mono {{ font-family: monospace; font-size: 12px; color: #38bdf8; }}
        .disclaimer {{ font-size: 11px; color: #94a3b8; border-top: 1px solid #334155; padding-top: 15px; margin-top: 30px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">ETHIO-AI DEFENDER | STATIC SECURITY REPORT</div>
            <div style="color: #94a3b8; font-size: 13px;">Analysis ID: {data.get("analysis_id")} • Generated on: {fi.get("created_at", "N/A")}</div>
        </div>
        <div>
            <span class="badge {'badge-crit' if ts.get('risk_level') == 'CRITICAL' else ('badge-high' if ts.get('risk_level') == 'HIGH' else 'badge-low')}">
                {ts.get('risk_level', 'LOW')} ({ts.get('score', 0)}/100)
            </span>
        </div>
    </div>

    <div class="card">
        <div class="card-title">1. File Identification & Metadata</div>
        <table>
            <tr><th>Filename</th><td>{fi.get("filename")}</td><th>File Size</th><td>{fi.get("file_size")} bytes</td></tr>
            <tr><th>Architecture</th><td>{fi.get("machine_type")}</td><th>File Format</th><td>{fi.get("file_kind")}</td></tr>
            <tr><th>SHA-256</th><td colspan="3" class="mono">{hashes.get("sha256")}</td></tr>
            <tr><th>MD5</th><td colspan="3" class="mono">{hashes.get("md5")}</td></tr>
        </table>
    </div>

    <div class="card">
        <div class="card-title">2. AI Security Interpretation</div>
        <p><strong>Executive Summary:</strong> {ai.get("summary")}</p>
        <p><strong>Confidence:</strong> {ai.get("confidence", "MEDIUM")}</p>
    </div>

    <div class="card">
        <div class="card-title">3. Correlated Threat Indicators ({len(indicators)})</div>
        <table>
            <thead><tr><th>Indicator Name</th><th>Category</th><th>Severity</th><th>Evidence</th></tr></thead>
            <tbody>
                {''.join(f"<tr><td>{ind.get('name')}</td><td>{ind.get('category')}</td><td>{ind.get('severity')}</td><td>{ind.get('evidence')}</td></tr>" for ind in indicators) if indicators else '<tr><td colspan="4">No high-risk indicators detected.</td></tr>'}
            </tbody>
        </table>
    </div>

    <div class="card">
        <div class="card-title">4. PE Sections ({len(sections)})</div>
        <table>
            <thead><tr><th>Name</th><th>Virtual Addr</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th><th>Permissions</th></tr></thead>
            <tbody>
                {''.join(f"<tr><td class='mono'>{s.get('name')}</td><td>{s.get('virtual_address')}</td><td>{s.get('virtual_size')}</td><td>{s.get('raw_size')}</td><td>{s.get('entropy'):.2f}</td><td>{s.get('characteristics')}</td></tr>" for s in sections)}
            </tbody>
        </table>
    </div>

    <div class="disclaimer">
        <strong>Defensive Static Analysis Guarantee:</strong> This report was generated statically without binary runtime execution.
        Risk score is an evidence-backed heuristic metric.
    </div>
</body>
</html>"""


def generate_markdown_report_view(data: Dict[str, Any], language: str = "en") -> str:
    """Renders a structured Markdown report."""
    fi = data.get("file_information", {})
    hashes = data.get("hashes", {})
    ts = data.get("threat_score", {})
    ai = data.get("ai_assessment", {})
    indicators = data.get("indicators", {}).get("indicators", [])

    return f"""# ETHIO-AI Defender Security Report

**Analysis ID:** `{data.get("analysis_id")}`  
**Filename:** `{fi.get("filename")}`  
**Risk Level:** **{ts.get("risk_level", "LOW")}** ({ts.get("score", 0)}/100)  
**SHA-256:** `{hashes.get("sha256")}`  
**MD5:** `{hashes.get("md5")}`  

---

## Executive Summary
{ai.get("summary", "N/A")}

**Confidence:** {ai.get("confidence", "MEDIUM")}

---

## Correlated Threat Indicators ({len(indicators)})
{chr(10).join(f"- **{ind.get('name')}** [{ind.get('severity')}] ({ind.get('category')}): {ind.get('evidence')}" for ind in indicators) if indicators else "No suspicious indicators detected."}

---
*Generated by ETHIO-AI Defender Static Reverse-Engineering Platform (Zero-Execution).*
"""


def generate_text_report_view(data: Dict[str, Any], language: str = "en") -> str:
    """Renders a clean plain text report."""
    fi = data.get("file_information", {})
    hashes = data.get("hashes", {})
    ts = data.get("threat_score", {})
    ai = data.get("ai_assessment", {})

    return f"""================================================================================
ETHIO-AI DEFENDER - STATIC SECURITY ANALYSIS REPORT
================================================================================
Analysis ID  : {data.get("analysis_id")}
Filename     : {fi.get("filename")}
File Size    : {fi.get("file_size")} bytes
Architecture : {fi.get("machine_type")}
Risk Tier    : {ts.get("risk_level", "LOW")} ({ts.get("score", 0)}/100)

HASHES:
SHA-256      : {hashes.get("sha256")}
MD5          : {hashes.get("md5")}

AI SUMMARY:
{ai.get("summary", "N/A")}

Zero-Execution Static Guarantee Enforced.
================================================================================
"""
