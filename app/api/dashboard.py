"""
Dashboard API Endpoints for ETHIO-AI Defender

Provides endpoints for:
- Uploading and running full static analysis pipeline across Modules 01 to 14
- Retrieving full multi-section analysis details for the 8 dashboard views
- Listing analyzed samples
"""

from fastapi import APIRouter, UploadFile, File, HTTPException, Query, status
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

from app.db.session import SessionLocal
from app.db.repository import SampleRepository
from app.db.schemas import (
    SampleCreate,
    SectionCreate,
    ImportCreate,
    StringCreate,
    IndicatorCreate,
    AnalysisResultCreate,
)

router = APIRouter(prefix="/api/dashboard", tags=["Defensive Dashboard"])


def run_full_analysis_pipeline(content: bytes, filename: str, language: str = "en") -> Dict[str, Any]:
    """
    Orchestrates the complete deterministic analysis, AI assessment, learning lessons,
    and database persistence across all modules.
    """
    lang = "am" if language.lower() in ("am", "amharic") else "en"

    # 1. Intake & Perimeter Validation (Module 01)
    intake_res = secure_intake_service.process_bytes(content, raw_filename=filename)
    if not intake_res.is_success:
        raise ValueError(f"Intake validation failed: {intake_res.message}")

    analysis_id = intake_res.analysis_id or "ANL-UNKNOWN"
    safe_filename = intake_res.filename
    quarantine_path = intake_res.secure_storage_path

    # 2. Cryptographic Hashing (Module 02)
    hash_data = {
        "md5": intake_res.md5,
        "sha1": intake_res.sha1,
        "sha256": intake_res.sha256
    }

    # 3. PE Static Header Analysis (Module 03)
    pe_res = pe_static_analyzer_service.analyze_bytes(content)
    pe_data = pe_res.to_dict()

    # 4. PE Section Analysis (Module 04)
    sec_res = pe_section_analyzer_service.analyze_bytes(content)
    sec_data = sec_res.to_dict()

    # 5. Shannon Entropy Analysis (Module 05)
    ent_res = entropy_analyzer_service.analyze_bytes(content)
    ent_data = ent_res.to_dict()

    # 6. String Extraction & Classification (Module 06)
    str_res = string_analyzer_service.analyze_bytes(content)
    str_data = str_res.to_dict()

    # 7. Windows API Import Analysis (Module 07)
    imp_res = windows_api_import_analyzer_service.analyze_bytes(content)
    imp_data = imp_res.to_dict()

    # 8. Suspicious Indicator Engine (Module 08)
    ind_res = suspicious_indicator_engine_service.evaluate(
        pe=pe_res,
        sections=sec_res,
        entropy=ent_res,
        strings=str_res,
        imports=imp_res
    )
    ind_data = ind_res.to_dict()

    # 9. Threat Scoring Engine (Module 09)
    score_res = threat_scoring_engine_service.calculate_score(ind_res.indicators)
    score_data = score_res.to_dict()

    # 10. Ethiopian Cybersecurity Context Engine (Module 10)
    ethio_res = ethiopian_context_engine_service.analyze_context(
        indicators=ind_res.indicators,
        strings=str_res,
        threat_score=score_res.score,
        language=lang
    )
    ethio_data = ethio_res.to_dict()

    # Structured static evidence payload
    full_evidence = {
        "file_metadata": {
            "filename": safe_filename,
            "file_size": intake_res.size,
            "file_kind": pe_data.get("file_type", "EXE"),
            "machine_type": pe_data.get("machine_architecture", "x64"),
            "compile_time": pe_data.get("compile_time", "N/A")
        },
        "hashes": hash_data,
        "pe_information": pe_data,
        "sections": sec_data,
        "entropy": ent_data,
        "strings": str_data,
        "imports": imp_data,
        "indicators": ind_data,
        "threat_score": score_data,
        "ethiopian_context": ethio_data
    }

    # 11. AI Security Analyst (Module 11)
    ai_report = ai_security_analyst_service.analyze(full_evidence, language=lang)
    ai_data = ai_report.to_dict()

    # 12. Cybersecurity Learning Mode (Module 12)
    learning_report = learning_mode_service.generate_learning_report(full_evidence, language=lang)
    learning_data = learning_report.to_dict()

    # 13. Security Report Generation (Module 13)
    security_report = security_report_generator_service.generate_report(
        evidence=full_evidence,
        ai_report=ai_report,
        language=lang,
        report_id=f"REP-{analysis_id}"
    )

    # 14. Database Persistence (Module 14)
    db = SessionLocal()
    try:
        sample_in = SampleCreate(
            analysis_id=analysis_id,
            filename=safe_filename,
            size=intake_res.size,
            file_type=pe_data.get("file_type", "EXE"),
            architecture=pe_data.get("machine_architecture", "x64"),
            md5=intake_res.md5,
            sha256=intake_res.sha256,
            status="ANALYZED"
        )
        sections_in = [
            SectionCreate(
                name=s["name"],
                virtual_address=s["virtual_address"],
                virtual_size=s["virtual_size"],
                raw_size=s["raw_size"],
                entropy=s["entropy"],
                characteristics=s["characteristics"]
            )
            for s in sec_data.get("sections", [])
        ]
        imports_in = [
            ImportCreate(
                dll=i["dll"],
                api=i["api"],
                category=i.get("category", "GENERAL"),
                risk_relevance=i.get("risk_relevance", "LOW")
            )
            for i in imp_data.get("imports", [])[:50]
        ]
        strings_in = [
            StringCreate(value=u, type="URL") for u in str_data.get("urls", [])[:10]
        ] + [
            StringCreate(value=ip, type="IP_ADDRESS") for ip in str_data.get("ip_addresses", [])[:10]
        ] + [
            StringCreate(value=r, type="REGISTRY_PATH") for r in str_data.get("registry_paths", [])[:10]
        ]
        indicators_in = [
            IndicatorCreate(
                name=ind.get("name", "Indicator"),
                category=ind.get("category", "PE_STRUCTURE"),
                severity=ind.get("severity", "LOW"),
                evidence=ind.get("evidence", ""),
                confidence=ind.get("confidence", 1.0)
            )
            for ind in ind_data.get("indicators", [])
        ]
        result_in = AnalysisResultCreate(
            risk_score=score_data.get("score", 0),
            risk_level=score_data.get("risk_level", "LOW"),
            ai_summary=ai_data.get("summary", ""),
            ai_confidence=ai_data.get("confidence", "MEDIUM")
        )

        SampleRepository.save_full_analysis_transaction(
            db=db,
            sample_in=sample_in,
            sections_in=sections_in,
            imports_in=imports_in,
            strings_in=strings_in,
            indicators_in=indicators_in,
            result_in=result_in
        )
    except Exception as db_err:
        logger.warning(f"Database save warning (sample may already exist): {db_err}")
    finally:
        db.close()

    # Consolidate unified payload for Dashboard views
    return {
        "analysis_id": analysis_id,
        "filename": safe_filename,
        "language": lang,
        "file_information": full_evidence["file_metadata"],
        "hashes": hash_data,
        "pe_information": pe_data,
        "sections": sec_data,
        "entropy": ent_data,
        "strings": str_data,
        "imports": imp_data,
        "indicators": ind_data,
        "threat_score": score_data,
        "ethiopian_context": ethio_data,
        "ai_assessment": ai_data,
        "learning_mode": learning_data,
        "report": security_report.to_dict()
    }


@router.post("/analyze", summary="Upload and execute complete defensive analysis")
async def analyze_upload(
    file: UploadFile = File(...),
    language: str = Query("en", description="'en' for English, 'am' for Amharic")
):
    """
    Accepts PE binary, validates perimeter, orchestrates full multi-module analysis,
    and returns comprehensive results for the 8 dashboard views.
    """
    raw_filename = file.filename or "sample.exe"
    logger.info(f"Incoming dashboard analysis request for '{raw_filename}' (Lang: {language})")

    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Could not read upload payload: {e}"
        )

    try:
        result = run_full_analysis_pipeline(content, filename=raw_filename, language=language)
        return result
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as ex:
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
def get_sample_full(analysis_id: str, language: str = "en"):
    """Fetches full analysis details for a given analysis ID."""
    db = SessionLocal()
    try:
        sample = SampleRepository.get_by_analysis_id(db, analysis_id)
        if not sample:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sample '{analysis_id}' not found.")

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
            }
        }
    finally:
        db.close()
