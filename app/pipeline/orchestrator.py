"""
ETHIO-AI Defender - Module 19: Unified Analysis Pipeline Orchestrator.
Coordinates the entire deterministic static analysis pipeline, AI assessment, learning center, database storage, and reporting.
Includes comprehensive stage-by-stage error containment to ensure system resilience on malformed files.
"""

from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime, timezone

from app.core.logger import logger
from app.core.config import settings
from app.analyzers.file_intake import secure_intake_service, IntakeResult, IntakeStatus
from app.analyzers.hash_analyzer import hash_analyzer_service
from app.analyzers.pe_analyzer import pe_static_analyzer_service, PEAnalysisResult
from app.analyzers.section_analyzer import pe_section_analyzer_service, PESectionAnalysisResult
from app.analyzers.entropy_analyzer import entropy_analyzer_service, EntropyAnalysisResult
from app.analyzers.string_analyzer import string_analyzer_service, StringAnalysisResult
from app.analyzers.import_analyzer import windows_api_import_analyzer_service, ImportAnalysisResult
from app.analyzers.indicator_engine import suspicious_indicator_engine_service, IndicatorAnalysisResult
from app.analyzers.threat_scoring import threat_scoring_engine_service, ThreatScoreResult
from app.analyzers.ethiopian_context import ethiopian_context_engine_service, EthiopianContextAnalysisResult
from app.ai.analyst import ai_security_analyst_service
from app.education.learning_mode import learning_mode_service
from app.reports.generator import security_report_generator_service
from app.audit.logger import audit_logger
from app.audit.events import AuditResult, AuditEventType

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
from app.pipeline.models import (
    AnalysisSectionList,
    AnalysisImportList,
    AnalysisIndicatorList,
)


class UnifiedPipelineOrchestrator:
    """
    Module 19 Master Pipeline Orchestrator.
    Executes the comprehensive 15-stage analysis pipeline with defensive error shielding.
    """

    def execute_pipeline(
        self,
        content: bytes,
        filename: str = "sample.exe",
        language: str = "en",
        user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes the full pipeline and constructs the Unified Analysis Object.
        Guarantees non-execution of binary and graceful degradation on analyzer errors.
        """
        lang = "am" if language.lower() in ("am", "amharic") else "en"
        errors: List[str] = []

        # =========================================================================
        # Stage 1 & 2: Secure File Intake & Perimeter Validation (Module 01)
        # =========================================================================
        intake_res = secure_intake_service.process_bytes(content, raw_filename=filename)
        if not intake_res.is_success:
            audit_logger.log_analysis_failure(
                analysis_id="UNKNOWN",
                filename=filename,
                error=f"Perimeter validation failed: {intake_res.message}",
            )
            raise ValueError(f"Intake validation failed: {intake_res.message}")

        analysis_id = intake_res.analysis_id or "ANL-UNKNOWN"
        safe_filename = intake_res.filename

        # Log analysis start in security audit trail
        audit_logger.log_analysis_start(
            analysis_id=analysis_id,
            filename=safe_filename,
            details={"language": lang, "sha256": intake_res.sha256},
        )

        # =========================================================================
        # Stage 3: Cryptographic Hashing (Module 02)
        # =========================================================================
        try:
            hash_res = hash_analyzer_service.compute_from_bytes(content)
            hash_data = hash_res.to_dict()
        except Exception as e:
            err_msg = f"Hash Analyzer Error: {e}"
            errors.append(err_msg)
            logger.warning(err_msg)
            hash_data = {
                "md5": intake_res.md5,
                "sha1": intake_res.sha1,
                "sha256": intake_res.sha256,
            }

        # =========================================================================
        # Stage 4: PE Static Header Analysis (Module 03)
        # =========================================================================
        try:
            pe_res = pe_static_analyzer_service.analyze_bytes(content)
            pe_data = pe_res.to_dict()
            pe_data["file_type"] = pe_data.get("file_kind", "EXE")
            pe_data["machine_architecture"] = pe_data.get("architecture", "x64")
            pe_data["is_dll"] = pe_data.get("file_kind") == "DLL" or "IMAGE_FILE_DLL" in pe_data.get("characteristics", [])
        except Exception as e:
            err_msg = f"PE Static Analyzer Error: {e}"
            errors.append(err_msg)
            logger.warning(err_msg)
            pe_res = PEAnalysisResult(
                is_valid=False,
                error_message=str(e),
                file_type="UNKNOWN",
                machine_architecture="UNKNOWN",
            )
            pe_data = pe_res.to_dict()
            pe_data["file_type"] = "UNKNOWN"
            pe_data["machine_architecture"] = "UNKNOWN"

        # =========================================================================
        # Stage 5: PE Section Analysis (Module 04)
        # =========================================================================
        try:
            sec_res = pe_section_analyzer_service.analyze_bytes(content)
            raw_sec_dict = sec_res.to_dict()
            sections_raw_list = raw_sec_dict.get("sections", [])
            has_wx = raw_sec_dict.get("has_wx_sections", False)
            total_sec = raw_sec_dict.get("total_sections", len(sections_raw_list))
        except Exception as e:
            err_msg = f"Section Analyzer Error: {e}"
            errors.append(err_msg)
            logger.warning(err_msg)
            sec_res = PESectionAnalysisResult(total_sections=0, sections=[])
            sections_raw_list = []
            has_wx = False
            total_sec = 0

        # Wrap in dual-interface list
        sections_collection = AnalysisSectionList(
            items=sections_raw_list,
            total_sections=total_sec,
            has_wx_sections=has_wx
        )

        # =========================================================================
        # Stage 6: Shannon Entropy Analysis (Module 05)
        # =========================================================================
        try:
            ent_res = entropy_analyzer_service.analyze_bytes(content)
            ent_data = ent_res.to_dict()
            ent_data["status"] = "SUCCESS"
        except Exception as e:
            err_msg = f"Entropy Analyzer Error: {e}"
            errors.append(err_msg)
            logger.warning(err_msg)
            ent_res = EntropyAnalysisResult(file_entropy=0.0, file_classification="UNKNOWN", sections=[])
            ent_data = {
                "status": "FAILED",
                "error_code": "ENTROPY_ANALYSIS_ERROR",
                "file_entropy": 0.0,
                "file_classification": "UNKNOWN",
                "block_distribution": [],
            }

        # =========================================================================
        # Stage 7: String Extraction & Classification (Module 06)
        # =========================================================================
        try:
            str_res = string_analyzer_service.analyze_bytes(content)
            str_data = str_res.to_dict()
            str_data["status"] = "SUCCESS"
        except Exception as e:
            err_msg = f"String Analyzer Error: {e}"
            errors.append(err_msg)
            logger.warning(err_msg)
            str_res = StringAnalysisResult(
                total_strings=0,
                urls=[],
                ip_addresses=[],
                registry_paths=[],
                commands=[],
            )
            str_data = {
                "status": "FAILED",
                "error_code": "STRING_ANALYSIS_ERROR",
                "total_strings": 0,
                "urls": [],
                "ip_addresses": [],
                "registry_paths": [],
                "commands": [],
            }

        # =========================================================================
        # Stage 8: Windows API Import Analysis (Module 07)
        # =========================================================================
        imp_status = "SUCCESS"
        imp_err_code = None
        try:
            imp_res = windows_api_import_analyzer_service.analyze_bytes(content)
            raw_imp_dict = imp_res.to_dict()
            imports_raw_list = raw_imp_dict.get("imports", [])
            total_imp = raw_imp_dict.get("total_imports", len(imports_raw_list))
        except Exception as e:
            err_msg = f"Import Analyzer Error: {e}"
            errors.append(err_msg)
            logger.warning(err_msg)
            imp_res = ImportAnalysisResult(total_imports=0, imports=[])
            imports_raw_list = []
            total_imp = 0
            imp_status = "FAILED"
            imp_err_code = "IMPORT_ANALYSIS_ERROR"

        # Wrap in dual-interface list
        imports_collection = AnalysisImportList(
            items=imports_raw_list,
            total_imports=total_imp,
            status=imp_status,
            error_code=imp_err_code
        )

        # =========================================================================
        # Stage 9: Suspicious Indicator Engine (Module 08)
        # =========================================================================
        ind_status = "SUCCESS"
        ind_err_code = None
        try:
            ind_res = suspicious_indicator_engine_service.evaluate(
                pe=pe_res,
                sections=sec_res,
                entropy=ent_res,
                strings=str_res,
                imports=imp_res
            )
            raw_ind_dict = ind_res.to_dict()
            indicators_raw_list = raw_ind_dict.get("indicators", [])
            total_ind = raw_ind_dict.get("total_indicators", len(indicators_raw_list))
        except Exception as e:
            err_msg = f"Indicator Engine Error: {e}"
            errors.append(err_msg)
            logger.warning(err_msg)
            ind_res = IndicatorAnalysisResult(total_indicators=0, indicators=[])
            indicators_raw_list = []
            total_ind = 0
            ind_status = "FAILED"
            ind_err_code = "INDICATOR_ENGINE_ERROR"

        # Wrap in dual-interface list
        indicators_collection = AnalysisIndicatorList(
            items=indicators_raw_list,
            total_indicators=total_ind,
            status=ind_status,
            error_code=ind_err_code
        )

        # =========================================================================
        # Stage 10: Threat Scoring Engine (Module 09)
        # =========================================================================
        try:
            score_res = threat_scoring_engine_service.calculate_score(ind_res.indicators)
            score_data = score_res.to_dict()
            score_data["status"] = "SUCCESS"
        except Exception as e:
            err_msg = f"Threat Scoring Engine Error: {e}"
            errors.append(err_msg)
            logger.warning(err_msg)
            score_res = ThreatScoreResult(score=0, risk_level="LOW", category_breakdown={}, mitre_tactics=[])
            score_data = {
                "status": "FAILED",
                "error_code": "THREAT_SCORING_ERROR",
                "score": 0,
                "risk_level": "LOW",
                "category_breakdown": {},
                "mitre_tactics": [],
            }

        # =========================================================================
        # Stage 11: Ethiopian Cybersecurity Context Engine (Module 10)
        # =========================================================================
        try:
            ethio_res = ethiopian_context_engine_service.analyze_context(
                indicators=ind_res.indicators,
                strings=str_res,
                threat_score=score_res.score,
                language=lang
            )
            ethio_data = ethio_res.to_dict()
            ethio_data["status"] = "SUCCESS"
        except Exception as e:
            err_msg = f"Ethiopian Context Engine Error: {e}"
            errors.append(err_msg)
            logger.warning(err_msg)
            ethio_res = EthiopianContextAnalysisResult(
                environment="GENERAL",
                relevance="LOW",
                reason=f"Context analysis fallback: {e}",
            )
            ethio_data = {
                "status": "FAILED",
                "error_code": "ETHIOPIAN_CONTEXT_ERROR",
                "environment": "GENERAL",
                "relevance": "LOW",
                "reason": f"Context analysis fallback: {e}",
                "language": lang,
            }

        # =========================================================================
        # Stage 11b: YARA Signature Scanning
        # =========================================================================
        try:
            from app.analyzers.yara_analyzer import yara_analyzer_service
            from app.db.session import SessionLocal
            # Try DB-driven scanning first; fall back to filesystem on any issue
            db_session = SessionLocal()
            try:
                yara_res = yara_analyzer_service.scan_bytes_with_db_rules(content, db=db_session)
                yara_data = yara_res.to_dict()
            finally:
                db_session.close()
        except Exception as e:
            logger.warning(f"YARA Analyzer warning: {e}")
            yara_data = {
                "available": False,
                "status": "UNAVAILABLE",
                "message": f"YARA scan fallback: {e}",
                "total_matches": 0,
                "matches": []
            }

        # =========================================================================
        # Stage 11d: Machine Learning Offline Static Analysis (Shadow Mode)
        # =========================================================================
        shadow_mode = getattr(settings, "ML_SHADOW_MODE", True)
        ml_data = {
            "available": False,
            "status": "DISABLED",
            "message": "ML analysis is disabled by default configuration (ML_ENABLED=false).",
            "malicious_score": None,
            "is_malicious": None,
            "is_reliable": False,
            "shadow_mode": shadow_mode,
        }
        if getattr(settings, "ML_ENABLED", False):
            try:
                from app.analyzers.ml_analyzer import ml_analyzer_service
                ml_res = ml_analyzer_service.analyze_pe_bytes(content)
                ml_data = ml_res.to_dict()
                ml_data["shadow_mode"] = shadow_mode
                if not shadow_mode:
                    ml_data["active_blocking_inhibited"] = True
                    ml_data["policy_notice"] = (
                        "Active blocking via ML is prohibited while raw-PE feature parity remains unverified. "
                        "Execution constrained safely to non-blocking telemetry."
                    )
            except Exception as e:
                logger.warning("ML Analyzer warning during analysis.")
                clean_err = f"ML execution failed: {type(e).__name__}"
                ml_data = {
                    "available": False,
                    "status": "FAILED",
                    "message": "ML analysis encountered an internal error.",
                    "malicious_score": None,
                    "is_malicious": None,
                    "is_reliable": False,
                    "shadow_mode": shadow_mode,
                    "error": clean_err,
                }

        # =========================================================================
        # Stage 11c: IOC Extraction & MITRE ATT&CK Mapping
        # =========================================================================
        iocs_list = []
        seen_iocs = set()

        def add_ioc(ioc_type: str, val: str, source: str = "STATIC_ANALYSIS", confidence: float = 1.0):
            if not val or not isinstance(val, str) or not val.strip():
                return
            val_clean = val.strip()
            key = (ioc_type, val_clean)
            if key not in seen_iocs:
                seen_iocs.add(key)
                iocs_list.append({
                    "type": ioc_type,
                    "value": val_clean,
                    "source": source,
                    "confidence": confidence
                })

        # Hashes
        if hash_data.get("sha256"):
            add_ioc("HASH", hash_data["sha256"], "HASH_ANALYZER", 1.0)
        if hash_data.get("sha1"):
            add_ioc("HASH", hash_data["sha1"], "HASH_ANALYZER", 1.0)
        if hash_data.get("md5"):
            add_ioc("HASH", hash_data["md5"], "HASH_ANALYZER", 1.0)

        # Extracted strings
        for u in str_data.get("urls", []):
            add_ioc("URL", u, "STRING_EXTRACTION", 0.95)
        for ip in str_data.get("ip_addresses", []):
            add_ioc("IP", ip, "STRING_EXTRACTION", 0.95)
        for dom in str_data.get("domains", []):
            add_ioc("DOMAIN", dom, "STRING_EXTRACTION", 0.90)
        for em in str_data.get("emails", []):
            add_ioc("EMAIL", em, "STRING_EXTRACTION", 0.90)
        for r in str_data.get("registry_paths", []):
            add_ioc("REGISTRY_KEY", r, "STRING_EXTRACTION", 0.90)
        for fp in str_data.get("file_paths", []):
            add_ioc("FILE_PATH", fp, "STRING_EXTRACTION", 0.90)

        # MITRE ATT&CK Mappings (Configurable heuristic correlation)
        mitre_mappings = []
        mitre_seen = set()

        def add_mitre(t_id: str, t_name: str, tactic: str, evidence: str, conf: str = "MEDIUM"):
            if t_id not in mitre_seen:
                mitre_seen.add(t_id)
                mitre_mappings.append({
                    "technique_id": t_id,
                    "technique_name": t_name,
                    "tactic": tactic,
                    "evidence": evidence,
                    "confidence": conf,
                    "relationship": "Potentially associated with"
                })

        apis_lower = {i.get("api", "").lower() for i in imports_raw_list}
        if "virtualalloc" in apis_lower or "virtualprotect" in apis_lower or "writeprocessmemory" in apis_lower:
            add_mitre("T1055", "Process Injection", "Defense Evasion, Privilege Escalation", "VirtualAlloc/VirtualProtect/WriteProcessMemory imported", "HIGH")
        if "createremotethread" in apis_lower or "queueuserapc" in apis_lower:
            add_mitre("T1055.002", "Process Injection: Portable Executable Injection", "Defense Evasion", "CreateRemoteThread/QueueUserAPC imported", "HIGH")
        if "regsetvalueexa" in apis_lower or "regsetvaluew" in apis_lower or str_data.get("registry_paths"):
            add_mitre("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence", "Registry persistence API or Run key extracted", "MEDIUM")
        if "urldownloadtofilea" in apis_lower or "urldownloadtofilew" in apis_lower or "internetopenurla" in apis_lower:
            add_mitre("T1105", "Ingress Tool Transfer", "Command and Control", "URLDownloadToFile/InternetOpenUrl API imported", "HIGH")
        if "isdebuggerpresent" in apis_lower or "checkremotedebuggerpresent" in apis_lower:
            add_mitre("T1497", "Virtualization/Sandbox Evasion", "Defense Evasion", "Anti-debugging API imported", "MEDIUM")
        if has_wx or ent_data.get("file_classification") in ("HIGH", "VERY_HIGH"):
            add_mitre("T1027.002", "Obfuscated Files or Information: Software Packing", "Defense Evasion", "High entropy or W+X section detected", "HIGH")
        if str_data.get("commands") or str_data.get("powershell_references"):
            add_mitre("T1059.001", "Command and Scripting Interpreter: PowerShell / Command Shell", "Execution", "PowerShell/cmd.exe string references identified", "HIGH")

        # Risk Factors list
        risk_factors_list = []
        for contrib in getattr(score_res, "contributions", []):
            risk_factors_list.append({
                "name": contrib.indicator_name,
                "category": contrib.category,
                "severity": contrib.severity,
                "weight": contrib.points,
                "evidence": contrib.reason
            })

        # =========================================================================
        # Stage 11d: Ghidra Headless Static Reverse-Engineering (Module 20)
        # =========================================================================
        ghidra_data = {
            "available": False,
            "status": "UNAVAILABLE",
            "message": "Ghidra analysis was not executed.",
            "function_count": 0,
            "functions": [],
        }
        try:
            from app.analyzers.ghidra_analyzer import ghidra_analyzer_service
            ghidra_res = ghidra_analyzer_service.analyze_file(
                intake_res.secure_storage_path,
                analysis_id=analysis_id,
            )
            ghidra_data = ghidra_res.to_dict()
        except Exception as e:
            logger.warning(f"Ghidra Analyzer warning: {e}")
            ghidra_data = {
                "available": False,
                "status": "FAILED",
                "message": f"Ghidra analysis fallback: {e}",
                "function_count": 0,
                "functions": [],
            }

        # Build Observed Static Evidence (Strictly Distinguishes Observed vs Rule vs AI)
        file_info = {
            "filename": safe_filename,
            "file_size": intake_res.size,
            "file_kind": pe_data.get("file_type", "EXE"),
            "machine_type": pe_data.get("machine_architecture", "x64"),
            "compile_time": pe_data.get("compile_time", "N/A"),
        }

        full_evidence = {
            "file_metadata": file_info,
            "hashes": hash_data,
            "pe_information": pe_data,
            "sections": {"total_sections": total_sec, "sections": list(sections_collection), "has_wx_sections": has_wx},
            "entropy": ent_data,
            "strings": str_data,
            "imports": {"total_imports": total_imp, "imports": list(imports_collection)},
            "indicators": {"total_indicators": total_ind, "indicators": list(indicators_collection)},
            "iocs": {"total_iocs": len(iocs_list), "items": iocs_list},
            "yara_matches": yara_data,
            "mitre_attack": mitre_mappings,
            "risk_factors": risk_factors_list,
            "threat_score": score_data,
            "ethiopian_context": ethio_data,
            "ghidra": ghidra_data,
        }

        # =========================================================================
        # Stage 12: AI Security Analyst Assessment (Module 11)
        # =========================================================================
        ai_report = None
        try:
            ai_report = ai_security_analyst_service.analyze(full_evidence, language=lang)
            ai_data = ai_report.to_dict()
            ai_data["status"] = "SUCCESS"
        except Exception as e:
            err_msg = f"AI Security Analyst Warning: {e}"
            errors.append(err_msg)
            logger.warning(err_msg)
            ai_data = {
                "status": "UNAVAILABLE",
                "reason": "AI provider unavailable",
                "assessment": score_data.get("risk_level", "LOW"),
                "confidence": "LOW",
                "summary": "AI analysis unavailable. Static analysis results are available.",
                "key_findings": [f"Heuristic Threat Score: {score_data.get('score', 0)}/100 [{score_data.get('risk_level', 'LOW')}]."],
                "evidence": ["Static binary headers analyzed."],
                "possible_benign_explanations": ["Standard software executable."],
                "recommended_investigation": ["Review binary signatures."],
                "limitations": ["Static analysis only; no dynamic execution performed."],
            }

        # =========================================================================
        # Stage 13: Cybersecurity Learning Mode (Module 12)
        # =========================================================================
        try:
            learning_report = learning_mode_service.generate_learning_report(full_evidence, language=lang)
            learning_data = learning_report.to_dict()
        except Exception as e:
            logger.warning(f"Learning mode generator warning: {e}")
            learning_data = {"concepts": [], "language": lang}

        # =========================================================================
        # Stage 14: Security Report Generation (Module 13)
        # =========================================================================
        try:
            security_report = security_report_generator_service.generate_report(
                evidence=full_evidence,
                ai_report=ai_report,
                language=lang,
                report_id=f"REP-{analysis_id}"
            )
            report_dict = security_report.to_dict()
        except Exception as e:
            err_msg = f"Report Generator Error: {e}"
            errors.append(err_msg)
            logger.warning(err_msg)
            report_dict = {
                "report_id": f"REP-{analysis_id}",
                "language": lang,
                "summary": f"Report generated with warnings: {e}",
            }

        # =========================================================================
        # Stage 15: Database Persistence (Module 14)
        # =========================================================================
        db = SessionLocal()
        try:
            from app.db.schemas import IOCCreate, YaraMatchCreate, RiskFactorCreate, GhidraAnalysisCreate, GhidraFunctionCreate, GhidraRelationshipCreate
            sample_in = SampleCreate(
                analysis_id=analysis_id,
                filename=safe_filename,
                size=intake_res.size,
                file_type=pe_data.get("file_type", "EXE"),
                architecture=pe_data.get("machine_architecture", "x64"),
                md5=hash_data.get("md5", intake_res.md5),
                sha1=hash_data.get("sha1", intake_res.sha1),
                sha256=hash_data.get("sha256", intake_res.sha256),
                status="COMPLETED",
                risk_score=score_data.get("score", 0),
                classification=score_data.get("risk_level", "LOW"),
                user_id=user_id,
                completed_at=datetime.now(timezone.utc)
            )

            def _parse_int(val, default=0):
                if isinstance(val, int):
                    return val
                if isinstance(val, str):
                    try:
                        if val.lower().startswith("0x"):
                            return int(val, 16)
                        return int(val)
                    except Exception:
                        return default
                return default

            sections_in = [
                SectionCreate(
                    name=s.get("name", "UNNAMED"),
                    virtual_address=_parse_int(s.get("virtual_address", 0)),
                    virtual_size=_parse_int(s.get("virtual_size", 0)),
                    raw_size=_parse_int(s.get("raw_size", 0)),
                    entropy=float(s.get("entropy", 0.0)),
                    characteristics=",".join(s.get("characteristics", [])) if isinstance(s.get("characteristics"), list) else str(s.get("characteristics", ""))
                )
                for s in sections_raw_list
            ]
            imports_in = [
                ImportCreate(
                    dll=i.get("dll", "UNKNOWN.dll"),
                    api=i.get("api", "UNKNOWN"),
                    category=i.get("category", "GENERAL"),
                    risk_relevance=i.get("risk_relevance", "LOW")
                )
                for i in imports_raw_list[:100]
            ]
            if getattr(str_res, "items", None):
                strings_in = [
                    StringCreate(
                        value=item.value,
                        encoding=item.encoding,
                        offset=item.offset,
                        category=item.category,
                        type=item.category,
                        suspicious=item.suspicious,
                        severity=item.severity,
                        confidence=item.confidence,
                        reason=item.reason,
                        mitre_technique=item.mitre_technique
                    )
                    for item in str_res.items[:500]
                ]
            else:
                strings_in = [
                    StringCreate(value=u, type="URL", category="URL") for u in str_data.get("urls", [])[:20]
                ] + [
                    StringCreate(value=ip, type="IP_ADDRESS", category="IP_ADDRESS") for ip in str_data.get("ip_addresses", [])[:20]
                ] + [
                    StringCreate(value=r, type="REGISTRY_PATH", category="REGISTRY") for r in str_data.get("registry_paths", [])[:20]
                ]
            indicators_in = [
                IndicatorCreate(
                    name=ind.get("name", "Indicator"),
                    category=ind.get("category", "PE_STRUCTURE"),
                    severity=ind.get("severity", "LOW"),
                    evidence=ind.get("evidence", ""),
                    confidence=float(ind.get("confidence", 1.0))
                )
                for ind in indicators_raw_list
            ]
            iocs_in = [
                IOCCreate(
                    type=ioc["type"],
                    value=ioc["value"],
                    source=ioc.get("source", "STATIC_ANALYSIS"),
                    confidence=float(ioc.get("confidence", 1.0))
                )
                for ioc in iocs_list[:50]
            ]
            yara_matches_in = [
                YaraMatchCreate(
                    rule_name=ym.get("rule_name", "YaraRule"),
                    namespace=ym.get("namespace", "default"),
                    tags=",".join(ym.get("tags", [])) if isinstance(ym.get("tags"), list) else str(ym.get("tags", "")),
                    description=ym.get("description", ""),
                    rule_version_id=ym.get("rule_version_id"),
                    rule_id=ym.get("rule_id"),
                )
                for ym in yara_data.get("matches", [])
            ]
            risk_factors_in = [
                RiskFactorCreate(
                    name=rf["name"],
                    category=rf["category"],
                    severity=rf["severity"],
                    weight=float(rf["weight"]),
                    evidence=rf.get("evidence", "")
                )
                for rf in risk_factors_list
            ]
            result_in = AnalysisResultCreate(
                risk_score=score_data.get("score", 0),
                risk_level=score_data.get("risk_level", "LOW"),
                ai_summary=ai_data.get("summary", ""),
                ai_confidence=ai_data.get("confidence", "MEDIUM")
            )

            ghidra_analysis_in = GhidraAnalysisCreate(
                status=ghidra_data.get("status", "UNAVAILABLE"),
                message=ghidra_data.get("message"),
                program_name=ghidra_data.get("program_name"),
                language_id=ghidra_data.get("language_id"),
                processor=ghidra_data.get("processor"),
                compiler=ghidra_data.get("compiler"),
                image_base=ghidra_data.get("image_base"),
                entry_point=ghidra_data.get("entry_point"),
                function_count=int(ghidra_data.get("function_count", 0) or 0),
                import_count=int(ghidra_data.get("import_count", 0) or 0),
                export_count=int(ghidra_data.get("export_count", 0) or 0),
                string_count=int(ghidra_data.get("string_count", 0) or 0),
                relationship_count=int(ghidra_data.get("relationship_count", 0) or 0),
            )
            ghidra_functions_in = [
                GhidraFunctionCreate(
                    name=fn.get("name", "FUN_unknown"),
                    address=fn.get("address"),
                    size=int(fn.get("size", 0) or 0),
                    is_thunk=bool(fn.get("is_thunk", False)),
                    calling_convention=fn.get("calling_convention"),
                )
                for fn in (ghidra_data.get("functions") or [])[:settings.GHIDRA_MAX_FUNCTIONS]
            ]
            ghidra_relationships_in = [
                GhidraRelationshipCreate(
                    from_address=rel.get("from_address"),
                    from_name=rel.get("from_name"),
                    to_address=rel.get("to_address"),
                    to_name=rel.get("to_name"),
                )
                for rel in (ghidra_data.get("relationships") or [])
            ]

            SampleRepository.save_full_analysis_transaction(
                db=db,
                sample_in=sample_in,
                sections_in=sections_in,
                imports_in=imports_in,
                strings_in=strings_in,
                indicators_in=indicators_in,
                iocs_in=iocs_in,
                yara_matches_in=yara_matches_in,
                risk_factors_in=risk_factors_in,
                result_in=result_in,
                ghidra_analysis_in=ghidra_analysis_in,
                ghidra_functions_in=ghidra_functions_in,
                ghidra_relationships_in=ghidra_relationships_in,
            )
        except Exception as db_err:
            logger.warning(f"Database save warning: {db_err}")
        finally:
            db.close()

        # Log completion in security audit system
        audit_logger.log_analysis_completion(
            analysis_id=analysis_id,
            filename=safe_filename,
            risk_level=score_data.get("risk_level", "LOW"),
            threat_score=score_data.get("score", 0),
            details={"indicators_count": len(indicators_collection), "errors_count": len(errors)},
        )

        overall_status = "PARTIAL" if errors else "COMPLETED"

        # =========================================================================
        # Construct and Return Module 19 Unified Analysis Object
        # =========================================================================
        return {
            # Canonical Module 19 Versioned Schema:
            "schema_version": "1.0",
            "analysis_id": analysis_id,
            "status": overall_status,
            "file": file_info,
            "hashes": hash_data,
            "pe": pe_data,
            "sections": sections_collection,
            "entropy": ent_data,
            "strings": str_data,
            "imports": imports_collection,
            "indicators": indicators_collection,
            "iocs": {"total_iocs": len(iocs_list), "items": iocs_list},
            "yara_matches": yara_data,
            "mitre_attack": mitre_mappings,
            "risk_factors": risk_factors_list,
            "risk": score_data,
            "risk_score": score_data,
            "ethiopian_context": ethio_data,
            "ghidra": ghidra_data,
            "ai_assessment": ai_data,
            "report": report_dict,
            "errors": errors,
            "ml_analysis": ml_data,

            # Backward-Compatibility Aliases:
            "filename": safe_filename,
            "language": lang,
            "file_information": file_info,
            "pe_information": pe_data,
            "threat_score": score_data,
            "learning_mode": learning_data,
        }

    # Standard analysis alias
    analyze_bytes = execute_pipeline


# Global singleton instance
unified_pipeline_service = UnifiedPipelineOrchestrator()
