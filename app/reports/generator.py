"""
Security Report Generator Module

Responsibility:
Aggregates full static analysis evidence from Modules 01 through 12, applies the three-tier Evidence Model
(OBSERVED, RULE-BASED, AI-INTERPRETED), and exports comprehensive reports in JSON, HTML, and PDF-ready formats.
"""

import uuid
from typing import Dict, List, Optional, Any
from app.core.logger import logger
from app.reports.models import SecurityReport, ClassifiedStatement, EvidenceTier
from app.reports.renderers import JSONReportRenderer, HTMLReportRenderer, PDFReportRenderer
from app.ai.analyst import AIAnalystReport


class SecurityReportGenerator:
    """
    Unified Security Report Generator for ETHIO-AI Defender.
    """

    def __init__(self):
        self.renderers = {
            "json": JSONReportRenderer(),
            "html": HTMLReportRenderer(),
            "pdf": PDFReportRenderer(),
        }

    def _classify_evidence_statements(
        self,
        evidence: Dict[str, Any],
        ai_report: Optional[AIAnalystReport] = None,
        language: str = "en"
    ) -> List[ClassifiedStatement]:
        """
        Builds the three-tier Evidence Model classifying every important finding as
        OBSERVED, RULE-BASED, or AI-INTERPRETED.
        """
        statements: List[ClassifiedStatement] = []
        is_am = (language.lower() in ("am", "amharic"))

        # 1. TIER: OBSERVED (Deterministic static artifacts)
        # Hashes
        sha256 = evidence.get("hashes", {}).get("sha256")
        if sha256:
            statements.append(ClassifiedStatement(
                tier=EvidenceTier.OBSERVED,
                category="Cryptographic Hash",
                statement=f"SHA-256 hash verified as {sha256}" if not is_am else f"የተረጋገጠ የ SHA-256 ሃሽ: {sha256}"
            ))

        # PE & Sections
        sec_info = evidence.get("sections", {})
        if sec_info:
            has_wx = sec_info.get("has_wx_sections", False)
            if has_wx:
                statements.append(ClassifiedStatement(
                    tier=EvidenceTier.OBSERVED,
                    category="PE Sections",
                    statement="Section with simultaneous Writable and Executable (W+X) permissions observed." if not is_am else "የመጻፍ እና የማስፈጸም (W+X) ፈቃድ ያለው section ተገኝቷል።"
                ))

        # Imports
        imp_info = evidence.get("imports", {})
        if imp_info:
            for imp in imp_info.get("imports", [])[:5]:
                if isinstance(imp, dict):
                    api_name = imp.get("api", "API")
                    dll_name = imp.get("dll", "DLL")
                    statements.append(ClassifiedStatement(
                        tier=EvidenceTier.OBSERVED,
                        category="Import Table",
                        statement=f"{api_name} is imported from {dll_name}." if not is_am else f"{api_name} ከ {dll_name} ላይብረሪ ተጠርቷል።"
                    ))

        # Strings
        str_info = evidence.get("strings", {})
        if str_info:
            for url in str_info.get("urls", [])[:3]:
                statements.append(ClassifiedStatement(
                    tier=EvidenceTier.OBSERVED,
                    category="Embedded Strings",
                    statement=f"Embedded network URL observed: {url}" if not is_am else f"በፋይሉ ውስጥ የተገኘ የኔትወርክ አድራሻ (URL): {url}"
                ))

        # 2. TIER: RULE-BASED (Correlated heuristic algorithms)
        ind_info = evidence.get("indicators", {})
        if ind_info:
            for ind in ind_info.get("indicators", [])[:5]:
                if isinstance(ind, dict):
                    statements.append(ClassifiedStatement(
                        tier=EvidenceTier.RULE_BASED,
                        category="Correlated Indicator",
                        statement=f"{ind.get('name', 'Indicator')} detected ({ind.get('severity', 'MEDIUM')})." if not is_am else f"የ {ind.get('name', 'አመልካች')} ስጋት አመልካች ተለይቷል።"
                    ))

        threat_info = evidence.get("threat_score", {})
        if threat_info:
            score = threat_info.get("score", 0)
            level = threat_info.get("risk_level", "LOW")
            statements.append(ClassifiedStatement(
                tier=EvidenceTier.RULE_BASED,
                category="Threat Scoring",
                statement=f"Heuristic threat scoring calculated score of {score}/100 ({level})." if not is_am else f"የ Heuristic ስጋት ውጤት: {score}/100 [{level}]."
            ))

        ethio_info = evidence.get("ethiopian_context", {})
        if ethio_info:
            env = ethio_info.get("environment", "GENERAL")
            rel = ethio_info.get("relevance", "LOW")
            statements.append(ClassifiedStatement(
                tier=EvidenceTier.RULE_BASED,
                category="Ethiopian Context",
                statement=f"Operational sector relevance for {env} assessed as {rel}." if not is_am else f"ለ {env} ተቋማት የተሰጠ የደህንነት ቅድሚያ: {rel}."
            ))

        # 3. TIER: AI-INTERPRETED (Qualified model interpretations and analyst hypotheses)
        if ai_report:
            statements.append(ClassifiedStatement(
                tier=EvidenceTier.AI_INTERPRETED,
                category="AI Security Summary",
                statement=ai_report.summary or ("AI analyst summary evaluated." if not is_am else "የ AI ደህንነት ትንተና ማጠቃለያ።")
            ))
            for finding in ai_report.key_findings[:3]:
                statements.append(ClassifiedStatement(
                    tier=EvidenceTier.AI_INTERPRETED,
                    category="AI Key Finding",
                    statement=finding
                ))
            for rec in ai_report.recommended_investigation[:2]:
                statements.append(ClassifiedStatement(
                    tier=EvidenceTier.AI_INTERPRETED,
                    category="AI Recommended Action",
                    statement=rec
                ))

        return statements

    def generate_report(
        self,
        evidence: Dict[str, Any],
        ai_report: Optional[AIAnalystReport] = None,
        language: str = "en",
        report_id: Optional[str] = None
    ) -> SecurityReport:
        """
        Builds the unified 16-section SecurityReport from full evidence.
        """
        lang = "am" if language.lower() in ("am", "amharic") else "en"
        rid = report_id or f"REP-{uuid.uuid4().hex[:8].upper()}"

        # 1. Executive Summary
        threat_score_data = evidence.get("threat_score", {})
        score = threat_score_data.get("score", 0)
        risk_level = threat_score_data.get("risk_level", "LOW")
        filename = evidence.get("file_metadata", {}).get("filename", "binary_sample.exe")

        if ai_report and ai_report.summary:
            executive_summary = ai_report.summary
        else:
            executive_summary = (
                f"Static analysis evaluation of '{filename}' completed with a heuristic threat score of {score}/100 [{risk_level}]. "
                f"Static evidence was correlated across PE headers, memory sections, entropy, and imported system APIs."
                if lang == "en" else
                f"የ '{filename}' የ static ትንተና ግምገማ በ {score}/100 [{risk_level}] የስጋት ውጤት ተጠናቋል። "
                f"የፋይሉ ቴክኒካዊ ገጽታ በ PE headers፣ Sections፣ Entropy እና በ Imported APIs ተገምግሟል።"
            )

        # 2-11. Sections mapping
        file_info = evidence.get("file_metadata", {})
        hashes = evidence.get("hashes", {})
        pe_info = evidence.get("pe_information", {})
        sec_info = evidence.get("sections", {})
        ent_info = evidence.get("entropy", {})
        str_info = evidence.get("strings", {})
        imp_info = evidence.get("imports", {})
        ind_info = evidence.get("indicators", {}).get("indicators", [])
        ethio_info = evidence.get("ethiopian_context", {})

        # 12. AI Assessment
        ai_assessment_data = ai_report.to_dict() if ai_report else {
            "assessment": risk_level,
            "confidence": "MEDIUM",
            "summary": executive_summary
        }

        # 13. Evidence (Tri-tiered)
        classified_evidence = self._classify_evidence_statements(
            evidence=evidence,
            ai_report=ai_report,
            language=lang
        )

        # 14, 15, 16. Explanations, Investigations, Limitations
        if ai_report:
            benign_explanations = ai_report.possible_benign_explanations
            recommendations = ai_report.recommended_investigation
            limitations = ai_report.limitations
        else:
            benign_explanations = [
                "Legitimate software packers, installers, or DRM protections can produce elevated section entropy.",
                "Diagnostic administration tools legitimately utilize process and memory management APIs."
            ] if lang == "en" else [
                "መደበኛ የንግድ ሶፍትዌሮች እና የሲስተም መገልገያዎች ተመሳሳይ የ Windows API ጥሪዎችን ሊጠቀሙ ይችላሉ።"
            ]
            recommendations = [
                "Execute the binary within an isolated, instrumented sandbox to observe live runtime behavior.",
                "Verify file reputation against internal enterprise whitelists and baseline hashes."
            ] if lang == "en" else [
                "ፋይሉን በተከለለ የ Sandbox አካባቢ በ dynamic ትንተና መፈተሽ።"
            ]
            limitations = [
                "Static analysis evaluates binary capabilities without live code execution.",
                "Risk score is a heuristic analyst-support metric and is not a confirmed probability of maliciousness."
            ] if lang == "en" else [
                "Static analysis የፋይሉን ቴክኒካዊ ችሎታ የሚያሳይ እንጂ ፋይሉን አስነስቶ የተረጋገጠ ባህሪን አያሳይም።",
                "የስጋት ውጤቱ የትንተና ድጋፍ ሰጪ መረጃ እንጂ የጥቃት ማረጋገጫ አይደለም።"
            ]

        return SecurityReport(
            report_id=rid,
            language=lang,
            executive_summary=executive_summary,
            file_information=file_info,
            hashes=hashes,
            pe_information=pe_info,
            section_analysis=sec_info,
            entropy_analysis=ent_info,
            string_analysis=str_info,
            import_api_analysis=imp_info,
            suspicious_indicators=ind_info,
            threat_score=threat_score_data,
            ethiopian_context=ethio_info,
            ai_assessment=ai_assessment_data,
            evidence=classified_evidence,
            possible_benign_explanations=benign_explanations,
            recommended_investigation=recommendations,
            limitations=limitations
        )

    def export(self, report: SecurityReport, format: str = "json") -> str:
        """
        Exports the SecurityReport into the specified output format ('json', 'html', 'pdf').
        """
        fmt = format.lower()
        renderer = self.renderers.get(fmt, self.renderers["json"])
        return renderer.render(report)


# Global singleton instance
security_report_generator_service = SecurityReportGenerator()
