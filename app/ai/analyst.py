"""
AI Security Analyst Service

Responsibility:
Coordinates structured evidence interpretation, data sanitization, AI provider execution,
and grounding validation to produce explainable security reports.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from app.core.config import settings
from app.core.logger import logger
from app.ai.sanitizer import sanitize_evidence_payload
from app.ai.grounding import GroundingValidator
from app.ai.provider import AIProvider, MockAIProvider, OfflineRuleBasedProvider, GeminiProvider


@dataclass
class AIAnalystReport:
    """
    Structured outcome of the AI Security Analyst matching the Module 11 contract.
    """
    assessment: str = "LOW"  # 'LOW', 'MODERATE', 'SUSPICIOUS', 'HIGH', 'CRITICAL'
    confidence: str = "MEDIUM"  # 'LOW', 'MEDIUM', 'HIGH'
    summary: str = ""
    key_findings: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    possible_benign_explanations: List[str] = field(default_factory=list)
    recommended_investigation: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    language: str = "en"
    is_valid: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns the exact Module 11 output contract dictionary."""
        return {
            "assessment": self.assessment,
            "confidence": self.confidence,
            "summary": self.summary,
            "key_findings": self.key_findings,
            "evidence": self.evidence,
            "possible_benign_explanations": self.possible_benign_explanations,
            "recommended_investigation": self.recommended_investigation,
            "limitations": self.limitations,
        }


class AISecurityAnalystService:
    """
    AI Security Analyst Service with multi-provider abstraction and grounding validation.
    """

    def __init__(self, provider: Optional[AIProvider] = None):
        self.provider = provider or self._get_default_provider()
        self.grounding_validator = GroundingValidator()

    def _get_default_provider(self) -> AIProvider:
        """Instantiates default provider according to system configuration."""
        prov_name = settings.AI_PROVIDER.lower()
        if prov_name == "gemini" and settings.GEMINI_API_KEY:
            return GeminiProvider()
        elif prov_name == "mock":
            return MockAIProvider()
        else:
            return OfflineRuleBasedProvider()

    def set_provider(self, provider: AIProvider) -> None:
        """Sets or swaps the AI provider at runtime."""
        self.provider = provider

    def _parse_ai_json(self, raw_response: str) -> Dict[str, Any]:
        """
        Extracts and parses JSON from AI response text, handling Markdown code blocks gracefully.
        """
        cleaned = raw_response.strip()

        # Handle ```json ... ``` code blocks
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            cleaned = "\n".join(lines).strip()

        return json.loads(cleaned)

    def analyze(
        self,
        evidence: Dict[str, Any],
        language: str = "en"
    ) -> AIAnalystReport:
        """
        Interprets structured static-analysis evidence into an explainable security report.

        Args:
            evidence: Structured dictionary of static findings from Modules 01-10.
            language: 'en' for English, 'am' for Amharic.

        Returns:
            AIAnalystReport instance.
        """
        lang = "am" if language.lower() in ("am", "amharic") else "en"

        # 1. Sanitize evidence payload to guarantee privacy & boundary enforcement
        sanitized_evidence = sanitize_evidence_payload(evidence)

        # 2. Invoke AI Provider with error recovery
        try:
            raw_response = self.provider.generate_analysis(sanitized_evidence, language=lang)
            parsed_data = self._parse_ai_json(raw_response)
        except Exception as err:
            logger.warning(f"AI Provider execution/parsing failed: {err}. Triggering deterministic fallback.")
            fallback_provider = OfflineRuleBasedProvider()
            raw_response = fallback_provider.generate_analysis(sanitized_evidence, language=lang)
            try:
                parsed_data = self._parse_ai_json(raw_response)
            except Exception:
                parsed_data = {}

        # 3. Fill missing fields with safe defaults
        threat_info = sanitized_evidence.get("threat_score", {})
        default_assessment = threat_info.get("risk_level", "LOW")
        score = threat_info.get("score", 0)

        assessment = str(parsed_data.get("assessment", default_assessment)).upper()
        if assessment not in ("LOW", "MODERATE", "SUSPICIOUS", "HIGH", "CRITICAL"):
            assessment = default_assessment

        confidence = str(parsed_data.get("confidence", "MEDIUM")).upper()
        if confidence not in ("LOW", "MEDIUM", "HIGH"):
            confidence = "MEDIUM"

        summary = parsed_data.get("summary") or (
            f"Static assessment indicates a {assessment} risk profile (Score: {score}/100)."
            if lang == "en" else
            f"የ static ትንተና ግምገማ የ {assessment} ስጋት ደረጃ (ውጤት: {score}/100) ያሳያል።"
        )

        key_findings = parsed_data.get("key_findings")
        if not isinstance(key_findings, list) or not key_findings:
            key_findings = [f"Assigned heuristic risk level: {assessment} (Score: {score}/100)."]

        evidence_items = parsed_data.get("evidence")
        if not isinstance(evidence_items, list) or not evidence_items:
            evidence_items = ["Static analysis evidence evaluated across PE headers, sections, and APIs."]

        benign_explanations = parsed_data.get("possible_benign_explanations")
        if not isinstance(benign_explanations, list) or not benign_explanations:
            benign_explanations = ["Legitimate utilities may utilize similar Windows API structures."]

        recommendations = parsed_data.get("recommended_investigation")
        if not isinstance(recommendations, list) or not recommendations:
            recommendations = ["Conduct dynamic behavioral analysis in an isolated sandbox environment."]

        limitations = parsed_data.get("limitations")
        if not isinstance(limitations, list) or not limitations:
            limitations = [
                "Static analysis evaluates binary capabilities without live code execution.",
                "Risk score is a heuristic analyst-support metric and is not a confirmed probability of maliciousness."
            ]

        preliminary_dict = {
            "assessment": assessment,
            "confidence": confidence,
            "summary": summary,
            "key_findings": key_findings,
            "evidence": evidence_items,
            "possible_benign_explanations": benign_explanations,
            "recommended_investigation": recommendations,
            "limitations": limitations
        }

        # 4. Grounding & Hallucination validation
        grounded_dict = self.grounding_validator.validate_and_clean(
            ai_response_dict=preliminary_dict,
            raw_evidence=sanitized_evidence
        )

        return AIAnalystReport(
            assessment=grounded_dict["assessment"],
            confidence=grounded_dict["confidence"],
            summary=grounded_dict["summary"],
            key_findings=grounded_dict["key_findings"],
            evidence=grounded_dict["evidence"],
            possible_benign_explanations=grounded_dict["possible_benign_explanations"],
            recommended_investigation=grounded_dict["recommended_investigation"],
            limitations=grounded_dict["limitations"],
            language=lang,
            is_valid=True
        )


# Global singleton instance
ai_security_analyst_service = AISecurityAnalystService()
