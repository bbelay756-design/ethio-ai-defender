"""
AI Provider Abstraction and Implementation Module

Responsibility:
Provides an extensible AI provider interface (AIProvider) allowing flexible backend engines:
- GeminiProvider (Google Gemini API via API key)
- MockAIProvider (Configurable test double for unit and regression testing)
- OfflineRuleBasedProvider (Deterministic, zero-network fallback explanation engine)
"""

import abc
import json
import time
from typing import Dict, Any, Optional
from app.core.config import settings
from app.core.logger import logger


class AIProvider(abc.ABC):
    """
    Abstract Base Class for AI Analyst Providers.
    """

    @abc.abstractmethod
    def generate_analysis(self, evidence: Dict[str, Any], language: str = "en") -> str:
        """
        Generates structured static-analysis explanation text (JSON string) from evidence.

        Args:
            evidence: Sanitized dictionary of static analysis evidence.
            language: 'en' for English, 'am' for Amharic.

        Returns:
            JSON formatted string matching the AI output schema.
        """
        pass


class MockAIProvider(AIProvider):
    """
    Mock AI Provider for reproducible, hermetic testing without network dependencies.
    """

    def __init__(
        self,
        mode: str = "valid",
        custom_response: Optional[str] = None,
        simulate_delay: float = 0.0
    ):
        self.mode = mode
        self.custom_response = custom_response
        self.simulate_delay = simulate_delay

    def generate_analysis(self, evidence: Dict[str, Any], language: str = "en") -> str:
        if self.simulate_delay > 0:
            time.sleep(self.simulate_delay)

        if self.mode == "timeout":
            raise TimeoutError("AI Provider request timed out after 15 seconds.")

        if self.mode == "api_failure":
            raise RuntimeError("AI Provider returned HTTP 500 Internal Server Error.")

        if self.mode == "malformed":
            return "This is not valid JSON string {malformed..."

        if self.mode == "missing_fields":
            return json.dumps({
                "assessment": "HIGH",
                "summary": "Partial summary with missing fields."
            })

        if self.custom_response:
            return self.custom_response

        # Default valid response
        threat_score = evidence.get("threat_score", {}).get("score", 0)
        risk_level = evidence.get("threat_score", {}).get("risk_level", "LOW")
        indicators = evidence.get("indicators", {}).get("indicators", [])

        summary_text = (
            f"The analyzed binary presents a {risk_level} static threat posture with a heuristic score of {threat_score}/100. "
            f"Evaluated {len(indicators)} correlated static indicators across PE sections, entropy, and imported APIs."
        ) if language == "en" else (
            f"የተተነተነው የ PE ፋይል የ {risk_level} ስጋት ደረጃ እና {threat_score}/100 የስጋት ውጤት ያሳያል። "
            f"በ static ትንተና {len(indicators)} ቴክኒካዊ አመልካቾች ተገምግመዋል።"
        )

        return json.dumps({
            "assessment": risk_level,
            "confidence": "HIGH" if len(indicators) >= 3 else "MEDIUM",
            "summary": summary_text,
            "key_findings": [
                f"Identified {len(indicators)} correlated static indicator(s).",
                f"Assigned heuristic risk score: {threat_score}/100 ({risk_level})."
            ],
            "evidence": [
                f"Indicator {ind.get('id', 'N/A')}: {ind.get('name', 'N/A')}"
                for ind in indicators[:3]
            ],
            "possible_benign_explanations": [
                "Legitimate software packers or commercial protectors may produce similar high entropy.",
                "System utilities legitimately utilize low-level Windows APIs for diagnostic purposes."
            ],
            "recommended_investigation": [
                "Perform dynamic behavioral execution inside an isolated hardware sandbox.",
                "Monitor network gateway for egress traffic matching identified endpoints."
            ],
            "limitations": [
                "Static analysis evaluates binary capabilities without live code execution.",
                "Heuristic risk score is an analyst-support metric and not a probability of infection."
            ]
        })


class OfflineRuleBasedProvider(AIProvider):
    """
    Deterministic Offline Rule-Based Provider.
    Produces high-fidelity grounded explanations in English and Amharic with zero external network calls.
    """

    def generate_analysis(self, evidence: Dict[str, Any], language: str = "en") -> str:
        lang = "am" if language.lower() in ("am", "amharic") else "en"
        threat_score_info = evidence.get("threat_score", {})
        score = threat_score_info.get("score", 0)
        risk_level = threat_score_info.get("risk_level", "LOW")
        indicators = evidence.get("indicators", {}).get("indicators", [])
        ethio_ctx = evidence.get("ethiopian_context", {})
        env = ethio_ctx.get("environment", "GENERAL")

        if lang == "am":
            summary = (
                f"የተመረመረው የ PE ፋይል የ {risk_level} ስጋት ደረጃ (ውጤት: {score}/100) ያሳያል። "
                f"የተገኙት {len(indicators)} የ static አመልካቾች ለ {env} የመረጃ መሠረተ-ልማት ደህንነት ትኩረት የሚሹ ናቸው።"
            )
            key_findings = [
                f"የተረጋገጠ የስጋት ውጤት: {score}/100 [{risk_level}].",
                f"የተገኙ የ static አመልካቾች ብዛት: {len(indicators)}.",
                f"ለ {env} ተቋማት የተሰጠ የደህንነት ቅድሚያ: {ethio_ctx.get('relevance', 'LOW')}."
            ]
            benign_explanations = [
                "መደበኛ የንግድ ሶፍትዌሮች እና የሲስተም መገልገያዎች ተመሳሳይ የ Windows API ጥሪዎችን ሊጠቀሙ ይችላሉ።",
                "ከፍተኛ Entropy መረጃ በህጋዊ የመረጃ መጨመቂያ (Compression) ምክንያት ሊከሰት ይችላል።"
            ]
            recommendations = [
                "ፋይሉን በተከለለ የ Sandbox አካባቢ በ dynamic ትንተና መፈተሽ።",
                "የኔትወርክ ግንኙነቶችን እና የፋይል ለውጦችን በ Endpoint Detection መከታተል።"
            ]
        else:
            summary = (
                f"The static analysis assessment indicates a {risk_level} risk posture with a heuristic threat score of {score}/100. "
                f"{len(indicators)} correlated static indicators were identified, providing context for defensive monitoring in {env} environments."
            )
            key_findings = [
                f"Heuristic Threat Score: {score}/100 [{risk_level}].",
                f"Correlated Suspicious Indicators: {len(indicators)} detected.",
                f"Target Operational Relevance ({env}): {ethio_ctx.get('relevance', 'LOW')}."
            ]
            benign_explanations = [
                "Legitimate software packers, installers, or DRM protections can produce elevated section entropy.",
                "Diagnostic administration tools legitimately utilize process and memory management APIs."
            ]
            recommendations = [
                "Execute the binary within an isolated, instrumented sandbox to observe live runtime behavior.",
                "Verify file reputation against internal enterprise whitelists and baseline hashes."
            ]

        evidence_items = [
            f"{ind.get('id', 'IND')}: {ind.get('name', 'Finding')} - {ind.get('evidence', '')}"
            for ind in indicators[:5]
        ]
        if not evidence_items:
            evidence_items = ["No high-severity static anomalies detected in standard PE headers."]

        return json.dumps({
            "assessment": risk_level,
            "confidence": "HIGH" if score >= 60 or len(indicators) >= 3 else "MEDIUM",
            "summary": summary,
            "key_findings": key_findings,
            "evidence": evidence_items,
            "possible_benign_explanations": benign_explanations,
            "recommended_investigation": recommendations,
            "limitations": [
                "Static analysis evaluates binary capabilities without live code execution.",
                "Risk score is a heuristic analyst-support metric and is not a confirmed probability of maliciousness."
            ]
        })


class GeminiProvider(AIProvider):
    """
    Google Gemini API Provider.
    Configurable via environment variables without hardcoded API keys.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout: Optional[int] = None
    ):
        self.api_key = api_key or settings.GEMINI_API_KEY
        self.model_name = model_name or settings.AI_MODEL_NAME
        self.timeout = timeout or settings.AI_TIMEOUT_SECONDS

    def generate_analysis(self, evidence: Dict[str, Any], language: str = "en") -> str:
        if not self.api_key:
            logger.info("No GEMINI_API_KEY configured. Falling back to OfflineRuleBasedProvider.")
            return OfflineRuleBasedProvider().generate_analysis(evidence, language=language)

        try:
            # Dynamically import google-generativeai if installed
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel(self.model_name)

            prompt = (
                f"You are the AI Security Analyst for ETHIO-AI Defender. "
                f"Analyze the following structured static analysis evidence and return ONLY a valid JSON object matching the schema:\n"
                f"{{\n"
                f'  "assessment": "LOW|MODERATE|SUSPICIOUS|HIGH|CRITICAL",\n'
                f'  "confidence": "LOW|MEDIUM|HIGH",\n'
                f'  "summary": "...",\n'
                f'  "key_findings": ["..."],\n'
                f'  "evidence": ["..."],\n'
                f'  "possible_benign_explanations": ["..."],\n'
                f'  "recommended_investigation": ["..."],\n'
                f'  "limitations": ["..."]\n'
                f"}}\n\n"
                f"Rules:\n"
                f"- Language: {'Amharic (preserve technical terms PE, API, DLL, SHA-256, x86, x64, Entropy)' if language == 'am' else 'English'}\n"
                f"- Never invent evidence, hashes, imports, threat actors, or incidents.\n"
                f"- Distinguish facts from interpretations.\n\n"
                f"Evidence:\n{json.dumps(evidence, indent=2)}"
            )

            response = model.generate_content(
                prompt,
                generation_config={"response_mime_type": "application/json"}
            )
            return response.text
        except Exception as err:
            logger.error(f"Gemini API request failed: {err}. Falling back to offline provider.")
            return OfflineRuleBasedProvider().generate_analysis(evidence, language=language)
