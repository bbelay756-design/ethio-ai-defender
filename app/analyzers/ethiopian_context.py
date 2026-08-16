"""
Module 10: Ethiopian Cybersecurity Context Engine

Responsibility:
Provides localized defensive and operational context for malware triage in Ethiopia across key national sectors.

Environments:
- GOVERNMENT          : Ministries, agencies, public sector administration
- FINANCIAL           : Banks, microfinance institutions, payment gateways
- UNIVERSITY          : Higher education institutions, research labs, campus networks
- HEALTHCARE          : Hospitals, clinical networks, medical records infrastructure
- TELECOMMUNICATIONS  : ISP networks, telecom infrastructure, gateway routers
- ENTERPRISE          : Domestic corporations, commercial businesses, utilities
- GENERAL             : Baseline defensive threat triage

Crucial Defensive & Scientific Directives:
- Do NOT invent threat actors, campaigns, victims, incidents, statistics, or Ethiopian malware families.
- Do NOT claim that a sample targets Ethiopia unless verified static evidence (e.g., .et ccTLD or domestic endpoints) is present.
- This module provides defensive contextual prioritization only.

Languages:
- English ('en')
- Amharic ('am') with technical terms preserved: PE, API, SHA-256, DLL, x86, x64, Entropy.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from app.core.logger import logger
from app.analyzers.indicator_engine import SuspiciousIndicator, IndicatorAnalysisResult
from app.analyzers.string_analyzer import StringAnalysisResult
from app.analyzers.threat_scoring import ThreatScoreResult

# Supported Sector Environments
ENVIRONMENTS = [
    "GOVERNMENT",
    "FINANCIAL",
    "UNIVERSITY",
    "HEALTHCARE",
    "TELECOMMUNICATIONS",
    "ENTERPRISE",
    "GENERAL",
]

# Recognized Ethiopian National ccTLD and Domestic Infrastructure Identifiers
ETHIOPIAN_DOMESTIC_PATTERNS = [
    ".et", ".gov.et", ".edu.et", ".org.et", ".com.et", ".net.et",
    "telecom.et", "ethionet.et", "insa.gov.et", "cbe.com.et",
    "ethiotelecom", "amharic"
]


@dataclass
class ContextAssessment:
    """
    Individual sector contextual evaluation matching the Module 10 schema contract.
    """
    environment: str
    relevance: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    reason: str
    language: str = "en"

    def to_dict(self) -> Dict[str, Any]:
        """Returns the exact Module 10 output contract dictionary."""
        return {
            "environment": self.environment,
            "relevance": self.relevance,
            "reason": self.reason,
            "language": self.language,
        }


@dataclass
class EthiopianContextAnalysisResult:
    """
    Aggregated outcome of the Ethiopian Cybersecurity Context Engine.
    """
    environment: str = "GENERAL"
    relevance: str = "LOW"
    reason: str = "Standard defensive evaluation."
    language: str = "en"
    has_explicit_domestic_artifacts: bool = False
    explicit_artifacts: List[str] = field(default_factory=list)
    sector_assessments: List[ContextAssessment] = field(default_factory=list)
    is_valid: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns the primary environment assessment matching the user schema."""
        return {
            "environment": self.environment,
            "relevance": self.relevance,
            "reason": self.reason,
            "language": self.language,
        }

    def to_full_dict(self) -> Dict[str, Any]:
        """Returns the detailed assessment across all sectors and explicit artifacts."""
        return {
            "selected_environment": self.environment,
            "relevance": self.relevance,
            "reason": self.reason,
            "language": self.language,
            "has_explicit_domestic_artifacts": self.has_explicit_domestic_artifacts,
            "explicit_artifacts": self.explicit_artifacts,
            "sector_assessments": [a.to_dict() for a in self.sector_assessments],
        }


class EthiopianContextEngine:
    """
    Localized Cybersecurity Context & Sector Prioritization Engine for Ethiopia.
    """

    def __init__(self):
        pass

    def _extract_explicit_domestic_artifacts(self, strings: Optional[StringAnalysisResult]) -> List[str]:
        """
        Inspects extracted strings neutrally for verified Ethiopian domestic identifiers.
        Never hallucinates or invents non-existent findings.
        """
        if not strings:
            return []

        artifacts: Set[str] = set()

        # Check domains and URLs
        for domain in (strings.domains or []):
            d_lower = domain.lower()
            if any(pat in d_lower for pat in ETHIOPIAN_DOMESTIC_PATTERNS):
                artifacts.add(domain)

        for url in (strings.urls or []):
            u_lower = url.lower()
            if any(pat in u_lower for pat in ETHIOPIAN_DOMESTIC_PATTERNS):
                artifacts.add(url)

        for email in (strings.emails or []):
            e_lower = email.lower()
            if any(pat in e_lower for pat in ETHIOPIAN_DOMESTIC_PATTERNS):
                artifacts.add(email)

        return sorted(list(artifacts))

    def evaluate_sector(
        self,
        target_env: str,
        indicators: List[SuspiciousIndicator],
        strings: Optional[StringAnalysisResult] = None,
        threat_score: int = 0,
        language: str = "en"
    ) -> ContextAssessment:
        """
        Evaluates relevance for a specific Ethiopian operational environment.
        """
        env_norm = target_env.upper() if target_env.upper() in ENVIRONMENTS else "GENERAL"
        lang_norm = "am" if language.lower() in ("am", "amharic") else "en"

        categories_present = {ind.category for ind in indicators}
        has_high_indicators = any(ind.severity in ("HIGH", "CRITICAL") for ind in indicators)
        explicit_artifacts = self._extract_explicit_domestic_artifacts(strings)

        # Baseline relevance calculation based on technical capabilities
        relevance = "LOW"
        reason_en = ""
        reason_am = ""

        # Check explicit domestic artifacts first
        if explicit_artifacts:
            relevance = "HIGH" if threat_score < 60 else "CRITICAL"
            art_str = ", ".join(explicit_artifacts[:2])
            reason_en = (
                f"Static artifacts contain verified domestic identifiers ({art_str}). "
                f"Elevated defensive prioritization recommended for {env_norm} infrastructure."
            )
            reason_am = (
                f"በ static ትንተና የተረጋገጡ የሀገር ውስጥ መለያዎች ({art_str}) ተገኝተዋል። "
                f"ለ {env_norm} የመረጃ መሠረተ-ልማት ከፍተኛ የደህንነት ክትትል ቅድሚያ ይመከራል።"
            )
        else:
            # Sector-specific capability prioritization
            if env_norm == "FINANCIAL":
                if "MEMORY" in categories_present or "PROCESS" in categories_present:
                    relevance = "HIGH" if has_high_indicators else "MEDIUM"
                    reason_en = (
                        "Memory allocation and inter-process API capabilities identified; "
                        "relevant for banking endpoints, payment processors, and financial transactions."
                    )
                    reason_am = (
                        "የ Memory እና Process ማቀናበሪያ API ጥሪዎች ተለይተዋል፤ "
                        "ይህም ለባንክ እና ለክፍያ ስርዓቶች የደህንነት ክትትል አስፈላጊ ቴክኒካዊ መረጃ ነው።"
                    )
                elif "NETWORK" in categories_present:
                    relevance = "MEDIUM"
                    reason_en = "Network communication primitives identified; relevant for financial network egress monitoring."
                    reason_am = "የ Network የመረጃ ልውውጥ አመልካቾች ተለይተዋል፤ ለፋይናንስ ተቋማት የኔትወርክ ቁጥጥር አስፈላጊ ነው።"
                else:
                    relevance = "LOW"
                    reason_en = "Standard static profile; baseline defensive monitoring recommended for Financial networks."
                    reason_am = "መደበኛ የ PE ፋይል ገጽታ፤ ለፋይናንስ ዘርፍ መደበኛ የመከላከያ ክትትል ይመከራል።"

            elif env_norm == "GOVERNMENT":
                if "PERSISTENCE" in categories_present or "COMMAND_EXECUTION" in categories_present:
                    relevance = "HIGH" if has_high_indicators else "MEDIUM"
                    reason_en = (
                        "Persistence and command-line execution indicators identified; "
                        "relevant for public administration workstations and institutional servers."
                    )
                    reason_am = (
                        "የ Persistence እና የትዕዛዝ ማስፈጸሚያ (Command Execution) አመልካቾች ተለይተዋል፤ "
                        "ይህም ለመንግስታዊ አስተዳደር ኮምፒውተሮች እና አገልጋዮች ትኩረት የሚሻ ነው።"
                    )
                elif "NETWORK" in categories_present:
                    relevance = "MEDIUM"
                    reason_en = "Network connectivity artifacts present; relevant for government agency perimeter inspection."
                    reason_am = "የ Network ግንኙነት መረጃዎች ተገኝተዋል፤ ለመንግስት ተቋማት የኔትወርክ ፍተሻ የሚጠቅም ነው።"
                else:
                    relevance = "LOW"
                    reason_en = "Baseline profile; standard defensive posture recommended for Government networks."
                    reason_am = "መደበኛ የ PE ገጽታ፤ ለመንግስት ዘርፍ መደበኛ የደህንነት ክትትል ይመከራል።"

            elif env_norm == "TELECOMMUNICATIONS":
                if "NETWORK" in categories_present or "PROCESS" in categories_present:
                    relevance = "HIGH" if has_high_indicators else "MEDIUM"
                    reason_en = (
                        "Network communication artifacts and process primitives identified; "
                        "relevant for ISP routing, gateway infrastructure, and telecom operations."
                    )
                    reason_am = (
                        "የ Network እና የ Process አመልካቾች ተለይተዋል፤ "
                        "ይህም ለቴሌኮም እና የኔትወርክ አገልግሎት ሰጪዎች መሠረተ-ልማት የጥበቃ ክትትል ጠቃሚ ነው።"
                    )
                else:
                    relevance = "LOW"
                    reason_en = "Standard executable profile; baseline monitoring for Telecommunications environments."
                    reason_am = "መደበኛ የፋይል መዋቅር፤ ለቴሌኮሙኒኬሽን ዘርፍ መደበኛ ክትትል ይመከራል።"

            elif env_norm == "UNIVERSITY":
                if "FILE_ACTIVITY" in categories_present or "PERSISTENCE" in categories_present:
                    relevance = "MEDIUM"
                    reason_en = (
                        "File activity and persistence mechanisms identified; "
                        "relevant for academic labs, shared computer centers, and campus endpoints."
                    )
                    reason_am = (
                        "የፋይል እንቅስቃሴ (File Activity) እና Persistence አመልካቾች ተለይተዋል፤ "
                        "ይህም ለዩኒቨርሲቲ ላቦራቶሪዎች እና የጋራ ኮምፒውተሮች ጥበቃ አግባብነት አለው።"
                    )
                else:
                    relevance = "LOW"
                    reason_en = "Standard profile; baseline workstation protection for University environments."
                    reason_am = "መደበኛ የ PE መዋቅር፤ ለዩኒቨርሲቲ ኮምፒውተሮች መደበኛ የደህንነት ጥበቃ ይመከራል።"

            elif env_norm == "HEALTHCARE":
                if "FILE_ACTIVITY" in categories_present or "COMMAND_EXECUTION" in categories_present:
                    relevance = "MEDIUM"
                    reason_en = (
                        "File manipulation capabilities identified; "
                        "relevant for hospital management systems and patient records availability."
                    )
                    reason_am = (
                        "የፋይል ለውጥ የማድረግ ቴክኒካዊ አመልካቾች ተገኝተዋል፤ "
                        "ለጤና ተቋማት እና ለታካሚዎች መረጃ ዳታቤዝ ደህንነት ጠቃሚ መረጃ ነው።"
                    )
                else:
                    relevance = "LOW"
                    reason_en = "Standard static profile; baseline monitoring for Healthcare networks."
                    reason_am = "መደበኛ የፋይል ይዘት፤ ለጤና ዘርፍ መደበኛ ጥበቃ ይመከራል።"

            elif env_norm == "ENTERPRISE":
                if "NETWORK" in categories_present or "PERSISTENCE" in categories_present:
                    relevance = "MEDIUM"
                    reason_en = "Network communication and persistence primitives identified; relevant for corporate endpoints."
                    reason_am = "የ Network እና የ Persistence አመልካቾች ተገኝተዋል፤ ለንግድ ድርጅቶች የኮምፒውተር ጥበቃ የሚረዳ ነው።"
                else:
                    relevance = "LOW"
                    reason_en = "Standard executable profile; baseline monitoring for Enterprise environments."
                    reason_am = "መደበኛ የ PE ይዘት፤ ለድርጅቶች መደበኛ የጸጥታ ክትትል ይመከራል።"

            else:  # GENERAL
                if has_high_indicators or threat_score >= 60:
                    relevance = "HIGH" if threat_score >= 80 else "MEDIUM"
                    reason_en = f"Elevated static risk profile (Score: {threat_score}/100); general defensive inspection advised."
                    reason_am = f"ከፍተኛ የቴክኒክ አመልካች ውጤት (Score: {threat_score}/100)፤ አጠቃላይ የደህንነት ፍተሻ ይመከራል።"
                else:
                    relevance = "LOW"
                    reason_en = "Standard executable baseline profile; general security monitoring applied."
                    reason_am = "መደበኛ የ PE ፋይል ገጽታ፤ አጠቃላይ የሳይበር ደህንነት ክትትል ይመከራል።"

        chosen_reason = reason_am if lang_norm == "am" else reason_en

        return ContextAssessment(
            environment=env_norm,
            relevance=relevance,
            reason=chosen_reason,
            language=lang_norm
        )

    def analyze_context(
        self,
        indicators: List[SuspiciousIndicator],
        strings: Optional[StringAnalysisResult] = None,
        threat_score: int = 0,
        preferred_environment: str = "GENERAL",
        language: str = "en"
    ) -> EthiopianContextAnalysisResult:
        """
        Generates full contextual prioritization across all Ethiopian sectors.
        """
        explicit_artifacts = self._extract_explicit_domestic_artifacts(strings)
        has_domestic = len(explicit_artifacts) > 0

        # Assess each standard sector
        assessments: List[ContextAssessment] = []
        for env in ENVIRONMENTS:
            assessment = self.evaluate_sector(
                target_env=env,
                indicators=indicators,
                strings=strings,
                threat_score=threat_score,
                language=language
            )
            assessments.append(assessment)

        # Primary selected environment
        selected = self.evaluate_sector(
            target_env=preferred_environment,
            indicators=indicators,
            strings=strings,
            threat_score=threat_score,
            language=language
        )

        return EthiopianContextAnalysisResult(
            environment=selected.environment,
            relevance=selected.relevance,
            reason=selected.reason,
            language=selected.language,
            has_explicit_domestic_artifacts=has_domestic,
            explicit_artifacts=explicit_artifacts,
            sector_assessments=assessments,
            is_valid=True
        )


# Global singleton instance
ethiopian_context_engine_service = EthiopianContextEngine()


if __name__ == "__main__":
    import json

    print("=" * 68)
    print("  ETHIO-AI Defender - Module 10: Ethiopian Context Engine Demo")
    print("=" * 68)

    engine = EthiopianContextEngine()

    sample_indicators = [
        SuspiciousIndicator(
            id="IND-MEM-001",
            name="Memory Staging",
            category="MEMORY",
            severity="HIGH",
            evidence="VirtualAlloc + VirtualProtect",
            confidence=0.85,
            explanation="Dynamic memory page permission modification."
        ),
        SuspiciousIndicator(
            id="IND-NET-001",
            name="Network Egress",
            category="NETWORK",
            severity="HIGH",
            evidence="URL + InternetOpenA",
            confidence=0.82,
            explanation="Remote network communication."
        )
    ]

    # English evaluation for UNIVERSITY
    res_en = engine.analyze_context(
        indicators=sample_indicators,
        preferred_environment="UNIVERSITY",
        language="en"
    )
    print("\nEnglish Output Contract:")
    print(json.dumps(res_en.to_dict(), indent=2))

    # Amharic evaluation for FINANCIAL
    res_am = engine.analyze_context(
        indicators=sample_indicators,
        preferred_environment="FINANCIAL",
        language="am"
    )
    print("\nAmharic Output Contract:")
    print(json.dumps(res_am.to_dict(), indent=2, ensure_ascii=False))

    print("=" * 68)
