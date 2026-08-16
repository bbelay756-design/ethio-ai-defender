"""
Security Report Data Models and Evidence Epistemological Classification

Defines the 16 standard report sections and the three-tier Evidence Model:
- OBSERVED       : Concrete, verified deterministic static observations (e.g. imports, headers, hashes).
- RULE-BASED     : Heuristic correlated rules and scoring algorithms (e.g. indicators, risk score).
- AI-INTERPRETED : Qualified AI interpretations, hypotheses, and analyst recommendations.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone


class EvidenceTier(str, Enum):
    """
    Epistemological certainty level for report findings.
    """
    OBSERVED = "OBSERVED"
    RULE_BASED = "RULE-BASED"
    AI_INTERPRETED = "AI-INTERPRETED"


@dataclass
class ClassifiedStatement:
    """
    Individual finding classified by its evidence certainty tier.
    """
    tier: EvidenceTier
    category: str
    statement: str
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tier": self.tier.value,
            "category": self.category,
            "statement": self.statement,
            "details": self.details or "",
        }


@dataclass
class SecurityReport:
    """
    Comprehensive unified Security Analysis Report covering all 16 required sections.
    """
    # Metadata
    report_id: str
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    language: str = "en"
    disclaimer: str = "Risk score is a heuristic analyst-support metric and is not a confirmed probability of maliciousness."

    # 16 Required Report Sections
    # 1. Executive Summary
    executive_summary: str = ""
    # 2. File Information
    file_information: Dict[str, Any] = field(default_factory=dict)
    # 3. Hashes
    hashes: Dict[str, str] = field(default_factory=dict)
    # 4. PE Information
    pe_information: Dict[str, Any] = field(default_factory=dict)
    # 5. Section Analysis
    section_analysis: Dict[str, Any] = field(default_factory=dict)
    # 6. Entropy Analysis
    entropy_analysis: Dict[str, Any] = field(default_factory=dict)
    # 7. String Analysis
    string_analysis: Dict[str, Any] = field(default_factory=dict)
    # 8. Import/API Analysis
    import_api_analysis: Dict[str, Any] = field(default_factory=dict)
    # 9. Suspicious Indicators
    suspicious_indicators: List[Dict[str, Any]] = field(default_factory=list)
    # 10. Threat Score
    threat_score: Dict[str, Any] = field(default_factory=dict)
    # 11. Ethiopian Context
    ethiopian_context: Dict[str, Any] = field(default_factory=dict)
    # 12. AI Assessment
    ai_assessment: Dict[str, Any] = field(default_factory=dict)
    # 13. Evidence (Tri-tiered Classified Statements)
    evidence: List[ClassifiedStatement] = field(default_factory=list)
    # 14. Possible Benign Explanations
    possible_benign_explanations: List[str] = field(default_factory=list)
    # 15. Recommended Investigation
    recommended_investigation: List[str] = field(default_factory=list)
    # 16. Limitations
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the complete 16-section dictionary matching the Module 13 contract."""
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "language": self.language,
            "disclaimer": self.disclaimer,
            "sections": {
                "1_executive_summary": self.executive_summary,
                "2_file_information": self.file_information,
                "3_hashes": self.hashes,
                "4_pe_information": self.pe_information,
                "5_section_analysis": self.section_analysis,
                "6_entropy_analysis": self.entropy_analysis,
                "7_string_analysis": self.string_analysis,
                "8_import_api_analysis": self.import_api_analysis,
                "9_suspicious_indicators": self.suspicious_indicators,
                "10_threat_score": self.threat_score,
                "11_ethiopian_context": self.ethiopian_context,
                "12_ai_assessment": self.ai_assessment,
                "13_evidence": [e.to_dict() for e in self.evidence],
                "14_possible_benign_explanations": self.possible_benign_explanations,
                "15_recommended_investigation": self.recommended_investigation,
                "16_limitations": self.limitations,
            }
        }
