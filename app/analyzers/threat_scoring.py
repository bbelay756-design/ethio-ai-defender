"""
Module 09: Threat Scoring Engine

Responsibility:
Computes a transparent, explainable heuristic risk score from 0 to 100 based on correlated static indicators.

Risk Level Tiers:
-  0 - 20 : LOW
- 21 - 40 : MODERATE
- 41 - 60 : SUSPICIOUS
- 61 - 80 : HIGH
- 81 - 100: CRITICAL

Core Defensive & Mathematical Principles:
- The score is NOT a probability of infection.
- Each indicator contributes configurable points weighted by its severity and confidence.
- Category diminishing returns and caps prevent redundant/duplicate evidence from excessively inflating the score.
- Report Disclaimer: "Risk score is a heuristic analyst-support metric and is not a confirmed probability of maliciousness."
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from app.core.logger import logger
from app.analyzers.indicator_engine import SuspiciousIndicator, IndicatorAnalysisResult

# Standard Disclaimer Text
HEURISTIC_DISCLAIMER = (
    "Risk score is a heuristic analyst-support metric and is not a confirmed probability of maliciousness."
)

# Default Configurable Severity Base Weights
DEFAULT_SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 35.0,
    "HIGH": 25.0,
    "MEDIUM": 15.0,
    "LOW": 5.0,
    "INFO": 0.0,
}

# Diminishing return multipliers for multiple indicators in the same category
CATEGORY_DIMINISHING_MULTIPLIERS = [1.0, 0.5, 0.25, 0.1]
DEFAULT_CATEGORY_MAX_CAP = 40.0


def classify_risk_level(score: int) -> str:
    """
    Classifies an integer score [0, 100] into standard risk tiers:
    - 0-20   : LOW
    - 21-40  : MODERATE
    - 41-60  : SUSPICIOUS
    - 61-80  : HIGH
    - 81-100 : CRITICAL
    """
    if score <= 20:
        return "LOW"
    elif score <= 40:
        return "MODERATE"
    elif score <= 60:
        return "SUSPICIOUS"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"


@dataclass
class IndicatorContribution:
    """
    Individual item breakdown explaining how an indicator contributed to the overall score.
    """
    indicator_id: str
    indicator_name: str
    category: str
    severity: str
    confidence: float
    base_points: float
    points: float
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        """Returns the contribution dictionary."""
        return {
            "indicator_id": self.indicator_id,
            "indicator_name": self.indicator_name,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "points": round(self.points, 2),
            "reason": self.reason,
        }


@dataclass
class ThreatScoreResult:
    """
    Structured outcome of the Threat Scoring Engine.
    """
    score: int = 0
    risk_level: str = "LOW"
    contributions: List[IndicatorContribution] = field(default_factory=list)
    top_indicators: List[str] = field(default_factory=list)
    disclaimer: str = HEURISTIC_DISCLAIMER
    is_valid: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns the exact Module 09 output contract dictionary."""
        return {
            "score": self.score,
            "risk_level": self.risk_level,
            "contributions": [c.to_dict() for c in self.contributions],
            "top_indicators": self.top_indicators,
        }


class ThreatScoringEngine:
    """
    Transparent Heuristic Threat Scoring and Evidence Aggregation Engine.
    """

    def __init__(
        self,
        severity_weights: Optional[Dict[str, float]] = None,
        category_max_cap: float = DEFAULT_CATEGORY_MAX_CAP
    ):
        self.severity_weights = dict(severity_weights or DEFAULT_SEVERITY_WEIGHTS)
        self.category_max_cap = category_max_cap

    def calculate_score(self, indicators: List[SuspiciousIndicator]) -> ThreatScoreResult:
        """
        Calculates a normalized 0-100 heuristic threat score from detected indicators.

        Args:
            indicators: List of SuspiciousIndicator instances from Module 08.

        Returns:
            ThreatScoreResult object.
        """
        if not indicators:
            return ThreatScoreResult(
                score=0,
                risk_level="LOW",
                contributions=[],
                top_indicators=[],
                is_valid=True
            )

        # 1. Group indicators by category to apply category dampening / deduplication
        category_groups: Dict[str, List[SuspiciousIndicator]] = {}
        for ind in indicators:
            category_groups.setdefault(ind.category, []).append(ind)

        contributions: List[IndicatorContribution] = []
        total_raw_points = 0.0

        for cat_name, ind_list in category_groups.items():
            # Sort within category by base severity points descending
            ind_list_sorted = sorted(
                ind_list,
                key=lambda x: self.severity_weights.get(x.severity.upper(), 5.0) * x.confidence,
                reverse=True
            )

            category_points = 0.0

            for idx, ind in enumerate(ind_list_sorted):
                base_pts = self.severity_weights.get(ind.severity.upper(), 5.0)
                # Diminishing return multiplier for repetitive findings in same category
                multiplier = (
                    CATEGORY_DIMINISHING_MULTIPLIERS[idx]
                    if idx < len(CATEGORY_DIMINISHING_MULTIPLIERS)
                    else CATEGORY_DIMINISHING_MULTIPLIERS[-1]
                )

                calculated_pts = base_pts * ind.confidence * multiplier

                # Check if adding exceeds category max cap
                if category_points + calculated_pts > self.category_max_cap:
                    awarded_pts = max(0.0, self.category_max_cap - category_points)
                    reason = f"Points clamped by category '{cat_name}' max cap ({self.category_max_cap})."
                else:
                    awarded_pts = calculated_pts
                    reason = (
                        f"Base {base_pts}pts * {ind.confidence:.2f} conf"
                        + (f" * {multiplier}x dampening" if multiplier < 1.0 else "")
                    )

                category_points += awarded_pts

                contributions.append(IndicatorContribution(
                    indicator_id=ind.id,
                    indicator_name=ind.name,
                    category=ind.category,
                    severity=ind.severity,
                    confidence=ind.confidence,
                    base_points=base_pts,
                    points=awarded_pts,
                    reason=reason
                ))

            total_raw_points += category_points

        # 2. Normalize and clamp score to strictly [0, 100]
        final_score = int(min(100, max(0, round(total_raw_points))))
        risk_level = classify_risk_level(final_score)

        # 3. Format top indicators list
        sorted_contributions = sorted(contributions, key=lambda c: c.points, reverse=True)
        top_indicators = [
            f"{c.indicator_id}: {c.indicator_name} ({c.severity} - {c.points:.1f} pts)"
            for c in sorted_contributions[:5]
        ]

        return ThreatScoreResult(
            score=final_score,
            risk_level=risk_level,
            contributions=contributions,
            top_indicators=top_indicators,
            is_valid=True
        )


# Global singleton instance
threat_scoring_engine_service = ThreatScoringEngine()


if __name__ == "__main__":
    import json

    print("=" * 68)
    print("  ETHIO-AI Defender - Module 09: Threat Scoring Engine Demo")
    print("=" * 68)

    engine = ThreatScoringEngine()

    mock_indicators = [
        SuspiciousIndicator(
            id="IND-MEM-001",
            name="Correlated Dynamic Memory Allocation and Protection Modification",
            category="MEMORY",
            severity="HIGH",
            evidence="VirtualAlloc + VirtualProtect",
            confidence=0.85,
            explanation="Static allocation & protection manipulation."
        ),
        SuspiciousIndicator(
            id="IND-PROC-001",
            name="Correlated Inter-Process Manipulation and Thread Injection",
            category="PROCESS",
            severity="HIGH",
            evidence="OpenProcess + CreateRemoteThread",
            confidence=0.88,
            explanation="Remote thread injection primitives."
        ),
        SuspiciousIndicator(
            id="IND-NET-001",
            name="Correlated Remote Network Endpoints and Communication APIs",
            category="NETWORK",
            severity="HIGH",
            evidence="C2 URL + URLDownloadToFileA",
            confidence=0.82,
            explanation="Remote network download capability."
        )
    ]

    res = engine.calculate_score(mock_indicators)
    print(f"Calculated Score: {res.score}/100 [{res.risk_level}]")
    print(f"Disclaimer: {res.disclaimer}")
    print("\nStructured Output Contract:")
    print(json.dumps(res.to_dict(), indent=2))
    print("=" * 68)
