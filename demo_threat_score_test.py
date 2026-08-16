"""
Live Demonstration Script for Module 09: Threat Scoring Engine.
"""

import json
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.threat_scoring import ThreatScoringEngine, classify_risk_level
from app.analyzers.indicator_engine import SuspiciousIndicator


def main():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 09: THREAT SCORING ENGINE DEMO")
    print("=" * 72)

    engine = ThreatScoringEngine()

    # 1. Demonstrate Risk Level Tiers
    print("\n[Scenario 1] Standard Risk Level Tiers:")
    for test_score in [10, 30, 50, 70, 90]:
        tier = classify_risk_level(test_score)
        print(f"  - Score {test_score:>3}/100 -> Risk Level: [{tier:<10}]")

    # 2. Score Calculation on a Correlated Sample
    print("\n[Scenario 2] Evaluating Correlated Sample Indicators:")
    sample_indicators = [
        SuspiciousIndicator(
            id="IND-STR-001",
            name="Writable and Executable (W+X) Section Detected",
            category="PE_STRUCTURE",
            severity="HIGH",
            evidence="Section '.shell' has simultaneous W+X rights",
            confidence=0.90,
            explanation="Breaches W^X security policy."
        ),
        SuspiciousIndicator(
            id="IND-PAK-001",
            name="Correlated Code Packing / Compressed Staging Anomaly",
            category="PACKING",
            severity="HIGH",
            evidence="High entropy (7.8) + zero raw size",
            confidence=0.88,
            explanation="Code packing / compressed payload staging."
        ),
        SuspiciousIndicator(
            id="IND-MEM-001",
            name="Correlated Dynamic Memory Allocation and Protection Modification",
            category="MEMORY",
            severity="HIGH",
            evidence="VirtualAlloc + VirtualProtect",
            confidence=0.85,
            explanation="Dynamic memory allocation and permission alteration."
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
            explanation="Remote download capability."
        )
    ]

    result = engine.calculate_score(sample_indicators)

    print(f"\nFinal Heuristic Threat Score : {result.score}/100 [{result.risk_level}]")
    print(f"Mandatory Disclaimer          : \"{result.disclaimer}\"")

    print("\nStructured Output Contract (JSON):")
    print(json.dumps(result.to_dict(), indent=2))

    print("\n" + "=" * 72)
    print("  DEMONSTRATION COMPLETE - TRANSPARENT HEURISTIC SCORING")
    print("=" * 72)


if __name__ == "__main__":
    main()
