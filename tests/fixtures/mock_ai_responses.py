"""
Mock AI Responses and Grounding Adversarial Fixtures for AI Security Testing.
"""

from typing import Dict, Any

# Valid, well-grounded AI report response
MOCK_VALID_AI_REPORT: Dict[str, Any] = {
    "assessment": "LOW",
    "confidence": "HIGH",
    "summary": "The analyzed binary displays a typical PE executable structure with standard section alignment and baseline imported APIs.",
    "key_findings": [
        "Standard PE32 header structure observed.",
        "Low Shannon entropy across sections indicates uncompressed code.",
    ],
    "evidence": [
        "Observed PE sections: .text, .data",
        "Calculated entropy: 2.5 (Normal)",
    ],
    "possible_benign_explanations": [
        "Legitimate compiled Windows utility.",
    ],
    "recommended_investigation": [
        "Review internal application whitelist.",
    ],
    "limitations": [
        "Static analysis does not simulate live execution.",
    ],
}

# Adversarial: AI invents a non-existent indicator or malware family
MOCK_HALLUCINATED_FAMILY_AI_REPORT: Dict[str, Any] = {
    "assessment": "CRITICAL",
    "confidence": "HIGH",
    "summary": "Confirmed infection with DarkSide Ransomware targeting Ethiopian banking infrastructure.",
    "key_findings": [
        "Ransomware signature DarkSide detected.",
        "C2 communication active on port 4444.",
    ],
    "evidence": [
        "DarkSide family signature found.",
    ],
    "possible_benign_explanations": [],
    "recommended_investigation": [
        "Isolate host immediately.",
    ],
    "limitations": [],
}

# Adversarial: AI claims runtime behavior from purely static evidence
MOCK_RUNTIME_CLAIM_AI_REPORT: Dict[str, Any] = {
    "assessment": "HIGH",
    "confidence": "HIGH",
    "summary": "Binary executed and spawned powershell.exe which exfiltrated data to remote IP 1.2.3.4.",
    "key_findings": [
        "Binary executed successfully in background.",
        "Data was transmitted over socket connection.",
    ],
    "evidence": [
        "Process spawned and network traffic captured.",
    ],
    "possible_benign_explanations": [],
    "recommended_investigation": [
        "Terminate running process PID.",
    ],
    "limitations": [],
}

# Adversarial: AI makes claims directly contradictory to observed evidence
# (e.g. evidence says 0 network APIs, but AI claims network egress observed)
MOCK_CONTRADICTORY_AI_REPORT: Dict[str, Any] = {
    "assessment": "HIGH",
    "confidence": "HIGH",
    "summary": "Network communication was observed transmitting encrypted credentials.",
    "key_findings": [
        "Network imports detected.",
    ],
    "evidence": [
        "Active InternetOpenA and HttpSendRequestA APIs present.",
    ],
    "possible_benign_explanations": [],
    "recommended_investigation": [
        "Block network IP.",
    ],
    "limitations": [],
}
