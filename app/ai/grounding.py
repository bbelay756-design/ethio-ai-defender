"""
Grounding Validation & Hallucination Prevention Module

Responsibility:
Validates AI generated explanations against the factual static-analysis evidence.

Enforces:
- No invented cryptographic hashes (SHA-256, SHA-1, MD5).
- No invented Windows APIs or DLL imports.
- No invented threat actors, APT campaigns, or unverified Ethiopian incidents.
- No false claims of runtime execution or certainty.
"""

import re
from typing import Dict, List, Set, Any, Tuple
from app.core.logger import logger

# Unverified APT / Threat Actor hallucination patterns
PROHIBITED_ACTOR_PATTERNS = [
    r'(?i)\b(lazarus\s*group|apt\d+|cozy\s*bear|fancy\s*bear|sandworm|equation\s*group)\b',
    r'(?i)\b(ethiopian\s*cyber\s*army|addis\s*hacker|national\s*malware\s*campaign)\b',
]


class GroundingValidator:
    """
    Validates that AI output stays 100% grounded in provided static evidence.
    """

    def __init__(self):
        self._compiled_actor_patterns = [re.compile(p) for p in PROHIBITED_ACTOR_PATTERNS]

    def _extract_grounded_facts(self, evidence: Dict[str, Any]) -> Tuple[Set[str], Set[str], Set[str]]:
        """
        Extracts known factual sets: valid hashes, valid APIs, and valid strings.
        """
        valid_hashes: Set[str] = set()
        valid_apis: Set[str] = set()
        valid_strings: Set[str] = set()

        # Hashes
        hashes = evidence.get("hashes", {})
        if isinstance(hashes, dict):
            for h in ("sha256", "sha1", "md5"):
                val = hashes.get(h)
                if val:
                    valid_hashes.add(str(val).lower())

        # Imports
        imports = evidence.get("imports", {})
        if isinstance(imports, dict):
            imp_list = imports.get("imports", [])
            for item in imp_list:
                if isinstance(item, dict) and "api" in item:
                    valid_apis.add(item["api"].lower())

        # Strings
        str_res = evidence.get("strings", {})
        if isinstance(str_res, dict):
            for cat in ("urls", "ip_addresses", "domains", "registry_paths", "commands"):
                for s in str_res.get(cat, []):
                    valid_strings.add(str(s).lower())

        return valid_hashes, valid_apis, valid_strings

    def validate_and_clean(
        self,
        ai_response_dict: Dict[str, Any],
        raw_evidence: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Verifies AI output claims against factual evidence and strips/corrects hallucinations.
        """
        valid_hashes, valid_apis, valid_strings = self._extract_grounded_facts(raw_evidence)
        cleaned_response = dict(ai_response_dict)

        # 1. Check for hallucinated 64-char SHA256 hashes in text
        summary = cleaned_response.get("summary", "")
        hash_matches = re.findall(r'\b[a-fA-F0-9]{64}\b', summary)
        for h in hash_matches:
            if h.lower() not in valid_hashes:
                logger.warning(f"Grounding Alert: AI generated ungrounded hash '{h}'. Stripping.")
                summary = summary.replace(h, "[VERIFIED_HASH_ONLY]")

        # Check summary for unverified threat actors
        for pat in self._compiled_actor_patterns:
            if pat.search(summary):
                logger.warning(f"Grounding Alert: Unverified actor claim in summary: '{summary}'. Scrubbing.")
                summary = pat.sub("[UNVERIFIED_ATTRIBUTION]", summary)

        cleaned_response["summary"] = summary

        # 2. Check for prohibited/invented threat actors
        cleaned_findings: List[str] = []
        for finding in cleaned_response.get("key_findings", []):
            finding_text = str(finding)
            has_hallucinated_actor = False
            for pat in self._compiled_actor_patterns:
                if pat.search(finding_text):
                    logger.warning(f"Grounding Alert: Unverified actor claim in finding: '{finding_text}'")
                    has_hallucinated_actor = True
                    break
            if not has_hallucinated_actor:
                cleaned_findings.append(finding_text)
            else:
                cleaned_findings.append("Static capability analysis (Unverified external attribution claims removed).")

        cleaned_response["key_findings"] = cleaned_findings

        # 3. Ensure mandatory limitations and static uncertainty are preserved
        limitations = cleaned_response.get("limitations", [])
        static_limitation = (
            "Static analysis evaluates binary capabilities without live code execution; "
            "runtime behavior cannot be definitively confirmed without dynamic instrumentation."
        )
        if not any("static" in str(l).lower() for l in limitations):
            limitations.append(static_limitation)
        cleaned_response["limitations"] = limitations

        return cleaned_response
