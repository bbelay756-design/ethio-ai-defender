"""
Module 12: Cybersecurity Learning Mode Engine

Responsibility:
Provides an interactive educational platform for cybersecurity students and reverse-engineering apprentices.
Generates beginner and advanced technical explanations for static analysis findings.

Key Educational Invariants:
1. What is it?
2. Why does it matter?
3. What evidence was found?
4. Does it prove malicious behavior? (Always emphasizes that static features/APIs alone do NOT prove malicious behavior).
5. What should the student learn next?

Never executes suspicious samples. Uses safe static models.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from app.core.logger import logger
from app.education.topics import EDUCATIONAL_TOPICS_DATABASE


# Specific API and Finding mappings to educational topics
FINDING_TOPIC_MAP: Dict[str, str] = {
    "VIRTUALPROTECT": "WINDOWS_APIS",
    "VIRTUALALLOC": "WINDOWS_APIS",
    "OPENPROCESS": "WINDOWS_APIS",
    "CREATEREMOTETHREAD": "WINDOWS_APIS",
    "INTERNETOPEN": "WINDOWS_APIS",
    "URLDOWNLOADTOFILE": "WINDOWS_APIS",
    "REGOPENKEY": "WINDOWS_APIS",
    "REGSETVALUE": "WINDOWS_APIS",
    "WINEXEC": "WINDOWS_APIS",
    "DOS_HEADER": "DOS_HEADER",
    "PE_HEADER": "PE_HEADER",
    "SECTIONS": "SECTIONS",
    "ENTRY_POINT": "ENTRY_POINT",
    "IMPORTS": "IMPORTS",
    "STRINGS": "STRINGS",
    "ENTROPY": "ENTROPY",
    "PACKING": "PACKING",
    "OBFUSCATION": "OBFUSCATION",
    "STATIC_ANALYSIS": "STATIC_ANALYSIS",
    "REVERSE_ENGINEERING": "REVERSE_ENGINEERING",
    "THREAT_INDICATORS": "THREAT_INDICATORS",
}


@dataclass
class EducationalLesson:
    """
    Individual structured educational explanation for a finding matching the Module 12 contract.
    """
    topic: str
    finding: str
    difficulty_level: str  # 'BEGINNER', 'ADVANCED', 'DUAL'
    what_is_it: str
    why_it_matters: str
    evidence_found: str
    proves_malicious: str
    what_to_learn_next: List[str]
    beginner_explanation: str
    advanced_explanation: str
    language: str = "en"

    def to_dict(self) -> Dict[str, Any]:
        """Returns the educational lesson dictionary."""
        return {
            "topic": self.topic,
            "finding": self.finding,
            "difficulty_level": self.difficulty_level,
            "what_is_it": self.what_is_it,
            "why_it_matters": self.why_it_matters,
            "evidence_found": self.evidence_found,
            "proves_malicious": self.proves_malicious,
            "what_to_learn_next": self.what_to_learn_next,
            "beginner_explanation": self.beginner_explanation,
            "advanced_explanation": self.advanced_explanation,
            "language": self.language,
        }


@dataclass
class LearningReport:
    """
    Comprehensive educational learning report generated for an analyzed sample.
    """
    total_lessons: int = 0
    lessons: List[EducationalLesson] = field(default_factory=list)
    language: str = "en"
    is_valid: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Returns the full report dictionary."""
        return {
            "total_lessons": self.total_lessons,
            "language": self.language,
            "lessons": [l.to_dict() for l in self.lessons],
        }


class LearningModeEngine:
    """
    Educational Explanation Engine for Cybersecurity and Reverse-Engineering Training.
    """

    def __init__(self):
        self.db = EDUCATIONAL_TOPICS_DATABASE

    def _resolve_topic_key(self, finding: str, explicit_topic: Optional[str] = None) -> str:
        """Resolves finding name to a normalized database topic key."""
        if explicit_topic and explicit_topic.upper() in self.db:
            return explicit_topic.upper()

        clean_finding = finding.upper().replace(" ", "_").replace(".", "")
        for key, topic_name in FINDING_TOPIC_MAP.items():
            if key in clean_finding:
                return topic_name

        return "STATIC_ANALYSIS"

    def explain_finding(
        self,
        finding: str,
        topic: Optional[str] = None,
        evidence_found: str = "",
        difficulty_level: str = "DUAL",
        language: str = "en"
    ) -> EducationalLesson:
        """
        Generates a comprehensive educational lesson for a specific technical finding.
        """
        lang = "am" if language.lower() in ("am", "amharic") else "en"
        topic_key = self._resolve_topic_key(finding, topic)
        topic_data = self.db.get(topic_key, self.db["STATIC_ANALYSIS"])
        content = topic_data[lang]

        # Specific finding customization
        clean_evidence = evidence_found or (
            f"Observed static artifact related to {finding} in sample binary."
            if lang == "en" else
            f"በናሙና ፋይሉ ውስጥ ከ {finding} ጋር የተያያዘ static መረጃ ተገኝቷል።"
        )

        finding_specific_proves_malicious = content["proves_malicious"]
        if finding.lower() in ("virtualprotect", "virtualalloc", "openprocess"):
            if lang == "en":
                finding_specific_proves_malicious = f"No. This API ({finding}) alone does not prove malicious behavior."
            else:
                finding_specific_proves_malicious = f"አያረጋግጥም። ይህ API ({finding}) ብቻውን የስጋት ወይም የጥቃት ማረጋገጫ ሊሆን አይችልም።"

        # Construct specific beginner and advanced text if finding is specific
        beginner_text = content["beginner_explanation"]
        advanced_text = content["advanced_explanation"]

        if finding.lower() == "virtualprotect":
            if lang == "en":
                beginner_text = "VirtualProtect is a Windows helper that changes the safety rules on a computer memory page, like unlocking a notebook to write new notes."
                advanced_text = "VirtualProtect alters page protection flags via the Virtual Memory Manager (e.g. converting PAGE_READONLY to PAGE_EXECUTE_READWRITE). While essential for JIT engines and dynamic runtime unpackers, writable-and-executable pages violate standard hardware DEP/W^X policies."
            else:
                beginner_text = "VirtualProtect የማህደረ-ትውስታ (Memory) ገጽ የደህንነት ደንብን ለመቀየር የሚረዳ የ Windows API ነው።"
                advanced_text = "VirtualProtect የገጽ ፈቃድን ወደ PAGE_EXECUTE_READWRITE ይቀይራል። ለ JIT compilers ጠቃሚ ሲሆን፣ W+X ፈቃዶች ግን ከመደበኛ የ DEP/W^X መከላከያ ጋር ይጋጫሉ።"

        return EducationalLesson(
            topic=topic_data["category"],
            finding=finding,
            difficulty_level=difficulty_level.upper(),
            what_is_it=content["what_is_it"],
            why_it_matters=content["why_it_matters"],
            evidence_found=clean_evidence,
            proves_malicious=finding_specific_proves_malicious,
            what_to_learn_next=content["what_to_learn_next"],
            beginner_explanation=beginner_text,
            advanced_explanation=advanced_text,
            language=lang
        )

    def generate_learning_report(
        self,
        evidence: Dict[str, Any],
        language: str = "en"
    ) -> LearningReport:
        """
        Generates a complete multi-topic educational report from an analyzed sample's evidence.
        """
        lessons: List[EducationalLesson] = []

        # 1. PE Format & Headers
        lessons.append(self.explain_finding(
            finding="PE File Header Structure",
            topic="PE_HEADER",
            evidence_found=f"Target Architecture: {evidence.get('file_metadata', {}).get('machine_type', 'x64')}",
            language=language
        ))

        # 2. Sections
        sections_info = evidence.get("sections", {})
        if sections_info:
            has_wx = sections_info.get("has_wx_sections", False)
            ev_sec = f"Total Sections: {sections_info.get('total_sections', 0)} (W+X Sections: {has_wx})"
            lessons.append(self.explain_finding(
                finding="PE Sections & Permissions",
                topic="SECTIONS",
                evidence_found=ev_sec,
                language=language
            ))

        # 3. Entropy
        entropy_info = evidence.get("entropy", {})
        if entropy_info:
            ev_ent = f"Calculated Shannon Entropy: {entropy_info.get('file_entropy', 0.0)} [{entropy_info.get('classification', 'NORMAL')}]"
            lessons.append(self.explain_finding(
                finding="Shannon Entropy Measurement",
                topic="ENTROPY",
                evidence_found=ev_ent,
                language=language
            ))

        # 4. Windows APIs & Imports
        imports_info = evidence.get("imports", {})
        if imports_info:
            ev_imp = f"Total Imported APIs: {imports_info.get('total_imports', 0)}"
            lessons.append(self.explain_finding(
                finding="Import Address Table & Windows APIs",
                topic="WINDOWS_APIS",
                evidence_found=ev_imp,
                language=language
            ))

        # 5. Indicators & Threat Correlation
        ind_info = evidence.get("indicators", {})
        if ind_info:
            ev_ind = f"Correlated Indicators Count: {ind_info.get('total_indicators', 0)}"
            lessons.append(self.explain_finding(
                finding="Correlated Static Threat Indicators",
                topic="THREAT_INDICATORS",
                evidence_found=ev_ind,
                language=language
            ))

        return LearningReport(
            total_lessons=len(lessons),
            lessons=lessons,
            language=language,
            is_valid=True
        )


# Global singleton instance
learning_mode_service = LearningModeEngine()


if __name__ == "__main__":
    import json

    print("=" * 68)
    print("  ETHIO-AI Defender - Module 12: Learning Mode Engine Demo")
    print("=" * 68)

    engine = LearningModeEngine()

    # Explain VirtualProtect finding
    lesson = engine.explain_finding(
        finding="VirtualProtect",
        topic="WINDOWS_APIS",
        evidence_found="Imported in KERNEL32.dll with VirtualAlloc",
        language="en"
    )

    print("\nEnglish Educational Finding Contract (JSON):")
    print(json.dumps(lesson.to_dict(), indent=2))

    # Amharic explanation
    lesson_am = engine.explain_finding(
        finding="VirtualProtect",
        topic="WINDOWS_APIS",
        evidence_found="በ KERNEL32.dll ውስጥ ተገኝቷል",
        language="am"
    )
    print("\nAmharic Educational Finding Contract (JSON):")
    print(json.dumps(lesson_am.to_dict(), indent=2, ensure_ascii=False))

    print("=" * 68)
