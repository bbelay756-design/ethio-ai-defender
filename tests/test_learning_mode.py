"""
Unit tests for Module 12: Cybersecurity Learning Mode.

Tests:
1. Topic coverage across all 14 required topics.
2. 5-point explanation structure for findings (What is it, Why it matters, Evidence found, Proves malicious, Next steps).
3. Beginner and Advanced explanations for VirtualProtect.
4. Mandatory non-malicious disclaimer verification ('does not prove malicious behavior').
5. Amharic localized lesson generation with technical terms preserved.
6. Batch sample educational report generation.
7. Output schema contract dictionary validation.
"""

import unittest

from app.education.topics import EDUCATIONAL_TOPICS_DATABASE
from app.education.learning_mode import LearningModeEngine, EducationalLesson, LearningReport


class TestCybersecurityLearningMode(unittest.TestCase):
    """Unit test suite for Cybersecurity Learning Mode."""

    def setUp(self):
        self.engine = LearningModeEngine()

    def test_all_14_topics_covered(self):
        """Verify that all 14 required cybersecurity topics exist in the database."""
        required_topics = {
            "PE_FORMAT", "DOS_HEADER", "PE_HEADER", "SECTIONS", "ENTRY_POINT",
            "IMPORTS", "WINDOWS_APIS", "STRINGS", "ENTROPY", "PACKING",
            "OBFUSCATION", "STATIC_ANALYSIS", "REVERSE_ENGINEERING", "THREAT_INDICATORS"
        }
        self.assertTrue(required_topics.issubset(set(EDUCATIONAL_TOPICS_DATABASE.keys())))

        for topic in required_topics:
            lesson = self.engine.explain_finding(finding=topic, topic=topic, language="en")
            self.assertTrue(len(lesson.what_is_it) > 0)
            self.assertTrue(len(lesson.why_it_matters) > 0)
            self.assertTrue(len(lesson.proves_malicious) > 0)
            self.assertGreaterEqual(len(lesson.what_to_learn_next), 1)

    def test_virtualprotect_beginner_and_advanced_explanations(self):
        """Verify beginner and advanced explanations for VirtualProtect."""
        lesson = self.engine.explain_finding(
            finding="VirtualProtect",
            topic="WINDOWS_APIS",
            evidence_found="VirtualProtect imported in KERNEL32.dll",
            language="en"
        )
        self.assertEqual(lesson.finding, "VirtualProtect")
        self.assertEqual(lesson.topic, "Windows APIs")
        self.assertTrue(len(lesson.beginner_explanation) > 0)
        self.assertTrue(len(lesson.advanced_explanation) > 0)
        self.assertIn("memory", lesson.beginner_explanation.lower())
        self.assertIn("page", lesson.advanced_explanation.lower())

    def test_explicit_non_malicious_disclaimer(self):
        """Verify every finding states that static evidence alone does NOT prove malicious behavior."""
        for finding_name in ["VirtualProtect", "VirtualAlloc", "Shannon Entropy", "W+X Section", "DOS Header"]:
            lesson = self.engine.explain_finding(finding=finding_name, language="en")
            disclaimer_lower = lesson.proves_malicious.lower()
            self.assertIn("does not prove malicious behavior", disclaimer_lower)

    def test_amharic_educational_lesson(self):
        """Verify Amharic educational lesson generation with technical terms preserved."""
        lesson = self.engine.explain_finding(
            finding="VirtualProtect",
            topic="WINDOWS_APIS",
            language="am"
        )
        self.assertEqual(lesson.language, "am")
        # Technical keywords preserved in Amharic text
        self.assertTrue("VirtualProtect" in lesson.proves_malicious or "API" in lesson.proves_malicious)
        self.assertTrue(len(lesson.what_is_it) > 0)
        self.assertTrue(len(lesson.what_to_learn_next) > 0)

    def test_batch_sample_learning_report(self):
        """Verify generating a comprehensive educational report from sample evidence."""
        sample_evidence = {
            "file_metadata": {"machine_type": "x64"},
            "sections": {"total_sections": 4, "has_wx_sections": False},
            "entropy": {"file_entropy": 6.32, "classification": "NORMAL"},
            "imports": {"total_imports": 12},
            "indicators": {"total_indicators": 2}
        }
        report = self.engine.generate_learning_report(sample_evidence, language="en")

        self.assertIsInstance(report, LearningReport)
        self.assertGreaterEqual(report.total_lessons, 5)
        self.assertEqual(len(report.lessons), report.total_lessons)

    def test_output_schema_contract(self):
        """Verify exact schema contract matching the specification."""
        lesson = self.engine.explain_finding(
            finding="VirtualProtect",
            topic="WINDOWS_APIS",
            evidence_found="Imported in KERNEL32.dll",
            language="en"
        )
        d = lesson.to_dict()

        expected_keys = {
            "topic",
            "finding",
            "difficulty_level",
            "what_is_it",
            "why_it_matters",
            "evidence_found",
            "proves_malicious",
            "what_to_learn_next",
            "beginner_explanation",
            "advanced_explanation",
            "language"
        }
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertEqual(d["finding"], "VirtualProtect")
        self.assertIn("does not prove malicious behavior", d["proves_malicious"].lower())


if __name__ == "__main__":
    unittest.main()
