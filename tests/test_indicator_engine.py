"""
Unit tests for Module 08: Suspicious Indicator Engine.

Tests:
1. Rule test for Category PE_STRUCTURE (W+X sections).
2. Rule test for Category PACKING (High entropy + section expansion).
3. Rule test for Category MEMORY (VirtualAlloc + VirtualProtect).
4. Rule test for Category PROCESS (OpenProcess + CreateRemoteThread).
5. Rule test for Category NETWORK (URLs/IPs + Network APIs).
6. Rule test for Category PERSISTENCE (Registry Run keys + RegSetValueEx).
7. Rule test for Category COMMAND_EXECUTION (cmd/PowerShell + Process execution).
8. Rule test for Category OBFUSCATION (IsDebuggerPresent + high entropy).
9. Rule test for Category FILE_ACTIVITY (CreateFile + temp directory).
10. Rule test for Category REGISTRY (RegOpenKeyEx + registry paths).
11. Correlated vs single-feature verification (naive single feature does not over-trigger).
12. Custom indicator rule registration.
13. Output schema contract dictionary test.
"""

import unittest

from app.analyzers.indicator_engine import (
    SuspiciousIndicatorEngine,
    SuspiciousIndicator,
    IndicatorAnalysisResult,
    AnalysisContext,
)
from app.analyzers.section_analyzer import PESectionAnalysisResult, SectionInfo
from app.analyzers.entropy_analyzer import EntropyAnalysisResult, SectionEntropyResult
from app.analyzers.string_analyzer import StringAnalysisResult
from app.analyzers.import_analyzer import ImportAnalysisResult, ImportInfo


class TestSuspiciousIndicatorEngine(unittest.TestCase):
    """Unit test suite for Suspicious Indicator Engine."""

    def setUp(self):
        self.engine = SuspiciousIndicatorEngine()

    def test_rule_pe_structure_wx(self):
        """Verify detection of W+X section structural indicator."""
        sec_res = PESectionAnalysisResult(
            total_sections=1,
            has_wx_sections=True,
            anomalous_sections_count=1,
            sections=[
                SectionInfo(
                    name=".shell",
                    virtual_address="0x1000",
                    virtual_size=4096,
                    raw_size=4096,
                    raw_offset=512,
                    characteristics=0xE0000020,
                    readable=True,
                    writable=True,
                    executable=True,
                    is_standard_name=False,
                    indicators=["Writable and Executable"]
                )
            ]
        )
        res = self.engine.evaluate(sections=sec_res)

        self.assertGreater(res.total_indicators, 0)
        ind = next((i for i in res.indicators if i.category == "PE_STRUCTURE"), None)
        self.assertIsNotNone(ind)
        self.assertEqual(ind.id, "IND-STR-001")
        self.assertEqual(ind.severity, "HIGH")

    def test_rule_packing_correlation(self):
        """Verify correlation between high section entropy and zero raw size."""
        ent_res = EntropyAnalysisResult(
            file_entropy=7.4,
            sections=[
                SectionEntropyResult(name=".packed", entropy=7.8, classification="VERY_HIGH")
            ]
        )
        sec_res = PESectionAnalysisResult(
            total_sections=1,
            sections=[
                SectionInfo(
                    name=".packed",
                    virtual_address="0x1000",
                    virtual_size=32768,
                    raw_size=0,
                    raw_offset=0,
                    characteristics=0xC0000040,
                    readable=True,
                    writable=True,
                    executable=False
                )
            ]
        )
        res = self.engine.evaluate(entropy=ent_res, sections=sec_res)

        ind = next((i for i in res.indicators if i.category == "PACKING"), None)
        self.assertIsNotNone(ind)
        self.assertEqual(ind.id, "IND-PAK-001")
        self.assertEqual(ind.severity, "HIGH")

    def test_rule_memory_correlation(self):
        """Verify correlation between VirtualAlloc and VirtualProtect."""
        imp_res = ImportAnalysisResult(
            total_imports=2,
            imports=[
                ImportInfo(dll="KERNEL32.dll", api="VirtualAlloc", category="MEMORY", risk_relevance="MEDIUM", explanation=""),
                ImportInfo(dll="KERNEL32.dll", api="VirtualProtect", category="MEMORY", risk_relevance="MEDIUM", explanation=""),
            ]
        )
        res = self.engine.evaluate(imports=imp_res)

        ind = next((i for i in res.indicators if i.category == "MEMORY"), None)
        self.assertIsNotNone(ind)
        self.assertEqual(ind.id, "IND-MEM-001")

    def test_rule_process_injection_correlation(self):
        """Verify correlation between OpenProcess and CreateRemoteThread."""
        imp_res = ImportAnalysisResult(
            total_imports=2,
            imports=[
                ImportInfo(dll="KERNEL32.dll", api="OpenProcess", category="PROCESS", risk_relevance="MEDIUM", explanation=""),
                ImportInfo(dll="KERNEL32.dll", api="CreateRemoteThread", category="THREAD", risk_relevance="HIGH", explanation=""),
            ]
        )
        res = self.engine.evaluate(imports=imp_res)

        ind = next((i for i in res.indicators if i.category == "PROCESS"), None)
        self.assertIsNotNone(ind)
        self.assertEqual(ind.id, "IND-PROC-001")
        self.assertEqual(ind.severity, "HIGH")

    def test_rule_network_correlation(self):
        """Verify correlation between embedded URLs and network download APIs."""
        str_res = StringAnalysisResult(
            urls=["https://threat-c2.net/payload.exe"],
            ip_addresses=["192.168.1.1"]
        )
        imp_res = ImportAnalysisResult(
            imports=[
                ImportInfo(dll="URLMON.dll", api="URLDownloadToFileA", category="NETWORK", risk_relevance="HIGH", explanation="")
            ]
        )
        res = self.engine.evaluate(strings=str_res, imports=imp_res)

        ind = next((i for i in res.indicators if i.category == "NETWORK"), None)
        self.assertIsNotNone(ind)
        self.assertEqual(ind.id, "IND-NET-001")
        self.assertEqual(ind.severity, "HIGH")

    def test_rule_persistence_correlation(self):
        """Verify correlation between Registry Run keys and RegSetValueEx."""
        str_res = StringAnalysisResult(
            registry_paths=["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
        )
        imp_res = ImportAnalysisResult(
            imports=[
                ImportInfo(dll="ADVAPI32.dll", api="RegSetValueExA", category="REGISTRY", risk_relevance="MEDIUM", explanation="")
            ]
        )
        res = self.engine.evaluate(strings=str_res, imports=imp_res)

        ind = next((i for i in res.indicators if i.category == "PERSISTENCE"), None)
        self.assertIsNotNone(ind)
        self.assertEqual(ind.id, "IND-PER-001")
        self.assertEqual(ind.severity, "HIGH")

    def test_rule_command_execution_correlation(self):
        """Verify correlation between cmd/PowerShell strings and WinExec/CreateProcess."""
        str_res = StringAnalysisResult(
            commands=["cmd.exe /c whoami >> C:\\out.txt"],
            powershell_references=["powershell -ExecutionPolicy Bypass"]
        )
        imp_res = ImportAnalysisResult(
            imports=[
                ImportInfo(dll="KERNEL32.dll", api="WinExec", category="PROCESS", risk_relevance="MEDIUM", explanation="")
            ]
        )
        res = self.engine.evaluate(strings=str_res, imports=imp_res)

        ind = next((i for i in res.indicators if i.category == "COMMAND_EXECUTION"), None)
        self.assertIsNotNone(ind)
        self.assertEqual(ind.id, "IND-CMD-001")
        self.assertEqual(ind.severity, "HIGH")

    def test_rule_obfuscation_correlation(self):
        """Verify correlation between anti-debugging APIs and dense entropy."""
        ent_res = EntropyAnalysisResult(file_entropy=6.9)
        imp_res = ImportAnalysisResult(
            imports=[
                ImportInfo(dll="KERNEL32.dll", api="IsDebuggerPresent", category="SYSTEM_INFORMATION", risk_relevance="MEDIUM", explanation="")
            ]
        )
        res = self.engine.evaluate(entropy=ent_res, imports=imp_res)

        ind = next((i for i in res.indicators if i.category == "OBFUSCATION"), None)
        self.assertIsNotNone(ind)
        self.assertEqual(ind.id, "IND-OBF-001")

    def test_rule_file_activity_correlation(self):
        """Verify correlation between CreateFile and temporary directory paths."""
        str_res = StringAnalysisResult(
            file_paths=["C:\\Windows\\Temp\\drop.exe"]
        )
        imp_res = ImportAnalysisResult(
            imports=[
                ImportInfo(dll="KERNEL32.dll", api="CreateFileA", category="FILE", risk_relevance="LOW", explanation="")
            ]
        )
        res = self.engine.evaluate(strings=str_res, imports=imp_res)

        ind = next((i for i in res.indicators if i.category == "FILE_ACTIVITY"), None)
        self.assertIsNotNone(ind)
        self.assertEqual(ind.id, "IND-FIL-001")

    def test_rule_registry_correlation(self):
        """Verify correlation between RegOpenKeyEx and registry paths."""
        str_res = StringAnalysisResult(
            registry_paths=["HKEY_LOCAL_MACHINE\\Software\\Policies"]
        )
        imp_res = ImportAnalysisResult(
            imports=[
                ImportInfo(dll="ADVAPI32.dll", api="RegOpenKeyExA", category="REGISTRY", risk_relevance="LOW", explanation="")
            ]
        )
        res = self.engine.evaluate(strings=str_res, imports=imp_res)

        ind = next((i for i in res.indicators if i.category == "REGISTRY"), None)
        self.assertIsNotNone(ind)
        self.assertEqual(ind.id, "IND-REG-001")

    def test_single_feature_does_not_overtrigger(self):
        """Verify that isolated benign features without correlation do not trigger false positive indicators."""
        # Only benign ReadFile and MessageBox without any anomalous sections, URLs, or injection primitives
        imp_res = ImportAnalysisResult(
            imports=[
                ImportInfo(dll="KERNEL32.dll", api="ReadFile", category="FILE", risk_relevance="LOW", explanation=""),
                ImportInfo(dll="USER32.dll", api="MessageBoxA", category="GUI", risk_relevance="LOW", explanation=""),
            ]
        )
        res = self.engine.evaluate(imports=imp_res)
        self.assertEqual(res.total_indicators, 0)

    def test_custom_rule_registration(self):
        """Verify adding a custom indicator rule."""
        def custom_ethiopia_rule(ctx: AnalysisContext):
            if ctx.strings and any("telecom.et" in d for d in ctx.strings.domains):
                return SuspiciousIndicator(
                    id="IND-ETH-001",
                    name="Ethiopian National Domain Reference Identified",
                    category="NETWORK",
                    severity="LOW",
                    evidence="Referenced Ethiopian national ccTLD domain",
                    confidence=0.95,
                    explanation="Binary references Ethiopian domestic internet infrastructure."
                )
            return None

        self.engine.register_rule(custom_ethiopia_rule)
        str_res = StringAnalysisResult(domains=["c2.telecom.et"])
        res = self.engine.evaluate(strings=str_res)

        ind = next((i for i in res.indicators if i.id == "IND-ETH-001"), None)
        self.assertIsNotNone(ind)
        self.assertEqual(ind.category, "NETWORK")

    def test_output_schema_contract(self):
        """Verify exact schema contract matching the specification."""
        ind = SuspiciousIndicator(
            id="IND-001",
            name="Test Indicator",
            category="MEMORY",
            severity="LOW",
            evidence="Test evidence",
            confidence=0.75,
            explanation="Test explanation"
        )
        d = ind.to_dict()
        expected_keys = {"id", "name", "category", "severity", "evidence", "confidence", "explanation"}
        self.assertEqual(set(d.keys()), expected_keys)


if __name__ == "__main__":
    unittest.main()
