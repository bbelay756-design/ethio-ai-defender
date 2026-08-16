"""
Unit tests for Module 07: Windows API Import Analyzer.

Tests:
1. Classification of APIs across all 11 required categories:
   - FILE
   - PROCESS
   - MEMORY
   - NETWORK
   - REGISTRY
   - SERVICE
   - CRYPTOGRAPHY
   - SYSTEM_INFORMATION
   - GUI
   - THREAD
   - SECURITY
2. Custom API registration and dynamic configuration override.
3. Item schema contract verification matching the requested JSON format.
4. Parsing import directories from synthetic PE binaries.
5. Error handling on non-PE data and non-existent file paths.
"""

import tempfile
import unittest
from pathlib import Path

from app.analyzers.import_analyzer import (
    WindowsAPIImportAnalyzer,
    ImportInfo,
    ImportAnalysisResult,
)
from tests.test_section_analyzer import build_custom_sections_pe


class TestWindowsAPIImportAnalyzer(unittest.TestCase):
    """Unit test suite for Windows API Import Analyzer."""

    def setUp(self):
        self.analyzer = WindowsAPIImportAnalyzer()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. Category Classification Tests
    def test_category_file(self):
        """Verify FILE category classification."""
        cat, risk, exp = self.analyzer.classify_api("CreateFileA")
        self.assertEqual(cat, "FILE")
        self.assertIn("file", exp.lower())

        cat, _, _ = self.analyzer.classify_api("ReadFile")
        self.assertEqual(cat, "FILE")

        cat, _, _ = self.analyzer.classify_api("WriteFile")
        self.assertEqual(cat, "FILE")

    def test_category_process(self):
        """Verify PROCESS category classification."""
        cat, risk, exp = self.analyzer.classify_api("CreateProcessA")
        self.assertEqual(cat, "PROCESS")
        self.assertIn("process", exp.lower())

        cat, _, _ = self.analyzer.classify_api("WinExec")
        self.assertEqual(cat, "PROCESS")

        cat, _, _ = self.analyzer.classify_api("ShellExecuteA")
        self.assertEqual(cat, "PROCESS")

    def test_category_memory(self):
        """Verify MEMORY category classification."""
        cat, risk, exp = self.analyzer.classify_api("VirtualAlloc")
        self.assertEqual(cat, "MEMORY")
        self.assertEqual(risk, "MEDIUM")

        cat, risk, _ = self.analyzer.classify_api("VirtualProtect")
        self.assertEqual(cat, "MEMORY")

        cat, risk, _ = self.analyzer.classify_api("WriteProcessMemory")
        self.assertEqual(cat, "MEMORY")
        self.assertEqual(risk, "HIGH")

    def test_category_network(self):
        """Verify NETWORK category classification."""
        cat, risk, exp = self.analyzer.classify_api("InternetOpenA")
        self.assertEqual(cat, "NETWORK")

        cat, risk, _ = self.analyzer.classify_api("URLDownloadToFileA")
        self.assertEqual(cat, "NETWORK")
        self.assertEqual(risk, "HIGH")

        cat, _, _ = self.analyzer.classify_api("connect")
        self.assertEqual(cat, "NETWORK")

    def test_category_registry(self):
        """Verify REGISTRY category classification."""
        cat, _, exp = self.analyzer.classify_api("RegOpenKeyExA")
        self.assertEqual(cat, "REGISTRY")

        cat, _, _ = self.analyzer.classify_api("RegSetValueExA")
        self.assertEqual(cat, "REGISTRY")

    def test_category_service(self):
        """Verify SERVICE category classification."""
        cat, _, exp = self.analyzer.classify_api("OpenSCManagerA")
        self.assertEqual(cat, "SERVICE")

        cat, risk, _ = self.analyzer.classify_api("CreateServiceA")
        self.assertEqual(cat, "SERVICE")
        self.assertEqual(risk, "HIGH")

    def test_category_cryptography(self):
        """Verify CRYPTOGRAPHY category classification."""
        cat, _, exp = self.analyzer.classify_api("CryptAcquireContextA")
        self.assertEqual(cat, "CRYPTOGRAPHY")

        cat, _, _ = self.analyzer.classify_api("CryptEncrypt")
        self.assertEqual(cat, "CRYPTOGRAPHY")

    def test_category_system_information(self):
        """Verify SYSTEM_INFORMATION category classification."""
        cat, _, exp = self.analyzer.classify_api("GetSystemInfo")
        self.assertEqual(cat, "SYSTEM_INFORMATION")

        cat, _, _ = self.analyzer.classify_api("IsDebuggerPresent")
        self.assertEqual(cat, "SYSTEM_INFORMATION")

        cat, _, _ = self.analyzer.classify_api("GetComputerNameA")
        self.assertEqual(cat, "SYSTEM_INFORMATION")

    def test_category_gui(self):
        """Verify GUI category classification."""
        cat, _, exp = self.analyzer.classify_api("MessageBoxA")
        self.assertEqual(cat, "GUI")

        cat, _, _ = self.analyzer.classify_api("ShowWindow")
        self.assertEqual(cat, "GUI")

    def test_category_thread(self):
        """Verify THREAD category classification."""
        cat, _, exp = self.analyzer.classify_api("CreateThread")
        self.assertEqual(cat, "THREAD")

        cat, risk, _ = self.analyzer.classify_api("CreateRemoteThread")
        self.assertEqual(cat, "THREAD")
        self.assertEqual(risk, "HIGH")

    def test_category_security(self):
        """Verify SECURITY category classification."""
        cat, risk, exp = self.analyzer.classify_api("AdjustTokenPrivileges")
        self.assertEqual(cat, "SECURITY")
        self.assertEqual(risk, "HIGH")

        cat, _, _ = self.analyzer.classify_api("OpenProcessToken")
        self.assertEqual(cat, "SECURITY")

    # 2. Dynamic Configuration & Registration Tests
    def test_dynamic_api_registration(self):
        """Verify adding custom API definitions dynamically."""
        self.analyzer.register_api(
            api_name="CustomSecurityAuditAPI",
            category="SECURITY",
            risk_relevance="LOW",
            explanation="Custom Ethiopian SOC auditing API."
        )
        cat, risk, exp = self.analyzer.classify_api("CustomSecurityAuditAPI")
        self.assertEqual(cat, "SECURITY")
        self.assertEqual(risk, "LOW")
        self.assertIn("Ethiopian SOC", exp)

    # 3. Item & Output Schema Contract Tests
    def test_item_schema_contract(self):
        """Verify the exact dictionary contract structure requested for Module 07."""
        item = ImportInfo(
            dll="KERNEL32.dll",
            api="VirtualAlloc",
            category="MEMORY",
            risk_relevance="MEDIUM",
            explanation="Allocates virtual memory."
        )
        d = item.to_dict()
        expected = {
            "dll": "KERNEL32.dll",
            "api": "VirtualAlloc",
            "category": "MEMORY",
            "risk_relevance": "MEDIUM",
            "explanation": "Allocates virtual memory."
        }
        self.assertEqual(d, expected)

    # 4. Binary Analysis & Error Handling Tests
    def test_analyze_pe_binary_bytes(self):
        """Verify parsing a valid PE binary returns an ImportAnalysisResult."""
        spec = [(".text", 0x1000, 0x200, 0x60000020)]
        pe_bytes = build_custom_sections_pe(spec)
        res = self.analyzer.analyze_bytes(pe_bytes)

        self.assertTrue(res.is_valid)
        self.assertIsInstance(res.imports, list)
        self.assertIsInstance(res.categories_summary, dict)

    def test_non_pe_data_handling(self):
        """Verify non-PE binary data returns a clean invalid result."""
        res = self.analyzer.analyze_bytes(b"NOT A PE BINARY CONTENT")
        self.assertFalse(res.is_valid)
        self.assertIn("not a valid Windows PE", res.error_message)

    def test_missing_file_handling(self):
        """Verify attempting to analyze a non-existent file returns a clean failure."""
        missing = Path(self.temp_dir.name) / "no_such_file.exe"
        res = self.analyzer.analyze_file(missing)

        self.assertFalse(res.is_valid)
        self.assertIn("not found", res.error_message)


if __name__ == "__main__":
    unittest.main()
