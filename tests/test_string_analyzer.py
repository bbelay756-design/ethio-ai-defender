"""
Unit tests for Module 06: String Analyzer.

Tests:
1. Extraction of ASCII strings.
2. Extraction of Unicode (UTF-16LE) strings.
3. URL identification & categorization.
4. IPv4 address extraction.
5. Domain name extraction.
6. Registry path extraction.
7. File path extraction.
8. PowerShell command & reference extraction.
9. Shell command (cmd.exe, net user, whoami) extraction.
10. DLL name extraction.
11. Email address extraction.
12. Windows security & system API detection.
13. Minimum string length filtering and boundary handling.
14. File-based static analysis & missing file handling.
15. Output JSON schema contract dictionary formatting.
"""

import tempfile
import unittest
from pathlib import Path

from app.analyzers.string_analyzer import StringAnalyzer, StringAnalysisResult


class TestStringAnalyzer(unittest.TestCase):
    """Unit test suite for the String Analyzer service."""

    def setUp(self):
        self.analyzer = StringAnalyzer(min_length=4)
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_ascii_string_extraction(self):
        """Verify extracting pure ASCII strings."""
        data = b"Some harmless ASCII string in memory\x00\x00\x00Another readable text block\x00"
        res = self.analyzer.analyze_bytes(data)

        self.assertGreater(res.total_strings, 0)
        self.assertTrue(any("Some harmless ASCII" in s for s in res.all_extracted_strings))
        self.assertTrue(any("Another readable" in s for s in res.all_extracted_strings))

    def test_unicode_utf16le_string_extraction(self):
        """Verify extracting Unicode UTF-16LE encoded strings."""
        unicode_str = "Unicode Text String Payload".encode("utf-16le")
        data = b"\x00\x00" + unicode_str + b"\x00\x00"
        res = self.analyzer.analyze_bytes(data)

        self.assertGreater(res.total_strings, 0)
        self.assertTrue(any("Unicode Text String Payload" in s for s in res.all_extracted_strings))

    def test_url_extraction(self):
        """Verify identifying HTTP, HTTPS, and FTP URLs."""
        data = (
            b"https://cyber.gov.et/advisories/sec.pdf\x00"
            b"http://192.168.1.100:8080/stage.bin\x00"
            b"ftp://updates.server.org/files/\x00"
        )
        res = self.analyzer.analyze_bytes(data)

        self.assertEqual(len(res.urls), 3)
        self.assertIn("https://cyber.gov.et/advisories/sec.pdf", res.urls)
        self.assertIn("http://192.168.1.100:8080/stage.bin", res.urls)
        self.assertIn("ftp://updates.server.org/files/", res.urls)

    def test_ipv4_extraction(self):
        """Verify identifying valid IPv4 addresses."""
        data = b"Connecting to host 10.10.14.25 and secondary 192.168.1.1 with invalid 999.999.999.999\x00"
        res = self.analyzer.analyze_bytes(data)

        self.assertIn("10.10.14.25", res.ip_addresses)
        self.assertIn("192.168.1.1", res.ip_addresses)
        self.assertNotIn("999.999.999.999", res.ip_addresses)

    def test_domain_extraction(self):
        """Verify extracting standalone domain names."""
        data = b"Connect to telemetry.ethio-security.et or update.microsoft.com for patches\x00"
        res = self.analyzer.analyze_bytes(data)

        self.assertTrue(any("ethio-security.et" in d for d in res.domains))
        self.assertTrue(any("microsoft.com" in d for d in res.domains))

    def test_registry_path_extraction(self):
        """Verify identifying Windows Registry keys and persistence locations."""
        data = (
            b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
            b"HKEY_CURRENT_USER\\Software\\Classes\\exefile\\shell\\open\\command\x00"
        )
        res = self.analyzer.analyze_bytes(data)

        self.assertEqual(len(res.registry_paths), 2)
        self.assertTrue(any("HKLM\\Software" in r for r in res.registry_paths))
        self.assertTrue(any("HKEY_CURRENT_USER" in r for r in res.registry_paths))

    def test_file_path_extraction(self):
        """Verify identifying Windows absolute and environment file paths."""
        data = (
            b"C:\\Windows\\System32\\drivers\\etc\\hosts\x00"
            b"%APPDATA%\\Roaming\\service.exe\x00"
        )
        res = self.analyzer.analyze_bytes(data)

        self.assertTrue(any("C:\\Windows\\System32" in p for p in res.file_paths))
        self.assertTrue(any("%APPDATA%" in p for p in res.file_paths))

    def test_powershell_reference_extraction(self):
        """Verify identifying PowerShell commands and arguments."""
        data = b"powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgA\x00"
        res = self.analyzer.analyze_bytes(data)

        self.assertEqual(len(res.powershell_references), 1)
        self.assertIn("powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgA", res.powershell_references)

    def test_command_line_extraction(self):
        """Verify identifying command line invocations."""
        data = (
            b"cmd.exe /c whoami >> output.txt\x00"
            b"net user administrator /active:yes\x00"
            b"vssadmin delete shadows /all /quiet\x00"
        )
        res = self.analyzer.analyze_bytes(data)

        self.assertEqual(len(res.commands), 3)
        self.assertTrue(any("whoami" in c for c in res.commands))
        self.assertTrue(any("net user" in c for c in res.commands))
        self.assertTrue(any("vssadmin" in c for c in res.commands))

    def test_dll_and_email_and_api_extraction(self):
        """Verify identifying DLL libraries, contact emails, and known Windows APIs."""
        data = (
            b"kernel32.dll\x00ws2_32.dll\x00"
            b"soc-team@telecom.et\x00"
            b"VirtualAlloc\x00CreateRemoteThread\x00"
        )
        res = self.analyzer.analyze_bytes(data)

        self.assertIn("kernel32.dll", res.dlls)
        self.assertIn("ws2_32.dll", res.dlls)
        self.assertIn("soc-team@telecom.et", res.emails)
        self.assertIn("VirtualAlloc", res.apis)
        self.assertIn("CreateRemoteThread", res.apis)

    def test_minimum_length_filter_and_boundary(self):
        """Verify that strings shorter than min_length (4 bytes) are excluded."""
        data = b"a\x00ab\x00abc\x00abcd\x00abcde\x00"
        res = self.analyzer.analyze_bytes(data)

        self.assertNotIn("a", res.all_extracted_strings)
        self.assertNotIn("ab", res.all_extracted_strings)
        self.assertNotIn("abc", res.all_extracted_strings)
        self.assertIn("abcd", res.all_extracted_strings)
        self.assertIn("abcde", res.all_extracted_strings)

    def test_analyze_file_from_disk(self):
        """Verify static string extraction from a file on disk."""
        data = b"https://cert.gov.et/alerts\x00192.168.1.1\x00"
        test_file = Path(self.temp_dir.name) / "sample_binary.bin"
        test_file.write_bytes(data)

        res = self.analyzer.analyze_file(test_file)
        self.assertTrue(res.is_valid)
        self.assertIn("https://cert.gov.et/alerts", res.urls)
        self.assertIn("192.168.1.1", res.ip_addresses)

    def test_analyze_file_missing_handling(self):
        """Verify error handling on non-existent file path."""
        missing = Path(self.temp_dir.name) / "non_existent_file.bin"
        res = self.analyzer.analyze_file(missing)

        self.assertFalse(res.is_valid)
        self.assertIn("not found", res.error_message)

    def test_output_schema_contract(self):
        """Verify exact schema keys matching Module 06 specification."""
        data = b"https://sample.com\x00192.168.1.50\x00"
        res = self.analyzer.analyze_bytes(data)

        d = res.to_dict()
        expected_keys = {
            "total_strings", "urls", "ip_addresses", "domains",
            "registry_paths", "commands", "powershell_references"
        }
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertIsInstance(d["total_strings"], int)
        self.assertIsInstance(d["urls"], list)
        self.assertIsInstance(d["ip_addresses"], list)
        self.assertIsInstance(d["domains"], list)
        self.assertIsInstance(d["registry_paths"], list)
        self.assertIsInstance(d["commands"], list)
        self.assertIsInstance(d["powershell_references"], list)


if __name__ == "__main__":
    unittest.main()
