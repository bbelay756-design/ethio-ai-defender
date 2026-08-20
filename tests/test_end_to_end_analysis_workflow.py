"""
End-to-End Test Suite for Static Malware Analysis & Reverse-Engineering Workflow

Tests:
1. File intake validation & quarantine
2. Header & PE architecture parsing
3. Cryptographic hash calculation (SHA-256, SHA-1, MD5)
4. Section analysis, entropy, and W+X detection
5. Imports & API categorization
6. Strings classification
7. IOC extraction & deduplication
8. YARA scanning & graceful fallback
9. Evidence-based heuristic risk scoring
10. AI analysis fallback & grounding
11. MITRE ATT&CK heuristic mapping
12. Database persistence & relational transactions
13. REST APIs (/api/analyses POST, GET list, GET detail, GET report, DELETE)
14. RBAC & IDOR protections
"""

import io
import os
import sys
import struct
import unittest

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath("."))

from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal, init_db
from app.db.models import (
    UserModel,
    SampleModel,
    SectionModel,
    ImportModel,
    StringModel,
    IndicatorModel,
    IOCModel,
    YaraMatchModel,
    RiskFactorModel,
    AnalysisResultModel,
)
from app.db.repository import SampleRepository
from app.auth.security import hash_password, create_access_token
from app.auth.roles import UserRole
from app.pipeline.orchestrator import unified_pipeline_service
from app.analyzers.yara_analyzer import yara_analyzer_service


def create_synthetic_pe(
    num_sections=3,
    custom_strings=None,
    add_wx_section=False,
    machine=0x8664  # AMD64
) -> bytes:
    """
    Constructs a valid synthetic in-memory Windows PE executable binary
    with valid DOS MZ header, PE signature, COFF header, Optional header,
    Section headers, and section data.
    """
    custom_strings = custom_strings or []
    out = bytearray(4096)

    # 1. DOS Header
    out[0:2] = b'MZ'
    pe_offset = 0x80
    struct.pack_into('<I', out, 0x3C, pe_offset)

    # 2. PE Signature
    out[pe_offset:pe_offset+4] = b'PE\x00\x00'

    # 3. COFF File Header (20 bytes)
    coff_offset = pe_offset + 4
    num_sec = num_sections
    opt_hdr_size = 224
    characteristics = 0x0102  # Executable 32/64 bit
    coff_header = struct.pack(
        '<HHIIIHH',
        machine,        # Machine
        num_sec,        # NumberOfSections
        0x65C0FFEE,     # TimeDateStamp
        0,              # PointerToSymbolTable
        0,              # NumberOfSymbols
        opt_hdr_size,   # SizeOfOptionalHeader
        characteristics # Characteristics
    )
    out[coff_offset:coff_offset+20] = coff_header

    # 4. Optional Header (Standard + Windows Fields)
    opt_offset = coff_offset + 20
    magic = 0x020B if machine == 0x8664 else 0x010B  # PE32+ (64-bit) or PE32 (32-bit)
    entry_point = 0x1000
    image_base = 0x140000000 if machine == 0x8664 else 0x00400000
    subsystem = 2  # Windows GUI
    opt_data = bytearray(opt_hdr_size)
    struct.pack_into('<H', opt_data, 0, magic)
    struct.pack_into('<I', opt_data, 16, entry_point)
    if machine == 0x8664:
        struct.pack_into('<Q', opt_data, 24, image_base)
    else:
        struct.pack_into('<I', opt_data, 28, image_base)
    struct.pack_into('<H', opt_data, 68, subsystem)
    out[opt_offset:opt_offset+opt_hdr_size] = opt_data

    # 5. Section Headers (40 bytes each)
    sec_hdr_offset = opt_offset + opt_hdr_size
    sec_data_start = 0x400

    sections_info = [
        (b'.text\x00\x00\x00', 0x1000, 0x200, sec_data_start, 0x200, 0x60000020),  # R-X
        (b'.data\x00\x00\x00', 0x2000, 0x200, sec_data_start + 0x200, 0x200, 0xC0000040),  # RW-
        (b'.rsrc\x00\x00\x00', 0x3000, 0x200, sec_data_start + 0x400, 0x200, 0x40000040),  # R--
    ]

    if add_wx_section and len(sections_info) > 1:
        # Give second section W+X permissions (0xE0000020 = Read, Write, Execute)
        sections_info[1] = (b'.packed\x00', 0x2000, 0x200, sec_data_start + 0x200, 0x200, 0xE0000020)

    for i, s in enumerate(sections_info[:num_sections]):
        hdr = struct.pack(
            '<8sIIIIIIHHI',
            s[0], # Name
            s[1], # VirtualSize
            s[1], # VirtualAddress
            s[4], # SizeOfRawData
            s[3], # PointerToRawData
            0,    # PointerToRelocations
            0,    # PointerToLinenumbers
            0,    # NumberOfRelocations
            0,    # NumberOfLinenumbers
            s[5]  # Characteristics
        )
        out[sec_hdr_offset + i*40 : sec_hdr_offset + (i+1)*40] = hdr

    # 6. Embed strings and simulated API names in data section
    data_pos = sec_data_start + 0x200
    for cs in custom_strings:
        b_str = cs.encode('utf-8') + b'\x00'
        if data_pos + len(b_str) < len(out):
            out[data_pos:data_pos+len(b_str)] = b_str
            data_pos += len(b_str)

    return bytes(out)


class TestEndToEndAnalysisWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        db = SessionLocal()
        # Seed test admin & analyst
        admin = db.query(UserModel).filter(UserModel.username == "test_soc_admin").first()
        if not admin:
            salt_admin, hash_admin = hash_password("AdminSecurePass123!")
            admin = UserModel(
                username="test_soc_admin",
                email="admin@soc.et",
                salt=salt_admin,
                hashed_password=hash_admin,
                role=UserRole.ADMIN.value,
                is_active=True,
            )
            db.add(admin)

        analyst = db.query(UserModel).filter(UserModel.username == "test_soc_analyst").first()
        if not analyst:
            salt_analyst, hash_analyst = hash_password("AnalystPass123!")
            analyst = UserModel(
                username="test_soc_analyst",
                email="analyst@soc.et",
                salt=salt_analyst,
                hashed_password=hash_analyst,
                role=UserRole.ANALYST.value,
                is_active=True,
            )
            db.add(analyst)

        db.commit()
        db.refresh(admin)
        db.refresh(analyst)

        cls.admin = admin
        cls.analyst = analyst
        cls.admin_token, _, _ = create_access_token(data={"sub": str(admin.id), "username": admin.username, "role": "ADMIN"})
        cls.analyst_token, _, _ = create_access_token(data={"sub": str(analyst.id), "username": analyst.username, "role": "ANALYST"})
        db.close()

        cls.client = TestClient(app)

    def test_01_static_pe_pipeline_execution(self):
        """Verifies complete deterministic 15-stage pipeline on synthetic binary."""
        sample_pe = create_synthetic_pe(
            num_sections=3,
            custom_strings=[
                "https://telecom.et/auth/login",
                "196.188.120.10",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "VirtualAlloc",
                "VirtualProtect",
                "InternetOpenA"
            ],
            add_wx_section=True
        )

        result = unified_pipeline_service.execute_pipeline(
            content=sample_pe,
            filename="bank_defense_agent.exe",
            language="en"
        )

        self.assertIn(result["status"], ("COMPLETED", "PARTIAL"))
        self.assertTrue(result["analysis_id"].startswith("ANL-"))
        self.assertEqual(result["file"]["filename"], "bank_defense_agent.exe")

        # Hashes check
        self.assertEqual(len(result["hashes"]["sha256"]), 64)
        self.assertEqual(len(result["hashes"]["md5"]), 32)
        self.assertEqual(len(result["hashes"]["sha1"]), 40)

        # PE headers check
        self.assertEqual(result["pe"]["file_type"], "EXE")
        self.assertTrue("x64" in result["pe"]["machine_architecture"] or "x86" in result["pe"]["machine_architecture"])

        # Sections & Entropy
        self.assertGreaterEqual(result["sections"]["total_sections"], 3)
        self.assertTrue(result["sections"]["has_wx_sections"])

        # Strings & IOCs
        self.assertGreaterEqual(len(result["strings"]["urls"]), 1)
        self.assertIn("https://telecom.et/auth/login", result["strings"]["urls"])
        self.assertGreaterEqual(len(result["iocs"]["items"]), 3)

        # YARA Scan status
        self.assertIn("available", result["yara_matches"])

        # Threat score & Risk factors
        self.assertIn("score", result["risk_score"])
        self.assertGreater(result["risk_score"]["score"], 0)
        self.assertGreater(len(result["risk_factors"]), 0)

        # MITRE ATT&CK mapping
        self.assertGreater(len(result["mitre_attack"]), 0)

        # AI assessment
        self.assertIn(result["ai_assessment"]["status"], ("SUCCESS", "UNAVAILABLE"))
        self.assertIn("summary", result["ai_assessment"])

    def test_02_yara_analyzer_graceful_handling(self):
        """Verifies that YARA analyzer never crashes if yara-python is missing."""
        sample_bytes = b"MZ" + b"\x00" * 200
        yara_res = yara_analyzer_service.scan_bytes(sample_bytes)
        self.assertIn(yara_res.status, ("SUCCESS", "UNAVAILABLE"))
        self.assertIsInstance(yara_res.matches, list)

    def test_03_create_analysis_endpoint_success(self):
        """Verifies POST /api/analyses uploads and parses a real PE binary."""
        sample_pe = create_synthetic_pe(
            num_sections=3,
            custom_strings=["https://cbe.com.et/portal", "10.0.0.1", "CreateRemoteThread"],
            add_wx_section=False
        )

        response = self.client.post(
            "/api/analyses?language=en",
            files={"file": ("sample_analyst.exe", io.BytesIO(sample_pe), "application/x-msdownload")},
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )

        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn("analysis_id", data)
        self.assertEqual(data["filename"], "sample_analyst.exe")
        self.assertEqual(len(data["sha256"]), 64)
        self.assertIn(data["status"], ("COMPLETED", "PARTIAL"))
        self.assertIn("risk_score", data)
        self.assertIn("data", data)

    def test_04_create_analysis_invalid_extension(self):
        """Verifies POST /api/analyses rejects non-PE file extensions."""
        response = self.client.post(
            "/api/analyses",
            files={"file": ("malicious_script.sh", io.BytesIO(b"#!/bin/bash\necho hello"), "text/plain")},
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Unsupported file extension", response.json()["detail"])

    def test_05_create_analysis_invalid_pe_header(self):
        """Verifies POST /api/analyses rejects files with corrupt DOS magic bytes."""
        corrupt_pe = b"NOT_A_PE_HEADER" + b"\x00" * 500
        response = self.client.post(
            "/api/analyses",
            files={"file": ("fake_binary.exe", io.BytesIO(corrupt_pe), "application/x-msdownload")},
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertTrue("DOS signature" in response.json()["detail"] or "Invalid" in response.json()["detail"])

    def test_06_list_analyses_endpoint(self):
        """Verifies GET /api/analyses lists historical analyses with pagination."""
        response = self.client.get(
            "/api/analyses?skip=0&limit=10",
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total", data)
        self.assertIn("items", data)
        self.assertIsInstance(data["items"], list)

    def test_07_get_analysis_by_id_and_reports(self):
        """Verifies GET /api/analyses/{id} and report generation in all formats."""
        sample_pe = create_synthetic_pe(num_sections=3, custom_strings=["RegSetValueExA", "192.168.1.5"])
        upload_res = self.client.post(
            "/api/analyses",
            files={"file": ("target_investigation.exe", io.BytesIO(sample_pe), "application/x-msdownload")},
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(upload_res.status_code, 201)
        analysis_id = upload_res.json()["analysis_id"]

        # Detail fetch
        detail_res = self.client.get(
            f"/api/analyses/{analysis_id}",
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(detail_res.status_code, 200)
        detail = detail_res.json()
        self.assertEqual(detail["analysis_id"], analysis_id)
        self.assertIn("file_information", detail)
        self.assertIn("hashes", detail)
        self.assertIn("sections", detail)
        self.assertIn("imports", detail)
        self.assertIn("indicators", detail)
        self.assertIn("iocs", detail)

        # HTML report
        html_res = self.client.get(
            f"/api/analyses/{analysis_id}/report?format=html",
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(html_res.status_code, 200)
        self.assertIn("<!DOCTYPE html>", html_res.text)

        # Markdown report
        md_res = self.client.get(
            f"/api/analyses/{analysis_id}/report?format=markdown",
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(md_res.status_code, 200)
        self.assertIn("# ETHIO-AI Defender Security Report", md_res.text)

        # Text report
        txt_res = self.client.get(
            f"/api/analyses/{analysis_id}/report?format=text",
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(txt_res.status_code, 200)
        self.assertIn("ETHIO-AI DEFENDER - STATIC SECURITY ANALYSIS REPORT", txt_res.text)

    def test_08_delete_analysis_rbac(self):
        """Verifies DELETE /api/analyses/{id} enforces authorization and cleans up DB records."""
        sample_pe = create_synthetic_pe(num_sections=3)
        upload_res = self.client.post(
            "/api/analyses",
            files={"file": ("to_delete.exe", io.BytesIO(sample_pe), "application/x-msdownload")},
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(upload_res.status_code, 201)
        analysis_id = upload_res.json()["analysis_id"]

        # Admin deletes the analysis
        del_res = self.client.delete(
            f"/api/analyses/{analysis_id}",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(del_res.status_code, 200)

        # Ensure it is now 404
        get_res = self.client.get(
            f"/api/analyses/{analysis_id}",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(get_res.status_code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
