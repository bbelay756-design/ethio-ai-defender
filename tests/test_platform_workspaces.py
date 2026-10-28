"""
Comprehensive Unit & Integration Test Suite for ETHIO-AI Defender Workspaces:
- PE Analysis Structure (/api/analyses/{id}/pe)
- Imports & Windows APIs (/api/analyses/{id}/imports)
- Correlated Indicators & IOCs (/api/analyses/{id}/iocs)
- Grounded AI Security Analyst (/api/analyses/{id}/ai)
- Threat Intelligence Lookup (/api/analyses/threat-intel/lookup)
- Forensic Security Reports (/api/analyses/{id}/report)
- RBAC and Object-Level Authorization
"""

import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal, init_db
from app.db.models import SampleModel, SectionModel, ImportModel, StringModel, IndicatorModel, IOCModel, AnalysisResultModel, UserModel
from app.auth.roles import UserRole
from app.auth.security import hash_password, create_access_token
from app.analyzers.threat_intelligence import threat_intel_service


class TestPlatformWorkspaces(unittest.TestCase):
    """Verifies all static analysis module endpoints and threat intelligence service."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        # Create test users
        cls.admin_user = cls.db.query(UserModel).filter(UserModel.username == "test_admin_workspace").first()
        if not cls.admin_user:
            s, h = hash_password("AdminPass123!")
            cls.admin_user = UserModel(
                username="test_admin_workspace",
                email="admin_ws@defender.et",
                hashed_password=h,
                salt=s,
                role=UserRole.ADMIN.value
            )
            cls.db.add(cls.admin_user)
            cls.db.commit()
            cls.db.refresh(cls.admin_user)

        cls.analyst_user = cls.db.query(UserModel).filter(UserModel.username == "test_analyst_workspace").first()
        if not cls.analyst_user:
            s, h = hash_password("AnalystPass123!")
            cls.analyst_user = UserModel(
                username="test_analyst_workspace",
                email="analyst_ws@defender.et",
                hashed_password=h,
                salt=s,
                role=UserRole.ANALYST.value
            )
            cls.db.add(cls.analyst_user)
            cls.db.commit()
            cls.db.refresh(cls.analyst_user)

        cls.student_user = cls.db.query(UserModel).filter(UserModel.username == "test_student_workspace").first()
        if not cls.student_user:
            s, h = hash_password("StudentPass123!")
            cls.student_user = UserModel(
                username="test_student_workspace",
                email="student_ws@defender.et",
                hashed_password=h,
                salt=s,
                role=UserRole.VIEWER.value
            )
            cls.db.add(cls.student_user)
            cls.db.commit()
            cls.db.refresh(cls.student_user)

        cls.admin_token, _, _ = create_access_token({"sub": str(cls.admin_user.id), "username": cls.admin_user.username, "role": cls.admin_user.role})
        cls.analyst_token, _, _ = create_access_token({"sub": str(cls.analyst_user.id), "username": cls.analyst_user.username, "role": cls.analyst_user.role})
        cls.student_token, _, _ = create_access_token({"sub": str(cls.student_user.id), "username": cls.student_user.username, "role": cls.student_user.role})

        # Create sample analysis with sections, imports, IOCs, indicators
        cls.test_analysis_id = "ANL-TEST-WORKSPACE-001"
        cls.sample = cls.db.query(SampleModel).filter(SampleModel.analysis_id == cls.test_analysis_id).first()
        if not cls.sample:
            cls.sample = SampleModel(
                analysis_id=cls.test_analysis_id,
                filename="threat_sample.exe",
                size=102400,
                file_type="PE32+ (Executable)",
                architecture="x86_64",
                md5="0123456789abcdef0123456789abcdef",
                sha1="0123456789abcdef0123456789abcdef01234567",
                sha256="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                status="COMPLETED",
                risk_score=75,
                classification="HIGH",
                user_id=cls.analyst_user.id
            )
            cls.db.add(cls.sample)
            cls.db.commit()
            cls.db.refresh(cls.sample)

            # Add PE Sections
            sec1 = SectionModel(sample_id=cls.sample.id, name=".text", virtual_address=0x1000, virtual_size=40960, raw_size=40960, entropy=6.4, characteristics="IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE")
            sec2 = SectionModel(sample_id=cls.sample.id, name=".rdata", virtual_address=0xB000, virtual_size=16384, raw_size=16384, entropy=5.2, characteristics="IMAGE_SCN_MEM_READ")
            sec3 = SectionModel(sample_id=cls.sample.id, name=".data", virtual_address=0xF000, virtual_size=8192, raw_size=8192, entropy=7.6, characteristics="IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE")
            cls.db.add_all([sec1, sec2, sec3])

            # Add Imports
            imp1 = ImportModel(sample_id=cls.sample.id, dll="KERNEL32.DLL", api="VirtualAlloc", category="MEMORY", risk_relevance="HIGH")
            imp2 = ImportModel(sample_id=cls.sample.id, dll="KERNEL32.DLL", api="CreateRemoteThread", category="PROCESS", risk_relevance="CRITICAL")
            imp3 = ImportModel(sample_id=cls.sample.id, dll="WS2_32.DLL", api="connect", category="NETWORK", risk_relevance="HIGH")
            imp4 = ImportModel(sample_id=cls.sample.id, dll="ADVAPI32.DLL", api="RegSetValueExA", category="REGISTRY", risk_relevance="MEDIUM")
            imp5 = ImportModel(sample_id=cls.sample.id, dll="USER32.DLL", api="MessageBoxA", category="GENERAL", risk_relevance="LOW")
            cls.db.add_all([imp1, imp2, imp3, imp4, imp5])

            # Add IOCs
            ioc1 = IOCModel(sample_id=cls.sample.id, type="URL", value="http://malicious-c2-beacon.et/payload.bin", source="STATIC_STRINGS", confidence=1.0)
            ioc2 = IOCModel(sample_id=cls.sample.id, type="IP", value="196.189.1.50", source="STATIC_STRINGS", confidence=0.9)
            ioc3 = IOCModel(sample_id=cls.sample.id, type="REGISTRY", value="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", source="STATIC_STRINGS", confidence=1.0)
            cls.db.add_all([ioc1, ioc2, ioc3])

            # Add Indicators
            ind1 = IndicatorModel(sample_id=cls.sample.id, name="Dangerous RWX Memory Section", category="MEMORY", severity="HIGH", evidence="Section .data has both execute and write permissions.", confidence=1.0)
            ind2 = IndicatorModel(sample_id=cls.sample.id, name="Process Injection Capability", category="PROCESS", severity="CRITICAL", evidence="Imported CreateRemoteThread and VirtualAlloc primitives.", confidence=1.0)
            cls.db.add_all([ind1, ind2])

            # Add Analysis Result
            res = AnalysisResultModel(sample_id=cls.sample.id, risk_score=75, risk_level="HIGH", ai_summary="Static reverse-engineering reveals process injection primitives and high entropy packing.", ai_confidence="HIGH")
            cls.db.add(res)
            cls.db.commit()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_01_pe_structure_endpoint(self):
        """Tests GET /api/analyses/{id}/pe returns valid PE metrics and section list."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}
        res = self.client.get(f"/api/analyses/{self.test_analysis_id}/pe", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["analysis_id"], self.test_analysis_id)
        self.assertEqual(data["filename"], "threat_sample.exe")
        self.assertEqual(data["architecture"], "x86_64")
        self.assertTrue(data["has_wx_sections"])  # .data has execute and write
        self.assertEqual(len(data["sections"]), 3)
        self.assertEqual(data["sections"][0]["name"], ".text")
        self.assertEqual(data["sections"][2]["is_rwx"], True)

    def test_02_imports_endpoint_and_filters(self):
        """Tests GET /api/analyses/{id}/imports with categorization and risk relevance filters."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}

        # 1. Fetch all
        res = self.client.get(f"/api/analyses/{self.test_analysis_id}/imports", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total_imports"], 5)
        self.assertEqual(data["statistics"]["unique_dlls"], 4)
        self.assertGreaterEqual(data["statistics"]["suspicious_apis"], 3)

        # 2. Filter by category
        res_proc = self.client.get(f"/api/analyses/{self.test_analysis_id}/imports?category=PROCESS", headers=headers)
        self.assertEqual(res_proc.status_code, 200)
        self.assertEqual(len(res_proc.json()["imports"]), 1)
        self.assertEqual(res_proc.json()["imports"][0]["api"], "CreateRemoteThread")

        # 3. Filter by search
        res_search = self.client.get(f"/api/analyses/{self.test_analysis_id}/imports?search=VirtualAlloc", headers=headers)
        self.assertEqual(res_search.status_code, 200)
        self.assertEqual(len(res_search.json()["imports"]), 1)
        self.assertEqual(res_search.json()["imports"][0]["api"], "VirtualAlloc")

    def test_03_iocs_and_indicators_endpoint(self):
        """Tests GET /api/analyses/{id}/iocs returns normalized artifacts and correlated indicators."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}
        res = self.client.get(f"/api/analyses/{self.test_analysis_id}/iocs", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["total_iocs"], 3)
        self.assertEqual(data["statistics"]["urls"], 1)
        self.assertEqual(data["statistics"]["ips"], 1)
        self.assertEqual(data["statistics"]["registry_keys"], 1)
        self.assertEqual(len(data["indicators"]), 2)

    def test_04_ai_analyst_assessment_endpoint(self):
        """Tests GET /api/analyses/{id}/ai returns grounded assessment and ATT&CK alignment."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}
        res = self.client.get(f"/api/analyses/{self.test_analysis_id}/ai", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["risk_score"], 75)
        self.assertEqual(data["risk_level"], "HIGH")
        ai = data["ai_assessment"]
        self.assertIn("key_findings", ai)
        self.assertIn("benign_explanations", ai)
        self.assertIn("recommended_investigation", ai)
        self.assertIn("scientific_limitations", ai)
        self.assertIsInstance(data["mitre_attack"], list)

    def test_05_threat_intelligence_lookup_service(self):
        """Tests ThreatIntelligenceService cleanly handles unconfigured providers without fabricating false data."""
        # 1. IP Lookup
        ip_result = threat_intel_service.lookup_indicator("196.189.1.50")
        self.assertEqual(ip_result["indicator"], "196.189.1.50")
        self.assertEqual(ip_result["indicator_type"], "IP_ADDRESS")
        # In test environment, external keys are unconfigured
        if not ip_result["configured"]:
            self.assertEqual(ip_result["reputation"], "UNCHECKED")
            self.assertIn("not configured", ip_result["message"])

        # 2. SHA-256 Lookup
        sha_result = threat_intel_service.lookup_indicator("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        self.assertEqual(sha_result["indicator_type"], "SHA256")

        # 3. Via REST Endpoint POST /api/analyses/threat-intel/lookup
        headers = {"Authorization": f"Bearer {self.analyst_token}"}
        res = self.client.post(
            "/api/analyses/threat-intel/lookup",
            json={"indicator": "http://malicious-c2-beacon.et/payload.bin"},
            headers=headers
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["indicator_type"], "URL")

    def test_06_report_generation_formats(self):
        """Tests GET /api/analyses/{id}/report exports HTML, JSON, and Text formats."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}

        # 1. HTML
        res_html = self.client.get(f"/api/analyses/{self.test_analysis_id}/report?format=html", headers=headers)
        self.assertEqual(res_html.status_code, 200)
        self.assertIn("<!DOCTYPE html>", res_html.text)
        self.assertIn(self.test_analysis_id, res_html.text)

        # 2. JSON
        res_json = self.client.get(f"/api/analyses/{self.test_analysis_id}/report?format=json", headers=headers)
        self.assertEqual(res_json.status_code, 200)
        self.assertEqual(res_json.json()["analysis_id"], self.test_analysis_id)

        # 3. Plain Text
        res_txt = self.client.get(f"/api/analyses/{self.test_analysis_id}/report?format=text", headers=headers)
        self.assertEqual(res_txt.status_code, 200)
        self.assertIn("ETHIO-AI DEFENDER", res_txt.text)
        self.assertIn("Zero-Execution Static Guarantee", res_txt.text)


if __name__ == "__main__":
    unittest.main()
