"""
Module 18 - Integration Testing: Full 11-Step Analysis Pipeline.
Validates the full static-analysis, AI-interpretation, learning mode, reporting, and database persistence lifecycle.
"""

import io
import uuid
import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.api.dashboard import run_full_analysis_pipeline
from app.testing.synthetic_pe import SyntheticPEBuilder
from app.db.session import init_db, SessionLocal
from app.auth.service import AuthService
from app.auth.roles import UserRole


class TestFullAnalysisPipeline(unittest.TestCase):
    """End-to-End multi-module analysis pipeline integration suite."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        u_name = f"admin_int_{uuid.uuid4().hex[:6]}"
        cls.admin = AuthService.register_user(
            cls.db, u_name, f"{u_name}@soc.et", "AdminSecretPass2026!", role=UserRole.ADMIN
        )
        cls.admin_token = AuthService.create_token_for_user(cls.admin)["access_token"]
        cls.admin_hdr = {"Authorization": f"Bearer {cls.admin_token}"}

        cls.benign_pe = SyntheticPEBuilder.create_minimal_pe()
        cls.ethio_pe = SyntheticPEBuilder.create_ethiopian_targeted_pe()
        cls.suspicious_pe = SyntheticPEBuilder.create_suspicious_import_pe()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_01_full_11_step_pipeline_english(self):
        """Execute and verify every single stage of the 11-step pipeline in English."""
        result = run_full_analysis_pipeline(
            self.ethio_pe,
            filename="targeted_banking_agent.exe",
            language="en"
        )

        # 1. Intake Stage
        self.assertIn("analysis_id", result)
        self.assertIn("filename", result)

        # 2. Hash Calculation Stage
        self.assertIn("hashes", result)
        self.assertEqual(len(result["hashes"]["sha256"]), 64)

        # 3. PE Static Header Stage
        self.assertIn("pe_information", result)
        self.assertIn("type", result["pe_information"])
        self.assertIn("architecture", result["pe_information"])

        # 4. Section Analysis Stage
        self.assertIn("sections", result)
        self.assertGreaterEqual(result["sections"]["total_sections"], 1)

        # 5. Entropy Analysis Stage
        self.assertIn("entropy", result)
        self.assertIn("file_entropy", result["entropy"])

        # 6. String Extraction Stage
        self.assertIn("strings", result)
        self.assertIn("urls", result["strings"])

        # 7. Import API Analysis Stage
        self.assertIn("imports", result)

        # 8. Indicator Rule Engine Stage
        self.assertIn("indicators", result)

        # 9. Threat Scoring Stage
        self.assertIn("threat_score", result)
        self.assertIn("score", result["threat_score"])
        self.assertIn("risk_level", result["threat_score"])

        # 10. AI Assessment Stage
        self.assertIn("ai_assessment", result)
        self.assertIn("summary", result["ai_assessment"])

        # 11. Security Report Stage
        self.assertIn("report", result)
        self.assertIn("report_id", result["report"])

        # Ethiopian Context Verification
        self.assertIn("ethiopian_context", result)
        self.assertEqual(result["ethiopian_context"]["relevance"], "HIGH")
        self.assertIn("ethionet.et", result["ethiopian_context"]["reason"])

    def test_02_full_pipeline_amharic_locale(self):
        """Verify pipeline execution in Amharic ('am') produces localized assessment and lessons."""
        result_am = run_full_analysis_pipeline(
            self.benign_pe,
            filename="safe_utility.exe",
            language="am"
        )
        self.assertEqual(result_am["language"], "am")
        self.assertEqual(result_am["report"]["language"], "am")
        self.assertIn("learning_mode", result_am)

    def test_03_dashboard_analyze_api_flow(self):
        """Test POST /api/dashboard/analyze multipart endpoint executes full workflow."""
        file_obj = io.BytesIO(self.suspicious_pe)
        response = self.client.post(
            "/api/dashboard/analyze?language=en",
            files={"file": ("suspicious_loader.exe", file_obj, "application/octet-stream")},
            headers=self.admin_hdr
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("analysis_id", data)
        self.assertIn("threat_score", data)

    def test_04_database_sample_retrieval_and_report_export(self):
        """Verify database persistence and report generation endpoint with audit trail."""
        file_obj = io.BytesIO(self.benign_pe)
        upload_res = self.client.post(
            "/api/dashboard/analyze?language=en",
            files={"file": ("report_test.exe", file_obj, "application/octet-stream")},
            headers=self.admin_hdr
        )
        self.assertEqual(upload_res.status_code, 200)
        aid = upload_res.json()["analysis_id"]

        # Fetch full details
        full_res = self.client.get(f"/api/dashboard/samples/{aid}/full", headers=self.admin_hdr)
        self.assertEqual(full_res.status_code, 200)

        # Export report as JSON
        report_res = self.client.get(f"/api/dashboard/samples/{aid}/report?format=json", headers=self.admin_hdr)
        self.assertEqual(report_res.status_code, 200)


if __name__ == "__main__":
    unittest.main()
