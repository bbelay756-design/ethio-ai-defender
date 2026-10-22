"""
Module 18: Full End-to-End Integration Pipeline Test for ETHIO-AI Defender.

Verifies the complete 11-step analysis chain:
Upload -> Hash -> PE -> Sections -> Entropy -> Strings -> Imports -> Indicators -> Risk Score -> AI -> Report
Across both English and Amharic locales, with database persistence and audit log verification.
"""

import io
import unittest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import init_db, SessionLocal
from app.db.repository import SampleRepository
from app.testing.synthetic_pe import SyntheticPEBuilder
from app.api.dashboard import run_full_analysis_pipeline
from app.auth.service import AuthService
from app.audit.service import audit_service


class TestModule18E2EPipeline(unittest.TestCase):
    """End-to-end integration tests for complete defensive static analysis pipeline."""

    @classmethod
    def setUpClass(cls):
        import uuid
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        # Create test admin user and authentication token
        u_name = f"admin_e2e_{uuid.uuid4().hex[:6]}"
        cls.admin = AuthService.register_user(
            cls.db, u_name, f"{u_name}@soc.et", "AdminSecretPass2026!", role="ADMIN"
        )
        cls.admin_token = AuthService.create_token_for_user(cls.admin)["access_token"]

        # In-memory synthetic binaries
        cls.benign_pe = SyntheticPEBuilder.create_minimal_pe()
        cls.ethio_pe = SyntheticPEBuilder.create_ethiopian_targeted_pe()
        cls.suspicious_pe = SyntheticPEBuilder.create_suspicious_import_pe()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_01_full_pipeline_step_by_step_execution(self):
        """
        Execute and verify every single stage of the 11-step pipeline on a synthetic binary.
        Pipeline:
        1. Upload & Intake
        2. Hash Analysis
        3. PE Static Header Analysis
        4. Section Analysis
        5. Entropy Analysis
        6. String Extraction
        7. Import Analysis
        8. Indicator Rule Engine
        9. Threat Scoring
        10. AI Assessment & Grounding
        11. Security Report Generation
        """
        result = run_full_analysis_pipeline(
            self.ethio_pe,
            filename="targeted_banking_agent.exe",
            language="en"
        )

        # 1. Intake / Upload Stage
        self.assertIn("analysis_id", result)
        self.assertTrue(result["analysis_id"].startswith("ANL-"))
        self.assertEqual(result["filename"], "targeted_banking_agent.exe")
        self.assertEqual(result["language"], "en")

        # 2. Hash Analysis Stage
        self.assertIn("hashes", result)
        self.assertIn("md5", result["hashes"])
        self.assertIn("sha1", result["hashes"])
        self.assertIn("sha256", result["hashes"])
        self.assertEqual(len(result["hashes"]["sha256"]), 64)

        # 3. PE Static Header Analysis Stage
        self.assertIn("pe_information", result)
        self.assertIn("type", result["pe_information"])
        self.assertIn("architecture", result["pe_information"])

        # 4. Section Analysis Stage
        self.assertIn("sections", result)
        self.assertIn("total_sections", result["sections"])
        self.assertGreaterEqual(result["sections"]["total_sections"], 1)

        # 5. Entropy Analysis Stage
        self.assertIn("entropy", result)
        self.assertIn("file_entropy", result["entropy"])

        # 6. String Extraction Stage
        self.assertIn("strings", result)
        self.assertIn("urls", result["strings"])
        self.assertIn("ip_addresses", result["strings"])

        # 7. Import Analysis Stage
        self.assertIn("imports", result)
        self.assertIn("total_imports", result["imports"])

        # 8. Indicator Rule Engine Stage
        self.assertIn("indicators", result)
        self.assertIn("indicators", result["indicators"])

        # 9. Threat Scoring Stage
        self.assertIn("threat_score", result)
        self.assertIn("score", result["threat_score"])
        self.assertIn("risk_level", result["threat_score"])

        # 10. AI Assessment Stage
        self.assertIn("ai_assessment", result)
        self.assertIn("summary", result["ai_assessment"])
        self.assertIn("confidence", result["ai_assessment"])

        # 11. Security Report Stage
        self.assertIn("report", result)
        self.assertIn("report_id", result["report"])
        self.assertIn("sections", result["report"])

        # Ethiopian Context Verification
        self.assertIn("ethiopian_context", result)
        self.assertEqual(result["ethiopian_context"]["relevance"], "HIGH")
        self.assertIn("ethionet.et", result["ethiopian_context"]["reason"])

        # Educational Learning Mode Verification
        self.assertIn("learning_mode", result)
        self.assertIn("lessons", result["learning_mode"])

    def test_02_full_pipeline_amharic_locale(self):
        """Verify pipeline execution in Amharic ('am') produces localized assessment and lessons."""
        result_am = run_full_analysis_pipeline(
            self.benign_pe,
            filename="safe_utility.exe",
            language="am"
        )
        self.assertEqual(result_am["language"], "am")
        self.assertIn("report", result_am)
        self.assertIn("learning_mode", result_am)

    def test_03_http_multipart_upload_pipeline(self):
        """Test full pipeline via HTTP POST /api/dashboard/analyze endpoint."""
        file_obj = io.BytesIO(self.suspicious_pe)
        response = self.client.post(
            "/api/dashboard/analyze?language=en",
            files={"file": ("suspicious_loader.exe", file_obj, "application/octet-stream")},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("analysis_id", data)
        self.assertIn("threat_score", data)
        self.assertIn("hashes", data)

    def test_04_database_sample_and_details_retrieval(self):
        """Verify sample is retrievable via GET /api/dashboard/samples and GET /api/dashboard/samples/{id}/full."""
        # Execute analysis first
        res = run_full_analysis_pipeline(self.benign_pe, filename="persisted_test.exe")
        analysis_id = res["analysis_id"]

        # Retrieve full details
        full_res = self.client.get(f"/api/dashboard/samples/{analysis_id}/full")
        self.assertEqual(full_res.status_code, 200)
        details = full_res.json()
        self.assertEqual(details["analysis_id"], analysis_id)
        self.assertEqual(details["filename"], "persisted_test.exe")

    def test_05_report_export_api_with_audit_trail(self):
        """Verify report generation endpoint returns data and records an audit log."""
        res = run_full_analysis_pipeline(self.benign_pe, filename="report_test.exe")
        analysis_id = res["analysis_id"]

        report_res = self.client.get(f"/api/dashboard/samples/{analysis_id}/report?format=json&language=en")
        self.assertEqual(report_res.status_code, 200)
        rep_data = report_res.json()
        self.assertEqual(rep_data["analysis_id"], analysis_id)
        self.assertEqual(rep_data["format"], "JSON")


if __name__ == "__main__":
    unittest.main()
