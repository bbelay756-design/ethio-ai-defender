"""
Comprehensive Integration Tests for Analysis Overview Dashboard & Investigation Endpoints
Tests:
- Overview Statistics (/api/analyses/overview-stats)
- Sample Comparison (/api/analyses/compare)
- Contextual AI Ask (/api/analyses/{id}/ask-ai)
- Analyst Notes CRUD (/api/analyses/{id}/notes)
- Case Management Updates (/api/analyses/{id}/case)
- Report Exports (/api/analyses/{id}/report)
"""

import unittest
from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal, init_db
from app.db.models import UserModel
from app.auth.security import hash_password
from app.pipeline import unified_pipeline_service
from app.api.learning import SyntheticPEBuilder


class TestAnalysisOverviewFunctional(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        # Seed test users
        cls.admin_username = "test_admin_ov"
        cls.analyst_username = "test_analyst_ov"
        cls.student_username = "test_viewer_ov"

        from app.auth.service import AuthService
        for u_name, role in [
            (cls.admin_username, "ADMIN"),
            (cls.analyst_username, "ANALYST"),
            (cls.student_username, "VIEWER"),
        ]:
            existing = cls.db.query(UserModel).filter(UserModel.username == u_name).first()
            if existing:
                cls.db.delete(existing)
                cls.db.commit()
            AuthService.register_user(
                db=cls.db,
                username=u_name,
                email=f"{u_name}@ethio-defender.local",
                password="SecurePass123!",
                role=role
            )

        # Login tokens
        cls.admin_token = cls._login(cls.admin_username, "SecurePass123!")
        cls.analyst_token = cls._login(cls.analyst_username, "SecurePass123!")
        cls.student_token = cls._login(cls.student_username, "SecurePass123!")

        # Create two sample analyses
        sample_bytes_1 = SyntheticPEBuilder.create_minimal_pe()
        sample_bytes_2 = SyntheticPEBuilder.create_suspicious_import_pe()

        res1 = unified_pipeline_service.execute_pipeline(
            content=sample_bytes_1,
            filename="safe_cli_utility.exe",
            language="en"
        )
        cls.analysis_id_1 = res1["analysis_id"]

        res2 = unified_pipeline_service.execute_pipeline(
            content=sample_bytes_2,
            filename="suspicious_stager_demo.exe",
            language="en"
        )
        cls.analysis_id_2 = res2["analysis_id"]

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    @classmethod
    def _login(cls, username, password):
        res = cls.client.post(
            "/api/auth/login",
            json={"username": username, "password": password}
        )
        if res.status_code == 200:
            return res.json().get("access_token")
        return ""

    def test_01_get_overview_stats(self):
        """Test GET /api/analyses/overview-stats returns real calculated telemetry."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}
        res = self.client.get("/api/analyses/overview-stats", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total_analyses", data)
        self.assertGreaterEqual(data["total_analyses"], 2)
        self.assertIn("low_risk_count", data)
        self.assertIn("top_threat_indicators", data)
        self.assertIn("ioc_counts", data)
        self.assertIn("recent_activity", data)

    def test_02_compare_analyses(self):
        """Test GET /api/analyses/compare compares two real analyses side-by-side."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}
        res = self.client.get(
            f"/api/analyses/compare?id1={self.analysis_id_1}&id2={self.analysis_id_2}",
            headers=headers
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("sample_a", data)
        self.assertIn("sample_b", data)
        self.assertIn("differences", data)
        self.assertEqual(data["sample_a"]["analysis_id"], self.analysis_id_1)
        self.assertEqual(data["sample_b"]["analysis_id"], self.analysis_id_2)
        self.assertIn("score_delta", data["differences"])

    def test_03_ask_ai_endpoint(self):
        """Test POST /api/analyses/{id}/ask-ai generates grounded responses."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}
        res = self.client.post(
            f"/api/analyses/{self.analysis_id_2}/ask-ai",
            json={"question": "Why is this file high risk?", "language": "en"},
            headers=headers
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["analysis_id"], self.analysis_id_2)
        self.assertIn("answer", data)
        self.assertTrue(len(data["answer"]) > 10)
        self.assertIn("confidence", data)

    def test_04_analyst_notes_crud(self):
        """Test adding, listing, and deleting analyst notes."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}

        # 1. Add Note
        add_res = self.client.post(
            f"/api/analyses/{self.analysis_id_1}/notes",
            json={"content": "Verified safe hash against baseline.", "tag": "OBSERVATION"},
            headers=headers
        )
        self.assertEqual(add_res.status_code, 200)
        note_data = add_res.json()
        note_id = note_data["id"]
        self.assertEqual(note_data["content"], "Verified safe hash against baseline.")

        # 2. List Notes
        list_res = self.client.get(f"/api/analyses/{self.analysis_id_1}/notes", headers=headers)
        self.assertEqual(list_res.status_code, 200)
        notes = list_res.json()
        self.assertTrue(any(n["id"] == note_id for n in notes))

        # 3. Delete Note
        del_res = self.client.delete(f"/api/analyses/{self.analysis_id_1}/notes/{note_id}", headers=headers)
        self.assertEqual(del_res.status_code, 200)

    def test_05_update_case_metadata(self):
        """Test PATCH /api/analyses/{id}/case updates case tracking info."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}
        res = self.client.patch(
            f"/api/analyses/{self.analysis_id_1}/case",
            json={"case_id": "CASE-SOC-999", "case_status": "INVESTIGATING", "case_priority": "HIGH"},
            headers=headers
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["case_id"], "CASE-SOC-999")
        self.assertEqual(data["case_status"], "INVESTIGATING")
        self.assertEqual(data["case_priority"], "HIGH")

    def test_06_report_exports(self):
        """Test GET /api/analyses/{id}/report in all supported formats."""
        headers = {"Authorization": f"Bearer {self.analyst_token}"}
        for fmt in ["html", "json", "text", "markdown"]:
            res = self.client.get(
                f"/api/analyses/{self.analysis_id_1}/report?format={fmt}",
                headers=headers
            )
            self.assertEqual(res.status_code, 200)
            self.assertTrue(len(res.content) > 0)


if __name__ == "__main__":
    unittest.main()
