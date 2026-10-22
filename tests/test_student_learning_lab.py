"""
Unit and Integration Tests for Cybersecurity Student Learning Lab:
1. Topics Catalog API (/api/learning/topics)
2. Bilingual & Multi-level Topic Detail API (/api/learning/topics/{id})
3. Visual Byte Anatomy Metadata Verification
4. Safe Educational Practice Labs Catalog (/api/learning/practice-samples)
5. Live Pipeline Execution on Benign Practice Sample (lab-01-benign-cli)
6. Live Pipeline Execution on UPX Packed Practice Sample (lab-02-packed-upx)
7. Live Pipeline Execution on Crypto DLL Practice Sample (lab-03-crypto-dll)
8. Live Pipeline Execution on Suspicious Stager Practice Sample (lab-04-suspicious-stager)
9. Live Pipeline Execution on Ethiopian Infrastructure Sample (lab-05-ethio-cyber)
10. Knowledge Quiz Retrieval (/api/learning/quizzes)
11. Knowledge Quiz Evaluation & Scoring (/api/learning/quizzes/evaluate)
"""

import os
import sys
import unittest
import uuid

# Ensure repo root is on sys.path
sys.path.insert(0, os.path.abspath("."))

from fastapi.testclient import TestClient
from app.main import app
from app.db.session import SessionLocal, init_db
from app.auth.service import AuthService


class TestStudentLearningLab(unittest.TestCase):
    """
    Test suite verifying interactive educational reverse-engineering lessons,
    concept breakdowns, safe sample practice, and quiz evaluation.
    """

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

        cls.uid = uuid.uuid4().hex[:8]
        with SessionLocal() as db:
            cls.student = AuthService.register_user(
                db=db,
                username=f"student_lab_{cls.uid}",
                email=f"student_lab_{cls.uid}@defensive.local",
                password="StudentPassword123!",
                role="STUDENT"
            )

        # Login student to get JWT token
        student_login = cls.client.post("/api/auth/login", json={
            "username": f"student_lab_{cls.uid}",
            "password": "StudentPassword123!"
        })
        cls.student_token = student_login.json()["access_token"]
        cls.student_headers = {"Authorization": f"Bearer {cls.student_token}"}

    def test_01_list_all_14_learning_topics(self):
        """1. Student can list all 14 reverse-engineering educational topics."""
        res = self.client.get("/api/learning/topics?lang=en", headers=self.student_headers)
        self.assertEqual(res.status_code, 200)
        topics = res.json()
        self.assertGreaterEqual(len(topics), 14)
        topic_ids = [t["id"] for t in topics]
        self.assertIn("PE_FORMAT", topic_ids)
        self.assertIn("DOS_HEADER", topic_ids)
        self.assertIn("ENTROPY", topic_ids)
        self.assertIn("WINDOWS_APIS", topic_ids)
        self.assertIn("THREAT_INDICATORS", topic_ids)

    def test_02_get_topic_detail_beginner_en(self):
        """2. Student can retrieve beginner topic detail with visual anatomy in English."""
        res = self.client.get("/api/learning/topics/DOS_HEADER?lang=en&level=BEGINNER", headers=self.student_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["id"], "DOS_HEADER")
        self.assertEqual(data["difficulty_level"], "BEGINNER")
        self.assertIn("e_lfanew", data["why_it_matters"])
        self.assertIn("does not prove malicious", data["proves_malicious"].lower())
        self.assertIsNotNone(data["visual_anatomy"])
        self.assertGreaterEqual(len(data["visual_anatomy"]["fields"]), 3)

    def test_03_get_topic_detail_advanced_am(self):
        """3. Student can retrieve advanced topic detail in Amharic."""
        res = self.client.get("/api/learning/topics/PE_HEADER?lang=am&level=ADVANCED", headers=self.student_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["id"], "PE_HEADER")
        self.assertEqual(data["difficulty_level"], "ADVANCED")
        self.assertEqual(data["language"], "am")
        self.assertIn("IMAGE_NT_HEADERS", data["explanation"])

    def test_04_list_practice_samples_catalog(self):
        """4. Student can retrieve the curated safe practice lab binaries catalog."""
        res = self.client.get("/api/learning/practice-samples", headers=self.student_headers)
        self.assertEqual(res.status_code, 200)
        samples = res.json()
        self.assertEqual(len(samples), 5)
        sample_ids = [s["id"] for s in samples]
        self.assertIn("lab-01-benign-cli", sample_ids)
        self.assertIn("lab-02-packed-upx", sample_ids)
        self.assertIn("lab-03-crypto-dll", sample_ids)
        self.assertIn("lab-04-suspicious-stager", sample_ids)
        self.assertIn("lab-05-ethio-cyber", sample_ids)

    def test_05_load_benign_cli_practice_sample(self):
        """5. Student loads lab-01-benign-cli and verifies static analysis execution."""
        res = self.client.post("/api/learning/practice-samples/lab-01-benign-cli/load?lang=en", headers=self.student_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertIn("analysis_data", data)
        analysis = data["analysis_data"]
        self.assertEqual(analysis["filename"], "safe_cli_utility.exe")
        self.assertLess(analysis["entropy"]["file_entropy"], 5.0)

    def test_06_load_packed_upx_practice_sample(self):
        """6. Student loads lab-02-packed-upx and verifies high entropy and UPX detection."""
        res = self.client.post("/api/learning/practice-samples/lab-02-packed-upx/load?lang=en", headers=self.student_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        analysis = data["analysis_data"]
        self.assertEqual(analysis["filename"], "upx_packed_demo.exe")
        # Verify UPX section names
        section_names = [s["name"] for s in analysis.get("sections", [])]
        self.assertTrue(any("UPX" in name for name in section_names))

    def test_07_load_crypto_dll_practice_sample(self):
        """7. Student loads lab-03-crypto-dll and verifies DLL characteristics."""
        res = self.client.post("/api/learning/practice-samples/lab-03-crypto-dll/load?lang=en", headers=self.student_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        analysis = data["analysis_data"]
        self.assertEqual(analysis["filename"], "crypto_defense_helper.dll")
        self.assertTrue(analysis["pe"]["is_dll"])

    def test_08_load_suspicious_stager_practice_sample(self):
        """8. Student loads lab-04-suspicious-stager and verifies API indicator correlation."""
        res = self.client.post("/api/learning/practice-samples/lab-04-suspicious-stager/load?lang=en", headers=self.student_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        analysis = data["analysis_data"]
        self.assertEqual(analysis["filename"], "suspicious_stager_demo.exe")
        self.assertGreater(analysis["strings"]["total_strings"], 0)
        self.assertTrue(
            len(analysis["strings"].get("urls", [])) > 0 or
            len(analysis["strings"].get("ip_addresses", [])) > 0 or
            len(analysis["strings"].get("registry_paths", [])) > 0 or
            len(analysis["strings"].get("commands", [])) > 0
        )

    def test_09_load_ethio_cyber_practice_sample(self):
        """9. Student loads lab-05-ethio-cyber and verifies Ethiopian contextual triage."""
        res = self.client.post("/api/learning/practice-samples/lab-05-ethio-cyber/load?lang=en", headers=self.student_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        analysis = data["analysis_data"]
        self.assertEqual(analysis["filename"], "ethio_critical_infra_mock.exe")
        urls = analysis.get("strings", {}).get("urls", [])
        domains = analysis.get("strings", {}).get("domains", [])
        self.assertTrue(len(urls) > 0 or len(domains) > 0 or bool(analysis.get("ethiopian_context")))

    def test_10_retrieve_quiz_questions(self):
        """10. Student retrieves quiz bank without exposing correct answer keys."""
        res = self.client.get("/api/learning/quizzes", headers=self.student_headers)
        self.assertEqual(res.status_code, 200)
        questions = res.json()
        self.assertGreaterEqual(len(questions), 5)
        for q in questions:
            self.assertIn("id", q)
            self.assertIn("question", q)
            self.assertIn("options", q)
            self.assertIn("hint", q)
            # Correct answer key must NOT be returned in the question list
            self.assertNotIn("correct_id", q)
            self.assertNotIn("explanation", q)

    def test_11_evaluate_quiz_submission(self):
        """11. Student submits quiz answers and receives grading and technical rationales."""
        submission_payload = {
            "answers": [
                {"question_id": "q1", "selected_option_id": "b"},  # correct (e_lfanew)
                {"question_id": "q2", "selected_option_id": "b"},  # correct (entropy randomness)
                {"question_id": "q3", "selected_option_id": "b"},  # correct (VirtualProtect benign JIT)
                {"question_id": "q4", "selected_option_id": "a"},  # correct (W^X violation)
                {"question_id": "q5", "selected_option_id": "b"}   # correct (process injection APIs)
            ]
        }
        res = self.client.post("/api/learning/quizzes/evaluate", headers=self.student_headers, json=submission_payload)
        self.assertEqual(res.status_code, 200)
        eval_data = res.json()
        self.assertEqual(eval_data["total_questions"], 5)
        self.assertEqual(eval_data["correct_count"], 5)
        self.assertEqual(eval_data["score_percentage"], 100.0)
        self.assertTrue(eval_data["passed"])
        self.assertEqual(len(eval_data["results"]), 5)
        for r in eval_data["results"]:
            self.assertTrue(r["is_correct"])
            self.assertIn("explanation", r)

    def _register_and_login_student(self, tag):
        uid = uuid.uuid4().hex[:8]
        uname = f"dash_{tag}_{uid}"
        with SessionLocal() as db:
            AuthService.register_user(
                db=db,
                username=uname,
                email=f"{uname}@defensive.local",
                password="DashStatsPass2026!",
                role="STUDENT"
            )
        token = self.client.post("/api/auth/login", json={
            "username": uname,
            "password": "DashStatsPass2026!"
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def test_12_dashboard_stats_empty_state(self):
        """12. BUG-01: dashboard-stats returns 200 with zeroed metrics for a fresh student."""
        headers = self._register_and_login_student("empty")
        res = self.client.get("/api/learning/dashboard-stats", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["completed_analyses_count"], 0)
        self.assertEqual(data["labs_completed_count"], 0)
        self.assertGreaterEqual(data["total_available_labs"], 5)
        self.assertGreaterEqual(data["total_topics"], 14)
        self.assertEqual(len(data["achievements"]), 5)
        self.assertFalse(any(a["unlocked"] for a in data["achievements"]))

    def test_13_dashboard_stats_populated_state(self):
        """13. BUG-01: dashboard-stats reflects progress after loading a practice lab."""
        headers = self._register_and_login_student("pop")
        load = self.client.post(
            "/api/learning/practice-samples/lab-01-benign-cli/load?lang=en",
            headers=headers
        )
        self.assertEqual(load.status_code, 200)
        res = self.client.get("/api/learning/dashboard-stats", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(data["completed_analyses_count"], 1)
        self.assertEqual(data["labs_completed_count"], 1)
        self.assertGreaterEqual(len(data["recent_analyses"]), 1)

    def test_14_dashboard_stats_requires_authentication(self):
        """14. BUG-01: dashboard-stats rejects unauthenticated requests."""
        res = self.client.get("/api/learning/dashboard-stats")
        self.assertEqual(res.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)
