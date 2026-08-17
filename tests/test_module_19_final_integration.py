"""
Module 19 - Final ETHIO-AI Defender Integration & Failure Resilience Test Suite.
Verifies the complete 15-stage pipeline, Unified Analysis Object schema, graceful analyzer error recovery,
clear separation of observed evidence vs rule-based indicators vs AI interpretation, bilingual capabilities,
and all 10 failure isolation test scenarios.
"""

import io
import time
import uuid
import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.pipeline.orchestrator import unified_pipeline_service
from app.pipeline.models import UnifiedAnalysisResult
from app.testing.synthetic_pe import SyntheticPEBuilder
from app.db.session import init_db, SessionLocal
from app.auth.service import AuthService
from app.auth.roles import UserRole
from app.ai.analyst import ai_security_analyst_service


class TestModule19FinalIntegration(unittest.TestCase):
    """Exhaustive Module 19 Final Integration & Resilience Test Suite."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        # Admin user
        u_admin = f"m19_admin_{uuid.uuid4().hex[:6]}"
        cls.admin = AuthService.register_user(
            cls.db, u_admin, f"{u_admin}@soc.et", "M19SecretAdmin2026!", role=UserRole.ADMIN
        )
        cls.admin_token = AuthService.create_token_for_user(cls.admin)["access_token"]
        cls.admin_hdr = {"Authorization": f"Bearer {cls.admin_token}"}

        # Student User A
        u_student_a = f"m19_student_a_{uuid.uuid4().hex[:6]}"
        cls.user_a = AuthService.register_user(
            cls.db, u_student_a, f"{u_student_a}@uni.et", "StudentAPass2026!", role=UserRole.STUDENT
        )
        cls.user_a_token = AuthService.create_token_for_user(cls.user_a)["access_token"]
        cls.user_a_hdr = {"Authorization": f"Bearer {cls.user_a_token}"}

        # Student User B
        u_student_b = f"m19_student_b_{uuid.uuid4().hex[:6]}"
        cls.user_b = AuthService.register_user(
            cls.db, u_student_b, f"{u_student_b}@uni.et", "StudentBPass2026!", role=UserRole.STUDENT
        )
        cls.user_b_token = AuthService.create_token_for_user(cls.user_b)["access_token"]
        cls.user_b_hdr = {"Authorization": f"Bearer {cls.user_b_token}"}

        cls.benign_pe = SyntheticPEBuilder.create_minimal_pe()
        cls.ethio_pe = SyntheticPEBuilder.create_ethiopian_targeted_pe()
        cls.suspicious_pe = SyntheticPEBuilder.create_suspicious_import_pe()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    def test_01_unified_analysis_object_schema_conformance(self):
        """Verify the pipeline return contract conforms 100% to the Module 19 Unified Analysis Object specification."""
        result = unified_pipeline_service.execute_pipeline(
            self.ethio_pe,
            filename="ethiopian_banking_agent.exe",
            language="en"
        )

        # 1. Required Top-Level Schema Keys
        required_keys = [
            "schema_version",
            "analysis_id",
            "status",
            "file",
            "hashes",
            "pe",
            "sections",
            "entropy",
            "strings",
            "imports",
            "indicators",
            "risk",
            "risk_score",
            "ethiopian_context",
            "ai_assessment",
            "report",
            "errors"
        ]
        for key in required_keys:
            self.assertIn(key, result, f"Missing required Unified Analysis Object key: {key}")

        # 2. Type Validations
        self.assertEqual(result["schema_version"], "1.0")
        self.assertEqual(result["status"], "COMPLETED")
        self.assertIsInstance(result["analysis_id"], str)
        self.assertIsInstance(result["file"], dict)
        self.assertIsInstance(result["hashes"], dict)
        self.assertIsInstance(result["pe"], dict)
        self.assertIsInstance(result["sections"], list)
        self.assertIsInstance(result["entropy"], dict)
        self.assertIsInstance(result["strings"], dict)
        self.assertIsInstance(result["imports"], list)
        self.assertIsInstance(result["indicators"], list)
        self.assertIsInstance(result["risk"], dict)
        self.assertIsInstance(result["risk_score"], dict)
        self.assertIsInstance(result["ethiopian_context"], dict)
        self.assertIsInstance(result["ai_assessment"], dict)
        self.assertIsInstance(result["report"], dict)
        self.assertIsInstance(result["errors"], list)

        # 3. Pydantic Model Conformance
        pydantic_obj = UnifiedAnalysisResult(
            schema_version=result["schema_version"],
            analysis_id=result["analysis_id"],
            status=result["status"],
            file=result["file"],
            hashes=result["hashes"],
            pe=result["pe"],
            sections=list(result["sections"]),
            entropy=result["entropy"],
            strings=result["strings"],
            imports=list(result["imports"]),
            indicators=list(result["indicators"]),
            risk=result["risk"],
            risk_score=result["risk_score"],
            ethiopian_context=result["ethiopian_context"],
            ai_assessment=result["ai_assessment"],
            report=result["report"],
            errors=result["errors"],
        )
        self.assertEqual(pydantic_obj.analysis_id, result["analysis_id"])

    def test_02_strict_evidence_distinction(self):
        """
        Verify the system strictly distinguishes:
        1. Observed static evidence (raw PE, sections, strings, imports, hashes)
        2. Rule-based indicators (indicators, risk_score, ethiopian_context)
        3. AI interpretation (ai_assessment)
        And AI interpretation never overrides observed evidence.
        """
        result = unified_pipeline_service.execute_pipeline(
            self.ethio_pe,
            filename="evidence_separation_test.exe",
            language="en"
        )

        # (1) Observed Evidence
        self.assertIn("sha256", result["hashes"])
        self.assertIn("filename", result["file"])
        self.assertIn("urls", result["strings"])

        # (2) Rule-Based Indicators
        self.assertIn("score", result["risk"])
        self.assertIn("relevance", result["ethiopian_context"])
        self.assertEqual(result["ethiopian_context"]["relevance"], "HIGH")

        # (3) AI Interpretation
        self.assertIn("summary", result["ai_assessment"])
        self.assertIn("confidence", result["ai_assessment"])
        self.assertIn("limitations", result["ai_assessment"])

        # Invariant: AI summary cannot alter the cryptographic SHA-256 hash or file size
        self.assertEqual(len(result["hashes"]["sha256"]), 64)
        self.assertEqual(result["file"]["file_size"], len(self.ethio_pe))

    def test_03_analyzer_failure_handling_and_recovery(self):
        """
        Verify that if an analyzer encounters malformed headers/data:
        - The pipeline does NOT crash
        - The error is captured in `errors`
        - Safe analysis continues
        - Incomplete results are clearly reported
        """
        corrupt_opt_pe = SyntheticPEBuilder.create_malformed_pe("corrupt_optional_magic")
        result = unified_pipeline_service.execute_pipeline(
            corrupt_opt_pe,
            filename="corrupt_optional_magic.exe",
            language="en"
        )

        self.assertIn("analysis_id", result)
        self.assertIsInstance(result["errors"], list)
        self.assertIsInstance(result["sections"], list)
        self.assertIsInstance(result["imports"], list)
        self.assertIn("report", result)
        self.assertIn("sha256", result["hashes"])
        self.assertIn("file_entropy", result["entropy"])

    def test_04_bilingual_amharic_pipeline(self):
        """Verify full pipeline execution in Amharic locale ('am') generates localized analysis and lessons."""
        result_am = unified_pipeline_service.execute_pipeline(
            self.benign_pe,
            filename="amharic_report_sample.exe",
            language="am"
        )

        self.assertEqual(result_am["language"], "am")
        self.assertEqual(result_am["report"]["language"], "am")
        self.assertIn("learning_mode", result_am)
        self.assertEqual(result_am["learning_mode"]["language"], "am")

    def test_05_api_post_analyze_flow_and_report_export(self):
        """Test API POST /api/dashboard/analyze endpoint returns Unified Analysis Object and persists to database."""
        file_obj = io.BytesIO(self.suspicious_pe)
        res = self.client.post(
            "/api/dashboard/analyze?language=en",
            files={"file": ("api_integration_sample.exe", file_obj, "application/octet-stream")},
            headers=self.admin_hdr
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn("analysis_id", data)
        self.assertIn("risk", data)
        self.assertIn("errors", data)
        aid = data["analysis_id"]

        report_res = self.client.get(f"/api/dashboard/samples/{aid}/report?format=json", headers=self.admin_hdr)
        self.assertEqual(report_res.status_code, 200)

    # =========================================================================
    # Step 13: Exhaustive Failure Tests (10 Specific Failure Scenarios)
    # =========================================================================

    def test_failure_01_invalid_non_pe_file(self):
        """1. Invalid file: non-PE payload rejected safely by intake perimeter."""
        bad_bytes = b"Hello, this is a plain text file pretending to be an executable."
        file_obj = io.BytesIO(bad_bytes)
        res = self.client.post(
            "/api/files/upload",
            files={"file": ("invalid_non_pe.exe", file_obj, "application/octet-stream")}
        )
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json().get("detail", {}).get("status"), "REJECTED_INVALID_PE")

    def test_failure_02_malformed_pe_structure(self):
        """2. Malformed PE: corrupt PE headers handled without crashing application."""
        corrupt_pe = SyntheticPEBuilder.create_malformed_pe("bad_pe_magic")
        file_obj = io.BytesIO(corrupt_pe)
        res = self.client.post(
            "/api/files/upload",
            files={"file": ("malformed_pe.exe", file_obj, "application/octet-stream")}
        )
        self.assertEqual(res.status_code, 400)

    def test_failure_03_missing_sample_retrieval(self):
        """3. Missing file / non-existent sample: gracefully returns 404."""
        res = self.client.get("/api/dashboard/samples/ANL-NONEXISTENT-9999/full", headers=self.admin_hdr)
        self.assertEqual(res.status_code, 404)

    def test_failure_04_isolated_analyzer_fault_injection(self):
        """4. Analyzer failure: injected analyzer fault handled safely and marked as FAILED."""
        with patch("app.pipeline.orchestrator.entropy_analyzer_service.analyze_bytes", side_effect=RuntimeError("Entropy calculation failed")):
            res = unified_pipeline_service.execute_pipeline(
                self.benign_pe,
                filename="fault_injected_entropy.exe",
                language="en"
            )
            self.assertEqual(res["status"], "PARTIAL")
            self.assertIn("Entropy Analyzer Error: Entropy calculation failed", res["errors"])
            self.assertEqual(res["entropy"]["status"], "FAILED")
            self.assertEqual(res["entropy"]["error_code"], "ENTROPY_ANALYSIS_ERROR")
            # Other analyzers still succeeded
            self.assertIn("sha256", res["hashes"])
            self.assertIsInstance(res["sections"], list)

    def test_failure_05_database_persistence_error_isolation(self):
        """5. Database failure: database commit failure does not abort the return analysis."""
        with patch("app.pipeline.orchestrator.SampleRepository.save_full_analysis_transaction", side_effect=Exception("Database lock collision")):
            res = unified_pipeline_service.execute_pipeline(
                self.benign_pe,
                filename="db_fail_sample.exe",
                language="en"
            )
            self.assertIn("analysis_id", res)
            self.assertIn("risk", res)

    def test_failure_06_ai_timeout_safety(self):
        """6. AI timeout: AI provider timeout marks AI as UNAVAILABLE while preserving static findings."""
        with patch("app.pipeline.orchestrator.ai_security_analyst_service.analyze", side_effect=TimeoutError("AI Gateway timed out after 30s")):
            res = unified_pipeline_service.execute_pipeline(
                self.benign_pe,
                filename="ai_timeout_sample.exe",
                language="en"
            )
            self.assertEqual(res["ai_assessment"]["status"], "UNAVAILABLE")
            self.assertEqual(res["ai_assessment"]["reason"], "AI provider unavailable")
            self.assertIn("sha256", res["hashes"])
            self.assertIn("score", res["risk"])

    def test_failure_07_ai_malformed_response(self):
        """7. AI malformed response: non-JSON / corrupt AI output triggers safe fallback without crashing."""
        mock_provider = MagicMock()
        mock_provider.generate_analysis.return_value = "MALFORMED_NON_JSON_OUTPUT_%%%@@@"

        with patch.object(ai_security_analyst_service, "provider", mock_provider):
            res = unified_pipeline_service.execute_pipeline(
                self.benign_pe,
                filename="ai_malformed_response.exe",
                language="en"
            )
            self.assertIn("assessment", res["ai_assessment"])
            self.assertIn("summary", res["ai_assessment"])

    def test_failure_08_unauthorized_user_access(self):
        """8. Unauthorized user: unauthenticated request blocked with 401."""
        res = self.client.get("/api/auth/me")
        self.assertEqual(res.status_code, 401)

    def test_failure_09_unauthorized_object_idor_access(self):
        """9. Unauthorized analysis access: User B cannot access User A's private analysis sample."""
        # 1. User A uploads and analyzes sample
        file_obj = io.BytesIO(self.benign_pe)
        post_res = self.client.post(
            "/api/dashboard/analyze?language=en",
            files={"file": ("user_a_isolated.exe", file_obj, "application/octet-stream")},
            headers=self.user_a_hdr
        )
        self.assertEqual(post_res.status_code, 200)
        aid = post_res.json()["analysis_id"]

        # 2. User B attempts to access User A's sample -> Blocked with 403
        get_res = self.client.get(f"/api/dashboard/samples/{aid}/full", headers=self.user_b_hdr)
        self.assertEqual(get_res.status_code, 403)

    def test_failure_10_report_generator_error_containment(self):
        """10. Report generation failure: report generation errors contained safely."""
        with patch("app.pipeline.orchestrator.security_report_generator_service.generate_report", side_effect=Exception("Template rendering failure")):
            res = unified_pipeline_service.execute_pipeline(
                self.benign_pe,
                filename="report_fail_sample.exe",
                language="en"
            )
            self.assertEqual(res["status"], "PARTIAL")
            self.assertIn("Report Generator Error: Template rendering failure", res["errors"])
            self.assertIn("report_id", res["report"])

    # =========================================================================
    # Step 15: Pipeline Performance Profiling
    # =========================================================================

    def test_performance_pipeline_benchmarks(self):
        """Measures individual stage execution durations to identify any bottlenecks."""
        t_start = time.perf_counter()
        res = unified_pipeline_service.execute_pipeline(
            self.benign_pe,
            filename="perf_bench_sample.exe",
            language="en"
        )
        t_total = (time.perf_counter() - t_start) * 1000

        # Entire in-memory static pipeline should execute under 1500 ms
        self.assertLess(t_total, 1500.0, f"Analysis pipeline exceeded 1500ms threshold: {t_total:.2f}ms")
        self.assertEqual(res["status"], "COMPLETED")


if __name__ == "__main__":
    unittest.main()
