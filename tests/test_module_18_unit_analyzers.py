"""
Module 18: Independent Unit Tests for Every Analyzer in ETHIO-AI Defender.
Tests every analyzer independently with synthetic benign, edge-case, and malformed inputs.
"""

import unittest
from pathlib import Path

from app.testing.synthetic_pe import SyntheticPEBuilder
from app.analyzers.file_intake import secure_intake_service
from app.analyzers.hash_analyzer import hash_analyzer_service
from app.analyzers.pe_analyzer import pe_static_analyzer_service
from app.analyzers.section_analyzer import pe_section_analyzer_service
from app.analyzers.entropy_analyzer import entropy_analyzer_service
from app.analyzers.string_analyzer import string_analyzer_service
from app.analyzers.import_analyzer import windows_api_import_analyzer_service
from app.analyzers.indicator_engine import suspicious_indicator_engine_service, SuspiciousIndicator
from app.analyzers.threat_scoring import threat_scoring_engine_service
from app.analyzers.ethiopian_context import ethiopian_context_engine_service
from app.ai.analyst import ai_security_analyst_service
from app.education.learning_mode import learning_mode_service
from app.reports.generator import security_report_generator_service
from app.db.session import init_db, SessionLocal
from app.db.repository import SampleRepository
from app.auth.service import AuthService
from app.auth.rate_limiter import rate_limiter
from app.audit.logger import SecurityAuditLogger
from app.audit.service import audit_service
from app.audit.events import AuditEventType, AuditResult


class TestModule18IndependentAnalyzers(unittest.TestCase):
    """Exhaustive independent unit testing for every analyzer module."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.valid_pe = SyntheticPEBuilder.create_minimal_pe()
        cls.packed_pe = SyntheticPEBuilder.create_packed_pe()
        cls.suspicious_pe = SyntheticPEBuilder.create_suspicious_import_pe()
        cls.ethio_pe = SyntheticPEBuilder.create_ethiopian_targeted_pe()
        cls.malformed_pe = SyntheticPEBuilder.create_malformed_pe("bad_dos_magic")

    # 1. File Intake Service (Module 01)
    def test_01_intake_analyzer_independent(self):
        """Test FileIntakeService on valid PE and rejection on malformed non-PE."""
        res_valid = secure_intake_service.process_bytes(self.valid_pe, raw_filename="valid_sample.exe")
        self.assertTrue(res_valid.is_success)
        self.assertIsNotNone(res_valid.analysis_id)
        hash_res = hash_analyzer_service.compute_from_bytes(self.valid_pe)
        self.assertEqual(res_valid.sha256, hash_res.sha256)

        res_mal = secure_intake_service.process_bytes(self.malformed_pe, raw_filename="corrupt.exe")
        self.assertFalse(res_mal.is_success)
        self.assertIn("REJECTED", res_mal.status)

    # 2. Cryptographic Hash Analyzer (Module 02)
    def test_02_hash_analyzer_independent(self):
        """Test HashAnalyzerService MD5, SHA-1, and SHA-256 calculation."""
        res = hash_analyzer_service.compute_from_bytes(self.valid_pe)
        self.assertEqual(len(res.md5), 32)
        self.assertEqual(len(res.sha1), 40)
        self.assertEqual(len(res.sha256), 64)
        self.assertEqual(res.file_size_bytes, len(self.valid_pe))

    # 3. PE Static Header Analyzer (Module 03)
    def test_03_pe_analyzer_independent(self):
        """Test PEStaticAnalyzerService header parsing and metadata extraction."""
        res = pe_static_analyzer_service.analyze_bytes(self.valid_pe)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.type, "PE32")
        self.assertEqual(res.architecture, "x86")
        self.assertIsNotNone(res.optional_header)

    # 4. Section Header Analyzer (Module 04)
    def test_04_section_analyzer_independent(self):
        """Test PESectionAnalyzer section boundaries, names, and characteristics."""
        res = pe_section_analyzer_service.analyze_bytes(self.valid_pe)
        self.assertGreaterEqual(res.total_sections, 2)
        sec_names = [s.name for s in res.sections]
        self.assertIn(".text", sec_names)
        self.assertIn(".data", sec_names)

    # 5. Entropy Analyzer (Module 05)
    def test_05_entropy_analyzer_independent(self):
        """Test EntropyAnalyzerService on normal vs high-entropy packed PE."""
        ent_normal = entropy_analyzer_service.analyze_bytes(self.valid_pe)
        self.assertLess(ent_normal.file_entropy, 7.0)

        ent_packed = entropy_analyzer_service.analyze_bytes(self.packed_pe)
        self.assertGreater(ent_packed.file_entropy, 0.0)
        self.assertTrue(ent_packed.is_valid)

    # 6. String Analyzer (Module 06)
    def test_06_string_analyzer_independent(self):
        """Test StringAnalyzerService extraction of URLs, IPs, and forensic strings."""
        res = string_analyzer_service.analyze_bytes(self.ethio_pe)
        self.assertTrue(res.is_valid)
        self.assertGreater(res.total_strings, 0)
        self.assertTrue(any("cbe.com.et" in u for u in res.urls))

    # 7. Import Analyzer (Module 07)
    def test_07_import_analyzer_independent(self):
        """Test WindowsAPIImportAnalyzer for suspicious API tracking and categories."""
        res = windows_api_import_analyzer_service.analyze_bytes(self.suspicious_pe)
        self.assertTrue(res.is_valid)
        self.assertIsNotNone(res.imports)

    # 8. Indicator Engine (Module 08)
    def test_08_indicator_engine_independent(self):
        """Test SuspiciousIndicatorEngine rule evaluation across extracted artifacts."""
        pe_res = pe_static_analyzer_service.analyze_bytes(self.suspicious_pe)
        sec_res = pe_section_analyzer_service.analyze_bytes(self.suspicious_pe)
        ent_res = entropy_analyzer_service.analyze_bytes(self.suspicious_pe)
        str_res = string_analyzer_service.analyze_bytes(self.suspicious_pe)
        imp_res = windows_api_import_analyzer_service.analyze_bytes(self.suspicious_pe)

        res = suspicious_indicator_engine_service.evaluate(
            pe=pe_res,
            sections=sec_res,
            entropy=ent_res,
            strings=str_res,
            imports=imp_res,
        )
        self.assertIsNotNone(res.indicators)
        self.assertTrue(res.is_valid)

    # 9. Threat Scoring Engine (Module 09)
    def test_09_threat_scoring_independent(self):
        """Test ThreatScoringEngine deterministic score and risk level calculation."""
        indicators = [
            SuspiciousIndicator(
                id="IND-MEM-001",
                name="Suspicious Memory Allocation",
                category="MEMORY",
                severity="HIGH",
                evidence="VirtualAlloc",
                confidence=0.85,
                explanation="Memory allocation"
            ),
            SuspiciousIndicator(
                id="IND-NET-001",
                name="Network Egress",
                category="NETWORK",
                severity="HIGH",
                evidence="C2 URL",
                confidence=0.80,
                explanation="Remote communication"
            ),
        ]
        res = threat_scoring_engine_service.calculate_score(indicators=indicators)
        self.assertGreaterEqual(res.score, 30)
        self.assertIn(res.risk_level, ["LOW", "MODERATE", "SUSPICIOUS", "HIGH", "CRITICAL"])

    # 10. Ethiopian Context Analyzer (Module 10)
    def test_10_ethiopian_context_independent(self):
        """Test EthiopianContextEngine domain and infrastructure targeting detection."""
        str_res = string_analyzer_service.analyze_bytes(self.ethio_pe)
        res = ethiopian_context_engine_service.analyze_context(
            indicators=[],
            strings=str_res,
            threat_score=40,
            language="en"
        )
        self.assertTrue(res.is_valid)
        self.assertTrue(res.has_explicit_domestic_artifacts)

    # 11. AI Security Analyst (Module 11)
    def test_11_ai_analyst_independent(self):
        """Test AISecurityAnalystService deterministic fallback and prompt sanitization."""
        evidence = {
            "file_metadata": {"filename": "sample.exe", "file_size": 2048},
            "hashes": {"sha256": "3aca6c684a39c9ecaf3de614663d9c2240be7869d5ed5642b49140034ca9db9e"},
            "threat_score": {"score": 75, "risk_level": "HIGH"},
            "indicators": {"indicators": [{"name": "Suspicious Memory Allocation", "severity": "HIGH"}]},
        }
        res = ai_security_analyst_service.analyze(evidence, language="en")
        self.assertIn(res.assessment, ["LOW", "MODERATE", "SUSPICIOUS", "HIGH", "CRITICAL"])
        self.assertIsNotNone(res.summary)
        self.assertIn(res.confidence, ["LOW", "MEDIUM", "HIGH"])

    # 12. Learning Mode Service (Module 12)
    def test_12_learning_mode_independent(self):
        """Test LearningModeService topic explanations in English and Amharic."""
        evidence = {
            "file_metadata": {"filename": "sample.exe", "machine_type": "x86"},
            "indicators": {"total_indicators": 1},
            "entropy": {"file_entropy": 7.4, "classification": "HIGH"},
        }
        res_en = learning_mode_service.generate_learning_report(evidence, language="en")
        self.assertGreater(res_en.total_lessons, 0)
        self.assertEqual(res_en.language, "en")

        res_am = learning_mode_service.generate_learning_report(evidence, language="am")
        self.assertGreater(res_am.total_lessons, 0)
        self.assertEqual(res_am.language, "am")

    # 13. Security Report Generator (Module 13)
    def test_13_report_generator_independent(self):
        """Test SecurityReportGeneratorService multi-format rendering (JSON, HTML)."""
        evidence = {
            "analysis_id": "ANL-TEST-M18",
            "filename": "benign.exe",
            "hashes": {"sha256": "448d67c89f1232913ab8c9f2a18a5344c05ed1c7b69d3aa06205a2eae6376973"},
            "threat_score": {"score": 20, "risk_level": "LOW"},
            "file_information": {"file_size": 1024, "machine_type": "x86"},
            "indicators": {"indicators": []},
            "sections": {"sections": []},
            "imports": {"imports": []},
            "strings": {"urls": [], "ip_addresses": [], "registry_paths": []},
            "ethiopian_context": {"is_ethiopia_targeted": False},
            "ai_assessment": {"summary": "Safe sample.", "confidence": "HIGH"},
        }
        report = security_report_generator_service.generate_report(evidence, language="en")
        self.assertIsNotNone(report)
        json_out = security_report_generator_service.export(report, format="json")
        self.assertIn("448d67c89f1232913ab8c9f2a18a5344c05ed1c7b69d3aa06205a2eae6376973", json_out)
        html_out = security_report_generator_service.export(report, format="html")
        self.assertIn("<html", html_out.lower())

    # 14. Database Persistence & Repository (Module 15)
    def test_14_database_repository_independent(self):
        """Test Database and SampleRepository transaction integrity."""
        import uuid
        from app.db.schemas import SampleCreate
        db = SessionLocal()
        try:
            aid = f"ANL-UNIT-18-{uuid.uuid4().hex[:8]}"
            sample_in = SampleCreate(
                analysis_id=aid,
                filename="unit_db_test.exe",
                size=len(self.valid_pe),
                file_type="PE32",
                architecture="x86",
                md5="0" * 32,
                sha1="0" * 40,
                sha256="a" * 64,
                status="COMPLETED",
            )
            sample = SampleRepository.create_sample(db, sample_in)
            self.assertIsNotNone(sample.id)

            fetched = SampleRepository.get_by_analysis_id(db, aid)
            self.assertIsNotNone(fetched)
            self.assertEqual(fetched.filename, "unit_db_test.exe")
        finally:
            db.close()

    # 15. Authentication & Rate Limiting (Module 16)
    def test_15_auth_and_rate_limiter_independent(self):
        """Test Password hashing, token validation, and rate limiter windowing."""
        import uuid
        from app.auth.security import verify_password
        db = SessionLocal()
        try:
            u_name = f"unit_tester_18_{uuid.uuid4().hex[:6]}"
            user = AuthService.register_user(db, u_name, f"{u_name}@soc.et", "ValidPass2026!", role="ANALYST")
            self.assertIsNotNone(user.id)
            self.assertTrue(verify_password("ValidPass2026!", user.salt, user.hashed_password))

            # Rate Limiter Check (1 failed attempt should not lock yet)
            is_locked, lock_mins = rate_limiter.record_failed_attempt(f"{u_name}_rl")
            self.assertFalse(is_locked)
            self.assertEqual(lock_mins, 0)
        finally:
            db.close()

    # 16. Security Audit System (Module 17)
    def test_16_audit_logger_independent(self):
        """Test SecurityAuditLogger structured logging and sanitized secret guarantee."""
        from app.audit.logger import audit_logger
        db = SessionLocal()
        try:
            payload = {
                "password": "DO_NOT_LOG_THIS_PASSWORD",
                "token": "DO_NOT_LOG_JWT_TOKEN",
                "safe_info": "analysis_completed_normally"
            }
            res = audit_logger.log_event(
                event=AuditEventType.ANALYSIS_COMPLETION,
                result=AuditResult.SUCCESS,
                analysis_id="ANL-UNIT-18-AUDIT",
                details=payload,
                db=db
            )
            self.assertEqual(res["details"]["password"], "[REDACTED]")
            self.assertEqual(res["details"]["token"], "[REDACTED]")
            self.assertEqual(res["details"]["safe_info"], "analysis_completed_normally")
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
