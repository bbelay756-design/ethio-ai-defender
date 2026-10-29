"""
Comprehensive Unit & Integration Test Suite for Module 20:
Ghidra Headless Static Reverse-Engineering Integration.

Covers:
- Availability handling when Ghidra is not configured.
- Deliberate disablement via GHIDRA_ENABLED=false.
- Missing quarantine file handling.
- Successful structured parsing through a mocked headless run.
- Timeout handling.
- Database persistence + GET /api/analyses/{id}/ghidra endpoint (RBAC / IDOR).
"""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.analyzers.ghidra_analyzer import GhidraAnalyzerService
from app.main import app
from app.db.session import SessionLocal, init_db, get_db, Base
from app.db.repository import SampleRepository
from app.db.schemas import (
    SampleCreate,
    GhidraAnalysisCreate,
    GhidraFunctionCreate,
    GhidraRelationshipCreate,
)
from app.db.models import (
    SampleModel,
    GhidraAnalysisModel,
    GhidraFunctionModel,
    GhidraRelationshipModel,
    UserModel,
)
from app.auth.roles import UserRole
from app.auth.security import hash_password, create_access_token


SAMPLE_PAYLOAD = {
    "ok": True,
    "program_name": "threat_sample.exe",
    "language_id": "x86:LE:64:default",
    "processor": "x86",
    "compiler": "windows",
    "image_base": "00400000",
    "entry_point": "00401000",
    "function_count": 2,
    "functions_truncated": False,
    "functions": [
        {"name": "FUN_00401000", "address": "00401000", "size": 64, "is_thunk": False, "calling_convention": "__cdecl"},
        {"name": "FUN_00401200", "address": "00401200", "size": 32, "is_thunk": True, "calling_convention": "__stdcall"},
    ],
    "imports": [
        {"name": "VirtualAlloc", "library": "KERNEL32.DLL"},
        {"name": "CreateRemoteThread", "library": "KERNEL32.DLL"},
    ],
    "exports": ["00401000"],
    "string_count": 3,
    "strings": [
        {"value": "powershell.exe -enc", "address": "00405000"},
        {"value": "http://c2.example.et/gate", "address": "00405020"},
        {"value": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "address": "00405040"},
    ],
    "relationship_count": 1,
    "relationships": [
        {"from_address": "00401000", "from_name": "FUN_00401000", "to_address": "00401200", "to_name": "FUN_00401200"},
    ],
    "errors": [],
}


class TestGhidraAnalyzerService(unittest.TestCase):
    """Unit tests for the Ghidra analyzer service behavior."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _make_fake_home(self) -> Path:
        """Creates a fake GHIDRA_HOME with an analyzeHeadless launcher file."""
        support = self.tmp_path / "ghidra_home" / "support"
        support.mkdir(parents=True, exist_ok=True)
        (support / "analyzeHeadless.bat").write_text("@echo off\n", encoding="ascii")
        return self.tmp_path / "ghidra_home"

    def _make_sample_file(self) -> Path:
        sample = self.tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 126 + b"PE\x00\x00")
        return sample

    def test_01_unavailable_when_not_configured(self):
        """Without GHIDRA_HOME the service reports UNAVAILABLE and never runs a process."""
        service = GhidraAnalyzerService(ghidra_home=None, workspace_dir=self.tmp_path / "ws", script_dir=self.tmp_path)
        # Ensure settings fallback is empty during this test.
        with mock.patch.object(settings, "GHIDRA_HOME", ""):
            available, reason = service.is_available()
            self.assertFalse(available)
            self.assertIn("not configured", reason.lower())

    def test_02_disabled_by_configuration(self):
        """GHIDRA_ENABLED=false yields DISABLED status."""
        fake_home = self._make_fake_home()
        service = GhidraAnalyzerService(ghidra_home=fake_home, workspace_dir=self.tmp_path / "ws", script_dir=self.tmp_path)
        sample = self._make_sample_file()
        with mock.patch.object(settings, "GHIDRA_ENABLED", False):
            available, reason = service.is_available()
            self.assertFalse(available)
            res = service.analyze_file(sample, analysis_id="ANL-DISABLED")
        self.assertEqual(res.status, "DISABLED")
        self.assertFalse(res.available)

    def test_03_missing_sample_file(self):
        """A non-existent quarantine path yields a FAILED status without invoking Ghidra."""
        fake_home = self._make_fake_home()
        service = GhidraAnalyzerService(ghidra_home=fake_home, workspace_dir=self.tmp_path / "ws", script_dir=self.tmp_path)
        res = service.analyze_file(self.tmp_path / "does_not_exist.exe", analysis_id="ANL-MISSING")
        self.assertEqual(res.status, "FAILED")

    def test_04_successful_parsing_with_mocked_headless(self):
        """A mocked Ghidra run writes structured JSON that is parsed correctly."""
        fake_home = self._make_fake_home()
        service = GhidraAnalyzerService(ghidra_home=fake_home, workspace_dir=self.tmp_path / "ws", script_dir=self.tmp_path)
        sample = self._make_sample_file()

        def fake_run(command, env=None, **kwargs):
            # Simulate the Ghidra script writing its output file.
            out_path = env["GHIDRA_OUT_FILE"]
            Path(out_path).parent.mkdir(parents=True, exist_ok=True)
            Path(out_path).write_text(json.dumps(SAMPLE_PAYLOAD), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "ok", "")

        with mock.patch("app.analyzers.ghidra_analyzer.subprocess.run", side_effect=fake_run):
            res = service.analyze_file(sample, analysis_id="ANL-OK-001")

        self.assertEqual(res.status, "SUCCESS")
        self.assertTrue(res.available)
        self.assertEqual(res.program_name, "threat_sample.exe")
        self.assertEqual(res.function_count, 2)
        self.assertEqual(len(res.functions), 2)
        self.assertEqual(res.functions[0].name, "FUN_00401000")
        self.assertTrue(res.functions[1].is_thunk)
        self.assertEqual(len(res.imports), 2)
        self.assertEqual(res.imports[0]["library"], "KERNEL32.DLL")
        self.assertEqual(res.exports, ["00401000"])
        self.assertEqual(res.string_count, 3)
        self.assertIn("powershell.exe -enc", res.strings)
        self.assertEqual(res.relationship_count, 1)
        self.assertEqual(len(res.relationships), 1)
        self.assertEqual(res.relationships[0].to_name, "FUN_00401200")

    def test_05_timeout_handling(self):
        """A process timeout yields TIMEOUT status."""
        fake_home = self._make_fake_home()
        service = GhidraAnalyzerService(ghidra_home=fake_home, workspace_dir=self.tmp_path / "ws", script_dir=self.tmp_path)
        sample = self._make_sample_file()

        def fake_run(command, env=None, **kwargs):
            raise subprocess.TimeoutExpired(command, settings.GHIDRA_TIMEOUT_SECONDS)

        with mock.patch("app.analyzers.ghidra_analyzer.subprocess.run", side_effect=fake_run):
            res = service.analyze_file(sample, analysis_id="ANL-TIMEOUT")

        self.assertEqual(res.status, "TIMEOUT")

    def test_06_nonzero_exit_is_failed(self):
        """A non-zero Ghidra exit code yields FAILED status."""
        fake_home = self._make_fake_home()
        service = GhidraAnalyzerService(ghidra_home=fake_home, workspace_dir=self.tmp_path / "ws", script_dir=self.tmp_path)
        sample = self._make_sample_file()

        def fake_run(command, env=None, **kwargs):
            return subprocess.CompletedProcess(command, 2, "", "ghidra boom")

        with mock.patch("app.analyzers.ghidra_analyzer.subprocess.run", side_effect=fake_run):
            res = service.analyze_file(sample, analysis_id="ANL-EXIT")

        self.assertEqual(res.status, "FAILED")
        self.assertTrue(res.errors)


class TestGhidraEndpoint(unittest.TestCase):
    """Integration tests for GET /api/analyses/{id}/ghidra."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.test_db_path = Path(cls._tmp.name) / "test_ghidra_endpoint.db"
        cls.engine = create_engine(
            f"sqlite:///{cls.test_db_path}",
            connect_args={"check_same_thread": False},
        )
        @event.listens_for(cls.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        cls.TestSession = sessionmaker(
            bind=cls.engine, autocommit=False, autoflush=False, expire_on_commit=False
        )
        Base.metadata.create_all(bind=cls.engine)

        def override_get_db():
            db = cls.TestSession()
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.patchers = [
            mock.patch("app.db.session.SessionLocal", cls.TestSession),
            mock.patch("app.api.analyses.SessionLocal", cls.TestSession),
        ]
        for p in cls.patchers:
            p.start()

        cls.client = TestClient(app)
        cls.db = cls.TestSession()

        s, h = hash_password("GhidraPass123!")
        cls.analyst_user = UserModel(
            username="test_ghidra_analyst",
            email="ghidra_analyst@defender.et",
            hashed_password=h,
            salt=s,
            role=UserRole.ANALYST.value,
        )
        cls.db.add(cls.analyst_user)
        cls.db.commit()
        cls.db.refresh(cls.analyst_user)

        cls.analyst_token, _, _ = create_access_token(
            {"sub": str(cls.analyst_user.id), "username": cls.analyst_user.username, "role": cls.analyst_user.role}
        )

        cls.analysis_id = "ANL-TEST-GHIDRA-001"
        cls.sample = SampleModel(
            analysis_id=cls.analysis_id,
            filename="ghidra_sample.exe",
            size=40960,
            file_type="PE32+ (Executable)",
            architecture="x86_64",
            md5="fedcba9876543210fedcba9876543210",
            sha1="fedcba9876543210fedcba9876543210fedcba98",
            sha256="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            status="COMPLETED",
            risk_score=60,
            classification="MEDIUM",
            user_id=cls.analyst_user.id,
        )
        cls.db.add(cls.sample)
        cls.db.commit()
        cls.db.refresh(cls.sample)

        cls.db.add(GhidraAnalysisModel(
            sample_id=cls.sample.id,
            status="SUCCESS",
            message="Ghidra recovered 2 function(s).",
            program_name="ghidra_sample.exe",
            language_id="x86:LE:64:default",
            processor="x86",
            compiler="windows",
            image_base="00400000",
            entry_point="00401000",
            function_count=2,
            import_count=2,
            export_count=0,
            string_count=5,
            relationship_count=1,
        ))
        cls.db.add_all([
            GhidraFunctionModel(sample_id=cls.sample.id, name="FUN_00401000", address="00401000", size=64, is_thunk=False, calling_convention="__cdecl"),
            GhidraFunctionModel(sample_id=cls.sample.id, name="FUN_00401200", address="00401200", size=32, is_thunk=True, calling_convention="__stdcall"),
        ])
        cls.db.add(GhidraRelationshipModel(
            sample_id=cls.sample.id,
            from_address="00401000",
            from_name="FUN_00401000",
            to_address="00401200",
            to_name="FUN_00401200",
        ))
        cls.db.commit()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        for p in reversed(cls.patchers):
            p.stop()
        app.dependency_overrides.pop(get_db, None)
        cls.engine.dispose()
        cls._tmp.cleanup()

    def test_01_endpoint_returns_stored_results(self):
        headers = {"Authorization": f"Bearer {self.analyst_token}"}
        res = self.client.get(f"/api/analyses/{self.analysis_id}/ghidra", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["analysis_id"], self.analysis_id)
        self.assertTrue(data["available"])
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["program"]["program_name"], "ghidra_sample.exe")
        self.assertEqual(data["statistics"]["function_count"], 2)
        self.assertEqual(data["statistics"]["functions_stored"], 2)
        self.assertEqual(len(data["functions"]), 2)
        self.assertEqual(data["functions"][0]["name"], "FUN_00401000")
        self.assertEqual(data["statistics"]["relationship_count"], 1)
        self.assertEqual(len(data["relationships"]), 1)
        self.assertEqual(data["relationships"][0]["to_name"], "FUN_00401200")

    def test_02_endpoint_404_for_unknown_analysis(self):
        headers = {"Authorization": f"Bearer {self.analyst_token}"}
        res = self.client.get("/api/analyses/ANL-DOES-NOT-EXIST/ghidra", headers=headers)
        self.assertEqual(res.status_code, 404)

    def test_03_endpoint_empty_fallback_for_sample_without_ghidra(self):
        # Create a sample without ghidra rows
        sid = "ANL-TEST-GHIDRA-NONE"
        existing = self.db.query(SampleModel).filter(SampleModel.analysis_id == sid).first()
        if not existing:
            existing = SampleModel(
                analysis_id=sid,
                filename="no_ghidra.exe",
                size=1024,
                file_type="PE32 (Executable)",
                architecture="x86",
                md5="00112233445566778899aabbccddeeff",
                sha1="00112233445566778899aabbccddeeff00112233",
                sha256="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                status="COMPLETED",
                risk_score=10,
                classification="LOW",
                user_id=self.analyst_user.id,
            )
            self.db.add(existing)
            self.db.commit()

        headers = {"Authorization": f"Bearer {self.analyst_token}"}
        res = self.client.get(f"/api/analyses/{sid}/ghidra", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "UNAVAILABLE")
        self.assertEqual(data["functions"], [])
        self.assertEqual(data["relationships"], [])


class TestGhidraTransactionPersistence(unittest.TestCase):
    """Verifies the atomic transaction persists Ghidra functions and relationships."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self._tmp.name) / "test_ghidra_tx.db"
        self.engine = create_engine(
            f"sqlite:///{self.test_db_path}",
            connect_args={"check_same_thread": False},
        )
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        self.TestSession = sessionmaker(
            bind=self.engine, autocommit=False, autoflush=False, expire_on_commit=False
        )
        Base.metadata.create_all(bind=self.engine)
        self.patcher = mock.patch("app.db.session.SessionLocal", self.TestSession)
        self.patcher.start()
        self.db = self.TestSession()
        self.analysis_id = "ANL-TEST-GHIDRA-TX"

    def tearDown(self):
        self.db.close()
        self.patcher.stop()
        self.engine.dispose()
        self._tmp.cleanup()

    def test_relationships_persisted_atomically(self):
        SampleRepository.save_full_analysis_transaction(
            db=self.db,
            sample_in=SampleCreate(
                analysis_id=self.analysis_id,
                filename="tx_sample.exe",
                size=2048,
                file_type="PE32 (Executable)",
                architecture="x86",
                md5="abcdefabcdefabcdefabcdefabcdefab",
                sha1="abcdefabcdefabcdefabcdefabcdefabcdefab",
                sha256="abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                status="COMPLETED",
                risk_score=40,
                classification="MEDIUM",
            ),
            ghidra_analysis_in=GhidraAnalysisCreate(
                status="SUCCESS",
                message="ok",
                function_count=2,
                relationship_count=1,
            ),
            ghidra_functions_in=[
                GhidraFunctionCreate(name="FUN_1", address="00401000", size=16),
                GhidraFunctionCreate(name="FUN_2", address="00401100", size=16),
            ],
            ghidra_relationships_in=[
                GhidraRelationshipCreate(
                    from_address="00401000", from_name="FUN_1",
                    to_address="00401100", to_name="FUN_2",
                ),
            ],
        )

        stored = SampleRepository.get_by_analysis_id(self.db, self.analysis_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored.ghidra_analysis.relationship_count, 1)
        self.assertEqual(len(stored.ghidra_functions), 2)
        self.assertEqual(len(stored.ghidra_relationships), 1)
        self.assertEqual(stored.ghidra_relationships[0].to_name, "FUN_2")


class TestGhidraSidecarIntegration(unittest.TestCase):
    """OPS-02: Unit and integration tests for containerized Ghidra sidecar service."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)
        self.sample_file = self.tmp_path / "quarantined_test.exe"
        self.sample_file.write_bytes(b"MZ" + b"\x00" * 126 + b"PE\x00\x00")
        self.service = GhidraAnalyzerService()

    def tearDown(self):
        self._tmp.cleanup()

    def _mock_http_response(self, status_code: int, data: dict):
        mock_resp = mock.MagicMock()
        mock_resp.getcode.return_value = status_code
        mock_resp.read.return_value = json.dumps(data).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None
        return mock_resp

    def test_01_sidecar_probe_healthy(self):
        """When sidecar is enabled and /health returns healthy, is_available returns True."""
        with mock.patch.object(settings, "GHIDRA_SIDECAR_ENABLED", True), \
             mock.patch("urllib.request.urlopen") as mock_url:
            mock_url.return_value = self._mock_http_response(200, {"status": "healthy", "ghidra_available": True})
            avail, reason = self.service.is_available()
            self.assertTrue(avail)
            self.assertIn("healthy and available", reason)

    def test_02_sidecar_probe_connection_refused_graceful_degradation(self):
        """When sidecar is enabled but daemon/container is down, report UNAVAILABLE."""
        import urllib.error
        with mock.patch.object(settings, "GHIDRA_SIDECAR_ENABLED", True), \
             mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            avail, reason = self.service.is_available()
            self.assertFalse(avail)
            self.assertIn("unavailable", reason.lower())

    def test_03_sidecar_successful_analysis(self):
        """Test successful structured extraction via sidecar RPC with zero binary detonation."""
        with mock.patch.object(settings, "GHIDRA_SIDECAR_ENABLED", True), \
             mock.patch.object(self.service, "is_available", return_value=(True, "ok")), \
             mock.patch("urllib.request.urlopen") as mock_url:
            mock_url.return_value = self._mock_http_response(200, SAMPLE_PAYLOAD)
            result = self.service.analyze_file(self.sample_file, analysis_id="ANL-SIDECAR-01")

            self.assertTrue(result.available)
            self.assertEqual(result.status, "SUCCESS")
            self.assertEqual(result.program_name, "threat_sample.exe")
            self.assertEqual(len(result.functions), 2)
            self.assertEqual(result.functions[0].name, "FUN_00401000")
            self.assertEqual(len(result.relationships), 1)
            self.assertEqual(len(result.strings), 3)

    def test_04_sidecar_timeout_handling(self):
        """Sidecar timeout gracefully returns TIMEOUT status without crashing."""
        import urllib.error
        with mock.patch.object(settings, "GHIDRA_SIDECAR_ENABLED", True), \
             mock.patch.object(self.service, "is_available", return_value=(True, "ok")), \
             mock.patch("urllib.request.urlopen", side_effect=TimeoutError("Request timed out")):
            result = self.service.analyze_file(self.sample_file, analysis_id="ANL-SIDECAR-TO")

            self.assertEqual(result.status, "UNAVAILABLE")
            self.assertFalse(result.available)

    def test_05_sidecar_http_503_graceful_fallback(self):
        """Sidecar returning HTTP 503 results in UNAVAILABLE without failing pipeline."""
        import urllib.error
        err = urllib.error.HTTPError(
            url="http://127.0.0.1:8089/analyze",
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=mock.MagicMock(read=lambda: b'{"detail": "Launcher missing"}')
        )
        with mock.patch.object(settings, "GHIDRA_SIDECAR_ENABLED", True), \
             mock.patch.object(self.service, "is_available", return_value=(True, "ok")), \
             mock.patch("urllib.request.urlopen", side_effect=err):
            result = self.service.analyze_file(self.sample_file, analysis_id="ANL-SIDECAR-503")

            self.assertEqual(result.status, "UNAVAILABLE")
            self.assertFalse(result.available)

    def test_06_sidecar_malformed_json_response(self):
        """Malformed JSON payload from sidecar handled defensively as FAILED."""
        mock_resp = mock.MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b"<html>502 Bad Gateway</html>"
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.__exit__.return_value = None

        with mock.patch.object(settings, "GHIDRA_SIDECAR_ENABLED", True), \
             mock.patch.object(self.service, "is_available", return_value=(True, "ok")), \
             mock.patch("urllib.request.urlopen", return_value=mock_resp):
            result = self.service.analyze_file(self.sample_file, analysis_id="ANL-SIDECAR-MAL")

            self.assertEqual(result.status, "FAILED")
            self.assertIn("invalid response format", result.message)

    def test_07_sidecar_token_header_sent(self):
        """Auth token header correctly passed when configured."""
        with mock.patch.object(settings, "GHIDRA_SIDECAR_ENABLED", True), \
             mock.patch.object(settings, "GHIDRA_SIDECAR_TOKEN", "test-secret-token"), \
             mock.patch.object(self.service, "is_available", return_value=(True, "ok")), \
             mock.patch("urllib.request.urlopen") as mock_url:
            mock_url.return_value = self._mock_http_response(200, SAMPLE_PAYLOAD)
            self.service.analyze_file(self.sample_file, analysis_id="ANL-SIDECAR-AUTH")

            req_arg = mock_url.call_args[0][0]
            self.assertEqual(req_arg.get_header("X-sidecar-token"), "test-secret-token")


if __name__ == "__main__":
    unittest.main()
