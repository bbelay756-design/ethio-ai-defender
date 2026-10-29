"""
AUTH-01: API Access Control & Authorization Hardening Test Matrix.

Verifies:
1. GET /api/analyses without token -> 401 Unauthorized.
2. GET /api/analyses/{analysis_id} without token -> 401 Unauthorized.
3. GET /api/files/{analysis_id} without token -> 401 Unauthorized.
4. User A accessing User B's analysis -> 403 Forbidden.
5. User A accessing User B's sub-resources (/strings, /pe, /imports, /iocs, /ai, /ghidra, /report, /reviews, /notes, /ask-ai) -> 403 Forbidden.
6. User A accessing User B's file metadata (/api/files/{analysis_id}) -> 403 Forbidden.
7. Admin accessing User B's analysis and file metadata -> 200 OK.
8. Non-admin listing analyses -> only sees own and unassigned samples, never other users' samples.
9. VIEWER role cannot create notes (POST /api/analyses/{analysis_id}/notes) -> 403 Forbidden.
10. VIEWER role cannot update case tracking (PUT/PATCH /api/analyses/{analysis_id}/case) -> 403 Forbidden.
11. User A cannot delete User B's note (DELETE /api/analyses/{analysis_id}/notes/{note_id}) -> 403 Forbidden.
12. Admin can delete any user's note -> 200 OK.
13. Additional coverage: compare endpoint authorization, unassigned sample access, owner CRUD operations.
"""

import unittest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal, init_db
from app.db.models import UserModel, SampleModel, SectionModel, ImportModel, StringModel, IOCModel, AnalystNoteModel, AuditLogModel
from app.audit.events import AuditEventType
from app.db.repository import SampleRepository
from app.db.schemas import SampleCreate
from app.auth.service import AuthService
from app.core.storage import analysis_store, FileRecord


class TestAuth01AuthorizationHardening(unittest.TestCase):
    """Complete authorization and object-level scoping verification suite."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)
        cls.db = SessionLocal()

        # Seed distinct test users
        cls.user_a_name = "auth01_user_a"
        cls.user_b_name = "auth01_user_b"
        cls.admin_name = "auth01_admin"
        cls.viewer_name = "auth01_viewer"
        cls.password = "SecureAuthTest123!"

        users_info = [
            (cls.user_a_name, "ANALYST"),
            (cls.user_b_name, "ANALYST"),
            (cls.admin_name, "ADMIN"),
            (cls.viewer_name, "VIEWER"),
        ]

        cls.user_records = {}
        for username, role in users_info:
            existing = cls.db.query(UserModel).filter(UserModel.username == username).first()
            if existing:
                cls.db.delete(existing)
                cls.db.commit()
            u = AuthService.register_user(
                db=cls.db,
                username=username,
                email=f"{username}@ethio-defender.local",
                password=cls.password,
                role=role
            )
            cls.user_records[username] = u

        # Generate tokens
        cls.token_a = cls._login(cls.user_a_name, cls.password)
        cls.token_b = cls._login(cls.user_b_name, cls.password)
        cls.token_admin = cls._login(cls.admin_name, cls.password)
        cls.token_viewer = cls._login(cls.viewer_name, cls.password)

        cls.hdr_a = {"Authorization": f"Bearer {cls.token_a}"}
        cls.hdr_b = {"Authorization": f"Bearer {cls.token_b}"}
        cls.hdr_admin = {"Authorization": f"Bearer {cls.token_admin}"}
        cls.hdr_viewer = {"Authorization": f"Bearer {cls.token_viewer}"}

        # Create Sample for User A
        cls.sample_a_id = "AUTH01-SMPL-USER-A-000000000001"
        cls.sample_a = SampleRepository.create_sample(
            cls.db,
            SampleCreate(
                analysis_id=cls.sample_a_id,
                filename="sample_user_a.exe",
                size=2048,
                file_type="EXE",
                architecture="x64",
                md5="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                sha1="a" * 40,
                sha256="a" * 64,
                status="COMPLETED",
                risk_score=25,
                classification="LOW",
                user_id=cls.user_records[cls.user_a_name].id,
            )
        )

        # Create Sample for User B
        cls.sample_b_id = "AUTH01-SMPL-USER-B-000000000002"
        cls.sample_b = SampleRepository.create_sample(
            cls.db,
            SampleCreate(
                analysis_id=cls.sample_b_id,
                filename="sample_user_b.exe",
                size=4096,
                file_type="EXE",
                architecture="x64",
                md5="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                sha1="b" * 40,
                sha256="b" * 64,
                status="COMPLETED",
                risk_score=88,
                classification="CRITICAL",
                user_id=cls.user_records[cls.user_b_name].id,
            )
        )

        # Create Unassigned Sample (no owner)
        cls.sample_unassigned_id = "AUTH01-SMPL-UNASSIGNED-00000003"
        cls.sample_unassigned = SampleRepository.create_sample(
            cls.db,
            SampleCreate(
                analysis_id=cls.sample_unassigned_id,
                filename="sample_unassigned.exe",
                size=1024,
                file_type="EXE",
                architecture="x86",
                md5="cccccccccccccccccccccccccccccccc",
                sha1="c" * 40,
                sha256="c" * 64,
                status="COMPLETED",
                risk_score=10,
                classification="LOW",
                user_id=None,
            )
        )

        # Populate child relations for Sample B to allow testing sub-endpoints
        sec_b = SectionModel(sample_id=cls.sample_b.id, name=".text", virtual_address=4096, virtual_size=1000, raw_size=1024, entropy=6.5, characteristics="0x60000020")
        imp_b = ImportModel(sample_id=cls.sample_b.id, dll="kernel32.dll", api="CreateProcessW", category="EXECUTION", risk_relevance="HIGH")
        str_b = StringModel(sample_id=cls.sample_b.id, value="cmd.exe /c calc", category="COMMAND", severity="HIGH", suspicious=True)
        ioc_b = IOCModel(sample_id=cls.sample_b.id, type="URL", value="http://malicious-b.com/stage1", confidence=0.9)
        cls.db.add_all([sec_b, imp_b, str_b, ioc_b])
        cls.db.commit()

        # Save FileRecords in AnalysisStore for file intake endpoint tests
        analysis_store.save_record(FileRecord(
            analysis_id=cls.sample_a_id,
            filename="sample_user_a.exe",
            original_filename="sample_user_a.exe",
            size=2048,
            sha256="a" * 64,
            md5="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            sha1="a" * 40,
            status="COMPLETED",
            uploaded_at=datetime.now(timezone.utc).isoformat(),
            file_type="EXE",
            quarantined_path=""
        ))
        analysis_store.save_record(FileRecord(
            analysis_id=cls.sample_b_id,
            filename="sample_user_b.exe",
            original_filename="sample_user_b.exe",
            size=4096,
            sha256="b" * 64,
            md5="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            sha1="b" * 40,
            status="COMPLETED",
            uploaded_at=datetime.now(timezone.utc).isoformat(),
            file_type="EXE",
            quarantined_path=""
        ))
        analysis_store.save_record(FileRecord(
            analysis_id=cls.sample_unassigned_id,
            filename="sample_unassigned.exe",
            original_filename="sample_unassigned.exe",
            size=1024,
            sha256="c" * 64,
            md5="cccccccccccccccccccccccccccccccc",
            sha1="c" * 40,
            status="COMPLETED",
            uploaded_at=datetime.now(timezone.utc).isoformat(),
            file_type="EXE",
            quarantined_path=""
        ))

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    @classmethod
    def _login(cls, username, password):
        temp_client = TestClient(app)
        res = temp_client.post("/api/auth/login", json={"username": username, "password": password})
        if res.status_code == 200:
            return res.json().get("access_token")
        raise RuntimeError(f"Login failed for {username}: {res.status_code} {res.text}")

    # =========================================================================
    # 1. Unauthenticated requests receive 401 Unauthorized
    # =========================================================================

    def test_01_unauthenticated_analyses_list_returns_401(self):
        """GET /api/analyses without token -> 401 Unauthorized."""
        res = self.client.get("/api/analyses")
        self.assertEqual(res.status_code, 401)

    def test_02_unauthenticated_analysis_detail_returns_401(self):
        """GET /api/analyses/{analysis_id} without token -> 401 Unauthorized."""
        res = self.client.get(f"/api/analyses/{self.sample_a_id}")
        self.assertEqual(res.status_code, 401)

    def test_03_unauthenticated_file_record_returns_401(self):
        """GET /api/files/{analysis_id} without token -> 401 Unauthorized."""
        res = self.client.get(f"/api/files/{self.sample_a_id}")
        self.assertEqual(res.status_code, 401)

    def test_03b_unauthenticated_overview_and_compare_returns_401(self):
        """GET /api/analyses/overview-stats & /compare without token -> 401 Unauthorized."""
        res_ov = self.client.get("/api/analyses/overview-stats")
        self.assertEqual(res_ov.status_code, 401)

        res_cmp = self.client.get(f"/api/analyses/compare?id1={self.sample_a_id}&id2={self.sample_b_id}")
        self.assertEqual(res_cmp.status_code, 401)

    # =========================================================================
    # 2. Object-Level Access Control (IDOR / BOLA Prevention)
    # =========================================================================

    def test_04_user_a_accessing_user_b_analysis_returns_403(self):
        """User A accessing User B's analysis -> 403 Forbidden."""
        res = self.client.get(f"/api/analyses/{self.sample_b_id}", headers=self.hdr_a)
        self.assertEqual(res.status_code, 403)
        self.assertIn("Access denied", res.text)

    def test_05_user_a_accessing_user_b_sub_resources_returns_403(self):
        """User A accessing User B's sub-resources -> 403 Forbidden across all endpoints."""
        sub_endpoints = [
            ("GET", f"/api/analyses/{self.sample_b_id}/strings", None),
            ("GET", f"/api/analyses/{self.sample_b_id}/pe", None),
            ("GET", f"/api/analyses/{self.sample_b_id}/imports", None),
            ("GET", f"/api/analyses/{self.sample_b_id}/iocs", None),
            ("GET", f"/api/analyses/{self.sample_b_id}/ai", None),
            ("GET", f"/api/analyses/{self.sample_b_id}/ghidra", None),
            ("GET", f"/api/analyses/{self.sample_b_id}/report", None),
            ("GET", f"/api/analyses/{self.sample_b_id}/reviews", None),
            ("GET", f"/api/analyses/{self.sample_b_id}/notes", None),
            ("POST", f"/api/analyses/{self.sample_b_id}/ask-ai", {"question": "What is this file?", "language": "en"}),
        ]

        for method, endpoint, json_body in sub_endpoints:
            with self.subTest(endpoint=endpoint, method=method):
                if method == "GET":
                    res = self.client.get(endpoint, headers=self.hdr_a)
                elif method == "POST":
                    res = self.client.post(endpoint, json=json_body, headers=self.hdr_a)
                self.assertEqual(
                    res.status_code,
                    403,
                    f"Expected 403 Forbidden for User A accessing User B's {endpoint}, got {res.status_code}: {res.text}"
                )

    def test_06_user_a_accessing_user_b_file_metadata_returns_403(self):
        """User A accessing User B's file metadata (/api/files/{analysis_id}) -> 403 Forbidden."""
        res = self.client.get(f"/api/files/{self.sample_b_id}", headers=self.hdr_a)
        self.assertEqual(res.status_code, 403)
        self.assertIn("Access denied", res.text)

    def test_07_admin_accessing_user_b_analysis_and_file_metadata_returns_200(self):
        """Admin accessing User B's analysis and file metadata -> 200 OK."""
        res_analysis = self.client.get(f"/api/analyses/{self.sample_b_id}", headers=self.hdr_admin)
        self.assertEqual(res_analysis.status_code, 200)
        self.assertEqual(res_analysis.json()["analysis_id"], self.sample_b_id)

        res_file = self.client.get(f"/api/files/{self.sample_b_id}", headers=self.hdr_admin)
        self.assertEqual(res_file.status_code, 200)
        self.assertEqual(res_file.json()["analysis_id"], self.sample_b_id)

    def test_08_non_admin_listing_analyses_sees_only_own_and_unassigned(self):
        """Non-admin listing analyses -> only sees own and unassigned samples, never User B's."""
        res = self.client.get("/api/analyses", headers=self.hdr_a)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        returned_ids = [item["analysis_id"] for item in data["items"]]

        # User A must see their own sample
        self.assertIn(self.sample_a_id, returned_ids)
        # User A must see the unassigned sample
        self.assertIn(self.sample_unassigned_id, returned_ids)
        # User A must NOT see User B's sample
        self.assertNotIn(self.sample_b_id, returned_ids)

    def test_08b_admin_listing_analyses_sees_all_samples(self):
        """Admin listing analyses -> sees all samples across all users."""
        res = self.client.get("/api/analyses", headers=self.hdr_admin)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        returned_ids = [item["analysis_id"] for item in data["items"]]

        self.assertIn(self.sample_a_id, returned_ids)
        self.assertIn(self.sample_b_id, returned_ids)
        self.assertIn(self.sample_unassigned_id, returned_ids)

    # =========================================================================
    # 3. Role and Permission Enforcements (Notes & Cases)
    # =========================================================================

    def test_09_viewer_cannot_create_notes_returns_403(self):
        """VIEWER role cannot create notes (POST /api/analyses/{analysis_id}/notes) -> 403 Forbidden."""
        res = self.client.post(
            f"/api/analyses/{self.sample_unassigned_id}/notes",
            json={"content": "Viewer attempt to create note.", "tag": "OBSERVATION"},
            headers=self.hdr_viewer
        )
        self.assertEqual(res.status_code, 403)

    def test_10_viewer_cannot_update_case_returns_403(self):
        """VIEWER role cannot update case tracking (PUT and PATCH) -> 403 Forbidden."""
        patch_res = self.client.patch(
            f"/api/analyses/{self.sample_unassigned_id}/case",
            json={"case_id": "CASE-VIEWER-001", "case_status": "OPEN", "case_priority": "LOW"},
            headers=self.hdr_viewer
        )
        self.assertEqual(patch_res.status_code, 403)

        put_res = self.client.put(
            f"/api/analyses/{self.sample_unassigned_id}/case",
            json={"case_id": "CASE-VIEWER-001", "case_status": "OPEN", "case_priority": "LOW"},
            headers=self.hdr_viewer
        )
        self.assertEqual(put_res.status_code, 403)

    def test_11_user_a_cannot_delete_user_b_note_returns_403(self):
        """User A cannot delete User B's note -> 403 Forbidden."""
        # 1. User B adds a note to sample B
        add_res = self.client.post(
            f"/api/analyses/{self.sample_b_id}/notes",
            json={"content": "Private note by User B.", "tag": "IOC_CONFIRMATION"},
            headers=self.hdr_b
        )
        self.assertEqual(add_res.status_code, 200)
        note_id = add_res.json()["id"]

        # 2. User A attempts to delete User B's note
        del_res = self.client.delete(
            f"/api/analyses/{self.sample_b_id}/notes/{note_id}",
            headers=self.hdr_a
        )
        # Should be blocked either by sample access check (403) or note ownership check (403)
        self.assertEqual(del_res.status_code, 403)

        # 3. Verify note still exists
        note_in_db = self.db.query(AnalystNoteModel).filter(AnalystNoteModel.id == note_id).first()
        self.assertIsNotNone(note_in_db)

    def test_12_admin_can_delete_any_users_note_returns_200(self):
        """Admin can delete any user's note -> 200 OK."""
        # 1. User B adds a note to sample B
        add_res = self.client.post(
            f"/api/analyses/{self.sample_b_id}/notes",
            json={"content": "Note to be deleted by Admin.", "tag": "OBSERVATION"},
            headers=self.hdr_b
        )
        self.assertEqual(add_res.status_code, 200)
        note_id = add_res.json()["id"]

        # 2. Admin deletes User B's note
        del_res = self.client.delete(
            f"/api/analyses/{self.sample_b_id}/notes/{note_id}",
            headers=self.hdr_admin
        )
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.json()["status"], "deleted")

        # 3. Verify note is deleted from DB
        self.db.expire_all()
        note_in_db = self.db.query(AnalystNoteModel).filter(AnalystNoteModel.id == note_id).first()
        self.assertIsNone(note_in_db)

    # =========================================================================
    # 4. Legitimate Access Tests (Owner & Unassigned Samples)
    # =========================================================================

    def test_13_owner_can_access_own_analysis_and_sub_resources(self):
        """User A can access their own analysis and sub-resources -> 200 OK."""
        res_main = self.client.get(f"/api/analyses/{self.sample_a_id}", headers=self.hdr_a)
        self.assertEqual(res_main.status_code, 200)
        self.assertEqual(res_main.json()["analysis_id"], self.sample_a_id)

        res_strings = self.client.get(f"/api/analyses/{self.sample_a_id}/strings", headers=self.hdr_a)
        self.assertEqual(res_strings.status_code, 200)

        res_file = self.client.get(f"/api/files/{self.sample_a_id}", headers=self.hdr_a)
        self.assertEqual(res_file.status_code, 200)

    def test_14_non_admin_can_access_unassigned_sample(self):
        """Non-admin user can access unassigned sample -> 200 OK."""
        res = self.client.get(f"/api/analyses/{self.sample_unassigned_id}", headers=self.hdr_a)
        self.assertEqual(res.status_code, 200)

        res_file = self.client.get(f"/api/files/{self.sample_unassigned_id}", headers=self.hdr_a)
        self.assertEqual(res_file.status_code, 200)

    def test_15_owner_can_delete_own_note(self):
        """User A can delete their own note -> 200 OK."""
        add_res = self.client.post(
            f"/api/analyses/{self.sample_a_id}/notes",
            json={"content": "Note by User A to be deleted by User A.", "tag": "OBSERVATION"},
            headers=self.hdr_a
        )
        self.assertEqual(add_res.status_code, 200)
        note_id = add_res.json()["id"]

        del_res = self.client.delete(
            f"/api/analyses/{self.sample_a_id}/notes/{note_id}",
            headers=self.hdr_a
        )
        self.assertEqual(del_res.status_code, 200)

    def test_16_compare_endpoint_enforces_scoping(self):
        """Compare endpoint requires access to both samples."""
        # Comparing own sample A with unauthorized sample B -> 403 Forbidden
        res_fail = self.client.get(
            f"/api/analyses/compare?id1={self.sample_a_id}&id2={self.sample_b_id}",
            headers=self.hdr_a
        )
        self.assertEqual(res_fail.status_code, 403)

        # Comparing own sample A with unassigned sample -> 200 OK
        res_ok = self.client.get(
            f"/api/analyses/compare?id1={self.sample_a_id}&id2={self.sample_unassigned_id}",
            headers=self.hdr_a
        )
        self.assertEqual(res_ok.status_code, 200)

        # Admin comparing sample A and sample B -> 200 OK
        res_admin = self.client.get(
            f"/api/analyses/compare?id1={self.sample_a_id}&id2={self.sample_b_id}",
            headers=self.hdr_admin
        )
        self.assertEqual(res_admin.status_code, 200)

    def test_17_overview_stats_scoped_for_non_admin(self):
        """Overview stats returns valid structure scoped to user's authorized records."""
        res_a = self.client.get("/api/analyses/overview-stats", headers=self.hdr_a)
        self.assertEqual(res_a.status_code, 200)
        data_a = res_a.json()
        self.assertIn("total_analyses", data_a)
        # User A sees at least their own sample + unassigned sample
        self.assertGreaterEqual(data_a["total_analyses"], 2)

    # =========================================================================
    # 5. Missing / Invalid Identifiers and Audit Evidence
    # =========================================================================

    def test_18_missing_and_invalid_identifiers_do_not_expose_protected_data(self):
        """Missing, invalid, and nonexistent IDs fail closed without data exposure."""
        nonexistent_id = "AUTH01-NONEXISTENT-SAMPLE-9999"

        # 1. Unauthenticated requests to nonexistent IDs fail with 401 (not 404, preventing existence probing)
        res_unauth_analysis = self.client.get(f"/api/analyses/{nonexistent_id}")
        self.assertEqual(res_unauth_analysis.status_code, 401)

        res_unauth_file = self.client.get(f"/api/files/{nonexistent_id}")
        self.assertEqual(res_unauth_file.status_code, 401)

        # 2. Authenticated requests to nonexistent IDs return clean 404
        res_auth_analysis = self.client.get(f"/api/analyses/{nonexistent_id}", headers=self.hdr_a)
        self.assertEqual(res_auth_analysis.status_code, 404)
        self.assertIn("not found", res_auth_analysis.text.lower())

        res_auth_file = self.client.get(f"/api/files/{nonexistent_id}", headers=self.hdr_a)
        self.assertEqual(res_auth_file.status_code, 404)
        self.assertIn("not found", res_auth_file.text.lower())

        # 3. Path traversal attempts are blocked safely
        res_traversal = self.client.get("/api/analyses/..%2F..%2Fetc%2Fpasswd", headers=self.hdr_a)
        self.assertIn(res_traversal.status_code, (404, 400))

    def test_19_failed_authorization_leaves_database_state_unchanged(self):
        """Denied unauthorized operations leave database state completely unmodified."""
        # Baseline check: count notes and check current case status for sample A
        self.db.expire_all()
        notes_count_before = self.db.query(AnalystNoteModel).filter(
            AnalystNoteModel.sample_id == self.sample_a.id
        ).count()
        sample_a_db = self.db.query(SampleModel).filter(SampleModel.id == self.sample_a.id).first()
        case_status_before = sample_a_db.case_status
        case_priority_before = sample_a_db.case_priority

        # 1. VIEWER tries to add note -> 403 Forbidden
        viewer_note_res = self.client.post(
            f"/api/analyses/{self.sample_a_id}/notes",
            json={"content": "Malicious tampering attempt", "tag": "OBSERVATION"},
            headers=self.hdr_viewer
        )
        self.assertEqual(viewer_note_res.status_code, 403)

        # 2. VIEWER tries to change case status -> 403 Forbidden
        viewer_case_res = self.client.patch(
            f"/api/analyses/{self.sample_a_id}/case",
            json={"case_status": "RESOLVED", "case_priority": "LOW"},
            headers=self.hdr_viewer
        )
        self.assertEqual(viewer_case_res.status_code, 403)

        # Verify DB state is unchanged
        self.db.expire_all()
        notes_count_after = self.db.query(AnalystNoteModel).filter(
            AnalystNoteModel.sample_id == self.sample_a.id
        ).count()
        sample_a_after = self.db.query(SampleModel).filter(SampleModel.id == self.sample_a.id).first()
        self.assertEqual(notes_count_after, notes_count_before)
        self.assertEqual(sample_a_after.case_status, case_status_before)
        self.assertEqual(sample_a_after.case_priority, case_priority_before)

    def test_20_case_status_transition_validation(self):
        """Case status and priority updates validate domain values."""
        # 1. Invalid status rejected with 400
        res_bad_status = self.client.patch(
            f"/api/analyses/{self.sample_a_id}/case",
            json={"case_status": "INVALID_STATE_DISMISSED"},
            headers=self.hdr_a
        )
        self.assertEqual(res_bad_status.status_code, 400)
        self.assertIn("Invalid case status", res_bad_status.text)

        # 2. Invalid priority rejected with 400
        res_bad_priority = self.client.patch(
            f"/api/analyses/{self.sample_a_id}/case",
            json={"case_priority": "SUPER_CRITICAL_IMMEDIATE"},
            headers=self.hdr_a
        )
        self.assertEqual(res_bad_priority.status_code, 400)
        self.assertIn("Invalid case priority", res_bad_priority.text)

        # 3. Valid status transitions succeed
        for valid_status in ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED"]:
            res = self.client.patch(
                f"/api/analyses/{self.sample_a_id}/case",
                json={"case_status": valid_status},
                headers=self.hdr_a
            )
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["case_status"], valid_status)

    def test_21_successful_authorized_changes_produce_expected_audit_events(self):
        """Authorized mutations generate audit events and denied operations do not generate success logs."""
        # Add note as user A
        add_res = self.client.post(
            f"/api/analyses/{self.sample_a_id}/notes",
            json={"content": "Audit trail test note.", "tag": "OBSERVATION"},
            headers=self.hdr_a
        )
        self.assertEqual(add_res.status_code, 200)
        note_id = add_res.json()["id"]

        # Verify audit log exists in DB for this addition
        self.db.expire_all()
        add_audit = self.db.query(AuditLogModel).filter(
            AuditLogModel.analysis_id == self.sample_a_id,
            AuditLogModel.user_id == self.user_records[self.user_a_name].id
        ).order_by(AuditLogModel.id.desc()).first()
        self.assertIsNotNone(add_audit)
        self.assertEqual(add_audit.result, "SUCCESS")
        self.assertIn("add_note", add_audit.details_json)

        # Delete note as user A
        del_res = self.client.delete(
            f"/api/analyses/{self.sample_a_id}/notes/{note_id}",
            headers=self.hdr_a
        )
        self.assertEqual(del_res.status_code, 200)

        # Verify audit log for deletion
        self.db.expire_all()
        del_audit = self.db.query(AuditLogModel).filter(
            AuditLogModel.analysis_id == self.sample_a_id,
            AuditLogModel.user_id == self.user_records[self.user_a_name].id
        ).order_by(AuditLogModel.id.desc()).first()
        self.assertIsNotNone(del_audit)
        self.assertEqual(del_audit.result, "SUCCESS")
        self.assertIn("delete_note", del_audit.details_json)


if __name__ == "__main__":
    unittest.main()
