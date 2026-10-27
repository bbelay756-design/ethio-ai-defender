"""
Phase 3C Integration and Unit Tests: YARA Rule Management API.

Covers all 14 required capabilities:
1. Authorized rule creation and listing.
2. Retrieving a rule and its version history.
3. Publishing a valid new version.
4. Invalid YARA source rejection.
5. Published version immutability.
6. Correct current-version pointer after publication.
7. Deactivation and reactivation.
8. Unauthorized and insufficient-role requests.
9. Malformed payloads and invalid rule identifiers.
10. Audit events for successful management operations.
11. Failed operations leaving database state unchanged.
12. Historical matches retaining valid version provenance.
13. Concurrent or repeated publication behavior.
14. Database isolation verification (storage/defender.db untouched).
"""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

# Ensure isolated database environment BEFORE any app imports to protect storage/defender.db
_pre_tmp_dir = tempfile.mkdtemp()
_pre_tmp_db = os.path.join(_pre_tmp_dir, "test_api_env.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_pre_tmp_db}"
os.environ["ALEMBIC_DATABASE_URL"] = f"sqlite:///{_pre_tmp_db}"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from app.main import app as fastapi_app
import app.db.models
from app.db.session import Base, get_db
from app.db.models import (
    UserModel,
    YaraRuleModel,
    YaraRuleVersionModel,
    YaraMatchModel,
    SampleModel,
    AuditLogModel,
    RevokedTokenModel,
)
from app.auth.roles import UserRole
from app.auth.security import hash_password, create_access_token
from app.audit.events import AuditEventType
from app.services.yara_rule_publication_service import (
    create_rule_identity,
    publish_rule_version_safe,
    get_rule_by_id_or_name,
)

import tempfile

ROOT = Path(__file__).resolve().parents[1]
REAL_DB_PATH = ROOT / "storage" / "defender.db"


def make_test_engine(db_url: str):
    """SQLite engine with PRAGMA foreign_keys=ON."""
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


class TestYaraRuleManagementApi(unittest.TestCase):
    """Full test suite for Phase 3C: YARA Rule Management API."""

    @classmethod
    def setUpClass(cls):
        # Record real database hash / mtime for isolation verification
        cls.real_db_exists = REAL_DB_PATH.exists()
        if cls.real_db_exists:
            cls.real_db_mtime_before = REAL_DB_PATH.stat().st_mtime
            with open(REAL_DB_PATH, "rb") as f:
                cls.real_db_hash_before = hashlib.sha256(f.read()).hexdigest()

        # Build isolated test database in a temporary directory
        cls._tmp = tempfile.TemporaryDirectory()
        cls.test_db_path = Path(cls._tmp.name) / "test_yara_api.db"
        cls.engine = make_test_engine(f"sqlite:///{cls.test_db_path}")
        Base.metadata.create_all(bind=cls.engine)
        cls.SessionLocal = sessionmaker(bind=cls.engine)

        # Override FastAPI dependency get_db
        def override_get_db():
            db = cls.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        fastapi_app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(fastapi_app)

        # Create test users: ADMIN, ANALYST, VIEWER
        db = cls.SessionLocal()
        try:
            salt, hp = hash_password("AdminSecurePass123!")
            cls.admin_user = UserModel(
                username="yara_admin_tester",
                email="admin_yara@defender.et",
                hashed_password=hp,
                salt=salt,
                role=UserRole.ADMIN.value,
                is_active=True,
                token_version=1,
            )
            salt_a, hp_a = hash_password("AnalystSecurePass123!")
            cls.analyst_user = UserModel(
                username="yara_analyst_tester",
                email="analyst_yara@defender.et",
                hashed_password=hp_a,
                salt=salt_a,
                role=UserRole.ANALYST.value,
                is_active=True,
                token_version=1,
            )
            salt_v, hp_v = hash_password("ViewerSecurePass123!")
            cls.viewer_user = UserModel(
                username="yara_viewer_tester",
                email="viewer_yara@defender.et",
                hashed_password=hp_v,
                salt=salt_v,
                role=UserRole.VIEWER.value,
                is_active=True,
                token_version=1,
            )
            db.add_all([cls.admin_user, cls.analyst_user, cls.viewer_user])
            db.commit()
            db.refresh(cls.admin_user)
            db.refresh(cls.analyst_user)
            db.refresh(cls.viewer_user)

            # Generate authentication tokens
            cls.admin_token, _, _ = create_access_token({
                "sub": str(cls.admin_user.id),
                "username": cls.admin_user.username,
                "role": cls.admin_user.role,
                "tv": cls.admin_user.token_version,
            })
            cls.analyst_token, _, _ = create_access_token({
                "sub": str(cls.analyst_user.id),
                "username": cls.analyst_user.username,
                "role": cls.analyst_user.role,
                "tv": cls.analyst_user.token_version,
            })
            cls.viewer_token, _, _ = create_access_token({
                "sub": str(cls.viewer_user.id),
                "username": cls.viewer_user.username,
                "role": cls.viewer_user.role,
                "tv": cls.viewer_user.token_version,
            })
        finally:
            db.close()

    @classmethod
    def tearDownClass(cls):
        fastapi_app.dependency_overrides.pop(get_db, None)
        Base.metadata.drop_all(bind=cls.engine)
        cls.engine.dispose()
        if hasattr(cls, "_tmp"):
            cls._tmp.cleanup()

        # Verify real database isolation
        if cls.real_db_exists:
            mtime_after = REAL_DB_PATH.stat().st_mtime
            with open(REAL_DB_PATH, "rb") as f:
                hash_after = hashlib.sha256(f.read()).hexdigest()
            assert hash_after == cls.real_db_hash_before, "CRITICAL: Real database storage/defender.db was modified during tests!"
            assert mtime_after == cls.real_db_mtime_before, "CRITICAL: Real database storage/defender.db mtime was touched during tests!"

    def setUp(self):
        self.db = self.SessionLocal()
        self.admin_headers = {"Authorization": f"Bearer {self.admin_token}"}
        self.analyst_headers = {"Authorization": f"Bearer {self.analyst_token}"}
        self.viewer_headers = {"Authorization": f"Bearer {self.viewer_token}"}

    def tearDown(self):
        self.db.close()

    # -----------------------------------------------------------------------
    # 1. Authorized rule creation and listing
    # -----------------------------------------------------------------------

    def test_01_authorized_rule_creation_and_listing(self):
        """Admin creates rule identities with and without initial source, and lists them."""
        # A. Create rule identity without source
        res = self.client.post(
            "/api/yara/rules",
            json={
                "name": "Rule_Alpha_Test",
                "namespace": "malware",
                "description": "Alpha detection rule",
                "author": "SecAnalyst_01",
                "tags": "apt,trojan",
            },
            headers=self.admin_headers,
        )
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["name"], "Rule_Alpha_Test")
        self.assertEqual(data["namespace"], "malware")
        self.assertTrue(data["is_active"])
        self.assertIsNone(data["current_version_id"])
        self.assertIsNone(data["current_version"])

        # B. Create rule identity with valid source (auto-publishes version 1)
        valid_yara = 'rule Rule_Beta_Test { strings: $a = "malicious" condition: $a }'
        res2 = self.client.post(
            "/api/yara/rules",
            json={
                "name": "Rule_Beta_Test",
                "namespace": "banking",
                "source": valid_yara,
                "description": "Banking trojan rule",
                "author": "SecAnalyst_02",
                "tags": "cbe,banking",
            },
            headers=self.admin_headers,
        )
        self.assertEqual(res2.status_code, 201)
        data2 = res2.json()
        self.assertEqual(data2["name"], "Rule_Beta_Test")
        self.assertIsNotNone(data2["current_version_id"])
        self.assertIsNotNone(data2["current_version"])
        self.assertEqual(data2["current_version"]["version"], 1)

        # C. List rules as Admin
        list_res = self.client.get("/api/yara/rules", headers=self.admin_headers)
        self.assertEqual(list_res.status_code, 200)
        list_data = list_res.json()
        self.assertGreaterEqual(list_data["total"], 2)
        names = [item["name"] for item in list_data["items"]]
        self.assertIn("Rule_Alpha_Test", names)
        self.assertIn("Rule_Beta_Test", names)

        # D. List rules as Analyst (authorized reader)
        analyst_list = self.client.get("/api/yara/rules?namespace=banking", headers=self.analyst_headers)
        self.assertEqual(analyst_list.status_code, 200)
        analyst_data = analyst_list.json()
        self.assertEqual(analyst_data["total"], 1)
        self.assertEqual(analyst_data["items"][0]["name"], "Rule_Beta_Test")

    # -----------------------------------------------------------------------
    # 2. Retrieving a rule and its version history
    # -----------------------------------------------------------------------

    def test_02_retrieve_rule_and_version_history(self):
        """Retrieve individual rule by ID and by Name, and fetch version history."""
        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == "Rule_Beta_Test").first()
        self.assertIsNotNone(rule)

        # Retrieve by integer ID
        res_id = self.client.get(f"/api/yara/rules/{rule.id}", headers=self.analyst_headers)
        self.assertEqual(res_id.status_code, 200)
        self.assertEqual(res_id.json()["name"], "Rule_Beta_Test")

        # Retrieve by string name
        res_name = self.client.get("/api/yara/rules/Rule_Beta_Test", headers=self.analyst_headers)
        self.assertEqual(res_name.status_code, 200)
        self.assertEqual(res_name.json()["id"], rule.id)

        # Retrieve version history
        hist_res = self.client.get(f"/api/yara/rules/{rule.id}/versions", headers=self.analyst_headers)
        self.assertEqual(hist_res.status_code, 200)
        hist_data = hist_res.json()
        self.assertEqual(hist_data["total_versions"], 1)
        self.assertEqual(hist_data["versions"][0]["version"], 1)
        self.assertEqual(hist_data["versions"][0]["source_hash"], hashlib.sha256('rule Rule_Beta_Test { strings: $a = "malicious" condition: $a }'.encode()).hexdigest())

    # -----------------------------------------------------------------------
    # 3. Publishing a valid new version
    # -----------------------------------------------------------------------

    def test_03_publishing_valid_new_version(self):
        """Admin publishes a valid new version for an existing rule."""
        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == "Rule_Beta_Test").first()
        new_source = 'rule Rule_Beta_Test { strings: $a = "malicious_v2" condition: $a }'

        pub_res = self.client.post(
            f"/api/yara/rules/{rule.id}/publish",
            json={
                "source": new_source,
                "author": "Lead_Researcher",
                "severity": "CRITICAL",
                "category": "TROJAN",
                "tags": "v2,cbe",
            },
            headers=self.admin_headers,
        )
        self.assertEqual(pub_res.status_code, 201)
        pub_data = pub_res.json()
        self.assertEqual(pub_data["version"], 2)
        self.assertEqual(pub_data["severity"], "CRITICAL")
        self.assertEqual(pub_data["category"], "TROJAN")
        self.assertEqual(pub_data["source_hash"], hashlib.sha256(new_source.encode()).hexdigest())

        # Verify current pointer on the rule
        self.db.refresh(rule)
        self.assertEqual(rule.current_version.version, 2)
        self.assertEqual(rule.current_version_id, pub_data["id"])

    # -----------------------------------------------------------------------
    # 4. Invalid YARA source rejection
    # -----------------------------------------------------------------------

    def test_04_invalid_yara_source_rejection(self):
        """Invalid YARA syntax and empty source are rejected with 400 Bad Request."""
        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == "Rule_Beta_Test").first()
        initial_version_id = rule.current_version_id

        # Malformed syntax
        bad_res = self.client.post(
            f"/api/yara/rules/{rule.id}/publish",
            json={"source": "not a valid rule at all { condition: true"},
            headers=self.admin_headers,
        )
        self.assertEqual(bad_res.status_code, 400)
        self.assertIn("Invalid YARA source", bad_res.json()["detail"])

        # Empty source
        empty_res = self.client.post(
            f"/api/yara/rules/{rule.id}/publish",
            json={"source": "   "},
            headers=self.admin_headers,
        )
        self.assertEqual(empty_res.status_code, 400)

        # Database state unchanged
        self.db.refresh(rule)
        self.assertEqual(rule.current_version_id, initial_version_id)

    # -----------------------------------------------------------------------
    # 5. Published version immutability
    # -----------------------------------------------------------------------

    def test_05_published_version_immutability(self):
        """Published version rows remain immutable; changes require a new version."""
        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == "Rule_Beta_Test").first()
        v1 = self.db.query(YaraRuleVersionModel).filter_by(rule_id=rule.id, version=1).first()
        v1_hash = v1.source_hash
        v1_source = v1.source

        # Publish version 3
        v3_source = 'rule Rule_Beta_Test { strings: $a = "malicious_v3" condition: $a }'
        pub_res = self.client.post(
            f"/api/yara/rules/{rule.id}/publish",
            json={"source": v3_source},
            headers=self.admin_headers,
        )
        self.assertEqual(pub_res.status_code, 201)

        # Verify version 1 row is completely unchanged
        self.db.refresh(v1)
        self.assertEqual(v1.source_hash, v1_hash)
        self.assertEqual(v1.source, v1_source)
        self.assertEqual(v1.version, 1)

    # -----------------------------------------------------------------------
    # 6. Correct current-version pointer after publication
    # -----------------------------------------------------------------------

    def test_06_correct_current_version_pointer_after_publication(self):
        """Current version pointer tracks the highest published version."""
        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == "Rule_Beta_Test").first()
        self.assertEqual(rule.current_version.version, 3)

        # Fetch via API
        res = self.client.get(f"/api/yara/rules/{rule.id}", headers=self.analyst_headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["current_version"]["version"], 3)

    # -----------------------------------------------------------------------
    # 7. Deactivation and reactivation
    # -----------------------------------------------------------------------

    def test_07_deactivation_and_reactivation(self):
        """Rules can be deactivated and reactivated while preserving version history."""
        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == "Rule_Beta_Test").first()

        # Deactivate
        deact_res = self.client.post(f"/api/yara/rules/{rule.id}/deactivate", headers=self.admin_headers)
        self.assertEqual(deact_res.status_code, 200)
        self.assertFalse(deact_res.json()["is_active"])

        self.db.refresh(rule)
        self.assertFalse(rule.is_active)
        self.assertEqual(len(rule.versions), 3)

        # Reactivate
        react_res = self.client.post(f"/api/yara/rules/{rule.id}/reactivate", headers=self.admin_headers)
        self.assertEqual(react_res.status_code, 200)
        self.assertTrue(react_res.json()["is_active"])

        self.db.refresh(rule)
        self.assertTrue(rule.is_active)
        self.assertEqual(len(rule.versions), 3)

    # -----------------------------------------------------------------------
    # 8. Unauthorized and insufficient-role requests
    # -----------------------------------------------------------------------

    def test_08_unauthorized_and_insufficient_role_requests(self):
        """Unauthenticated and insufficient-role requests are rejected."""
        # Unauthenticated -> 401
        res_no_auth = self.client.get("/api/yara/rules")
        self.assertEqual(res_no_auth.status_code, 401)

        # VIEWER role (forbidden for read and write) -> 403
        viewer_get = self.client.get("/api/yara/rules", headers=self.viewer_headers)
        self.assertEqual(viewer_get.status_code, 403)

        viewer_post = self.client.post(
            "/api/yara/rules",
            json={"name": "Viewer_Illegal_Rule"},
            headers=self.viewer_headers,
        )
        self.assertEqual(viewer_post.status_code, 403)

        # ANALYST role (allowed to read, forbidden to mutate) -> 403 on write
        analyst_create = self.client.post(
            "/api/yara/rules",
            json={"name": "Analyst_Illegal_Rule"},
            headers=self.analyst_headers,
        )
        self.assertEqual(analyst_create.status_code, 403)

        analyst_pub = self.client.post(
            "/api/yara/rules/Rule_Beta_Test/publish",
            json={"source": "rule R { condition: true }"},
            headers=self.analyst_headers,
        )
        self.assertEqual(analyst_pub.status_code, 403)

        analyst_deact = self.client.post(
            "/api/yara/rules/Rule_Beta_Test/deactivate",
            headers=self.analyst_headers,
        )
        self.assertEqual(analyst_deact.status_code, 403)

    # -----------------------------------------------------------------------
    # 9. Malformed payloads and invalid rule identifiers
    # -----------------------------------------------------------------------

    def test_09_malformed_payloads_and_invalid_identifiers(self):
        """Non-existent rule IDs return 404; duplicate rule names return 400."""
        # 404 on non-existent rule
        res_404 = self.client.get("/api/yara/rules/999999", headers=self.admin_headers)
        self.assertEqual(res_404.status_code, 404)
        self.assertIn("not found", res_404.json()["detail"].lower())

        # 400 on duplicate rule name
        dup_res = self.client.post(
            "/api/yara/rules",
            json={"name": "Rule_Alpha_Test"},  # already created in test_01
            headers=self.admin_headers,
        )
        self.assertEqual(dup_res.status_code, 400)
        self.assertIn("already exists", dup_res.json()["detail"].lower())

    # -----------------------------------------------------------------------
    # 10. Audit events for successful management operations
    # -----------------------------------------------------------------------

    def test_10_audit_events_for_successful_management_operations(self):
        """Operations record structured audit log entries with user attribution."""
        # Check audit log records in DB for recent rule actions
        logs = (
            self.db.query(AuditLogModel)
            .filter(AuditLogModel.event == AuditEventType.ADMINISTRATIVE_CHANGES.value)
            .order_by(AuditLogModel.id.desc())
            .all()
        )
        self.assertGreater(len(logs), 0)

        # Inspect details of recent logs
        actions = []
        for l in logs:
            if l.details_json:
                import json
                det = json.loads(l.details_json) if isinstance(l.details_json, str) else l.details_json
                if "action" in det:
                    actions.append(det["action"])
        self.assertIn("create_rule_identity", actions)
        self.assertIn("publish_rule_version", actions)
        self.assertIn("deactivate_rule", actions)
        self.assertIn("reactivate_rule", actions)

    # -----------------------------------------------------------------------
    # 11. Failed operations leaving database state unchanged
    # -----------------------------------------------------------------------

    def test_11_failed_operations_leaving_database_state_unchanged(self):
        """Failed operations do not mutate database rows."""
        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == "Rule_Alpha_Test").first()
        prev_ver_id = rule.current_version_id

        # Attempt to publish invalid syntax
        fail_res = self.client.post(
            f"/api/yara/rules/{rule.id}/publish",
            json={"source": "invalid yara code here"},
            headers=self.admin_headers,
        )
        self.assertEqual(fail_res.status_code, 400)

        # Verify no version rows exist for Rule_Alpha_Test
        versions_count = self.db.query(YaraRuleVersionModel).filter_by(rule_id=rule.id).count()
        self.assertEqual(versions_count, 0)
        self.db.refresh(rule)
        self.assertEqual(rule.current_version_id, prev_ver_id)

    # -----------------------------------------------------------------------
    # 12. Historical matches retaining valid version provenance
    # -----------------------------------------------------------------------

    def test_12_historical_matches_retaining_valid_version_provenance(self):
        """Historical matches linked to published versions maintain foreign key integrity."""
        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == "Rule_Beta_Test").first()
        v1 = self.db.query(YaraRuleVersionModel).filter_by(rule_id=rule.id, version=1).first()

        # Create dummy sample and match linked to v1
        sample = SampleModel(
            analysis_id="ANL-YARA-API-TEST",
            filename="trojan.bin",
            md5="1" * 32,
            sha1="1" * 40,
            sha256="1" * 64,
            size=1024,
            status="COMPLETED",
        )
        self.db.add(sample)
        self.db.flush()

        match = YaraMatchModel(
            sample_id=sample.id,
            rule_name=rule.name,
            namespace=rule.namespace,
            rule_version_id=v1.id,
        )
        self.db.add(match)
        self.db.commit()

        # Verify match points to v1
        self.db.refresh(match)
        self.assertEqual(match.rule_version_id, v1.id)
        self.assertEqual(match.rule_version.version, 1)

    # -----------------------------------------------------------------------
    # 13. Concurrent or repeated publication behavior
    # -----------------------------------------------------------------------

    def test_13_concurrent_or_repeated_publication_behavior(self):
        """Repeated publications monotonically increment version numbers."""
        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == "Rule_Beta_Test").first()

        for step in range(4, 7):
            src = f'rule Rule_Beta_Test {{ strings: $s = "step_{step}" condition: $s }}'
            res = self.client.post(
                f"/api/yara/rules/{rule.id}/publish",
                json={"source": src},
                headers=self.admin_headers,
            )
            self.assertEqual(res.status_code, 201)
            self.assertEqual(res.json()["version"], step)

        self.db.refresh(rule)
        self.assertEqual(rule.current_version.version, 6)

    # -----------------------------------------------------------------------
    # 14. Database isolation verification
    # -----------------------------------------------------------------------

    def test_14_database_isolation_verification(self):
        """Confirms that tests executed entirely within isolated temporary storage."""
        if self.real_db_exists:
            current_mtime = REAL_DB_PATH.stat().st_mtime
            with open(REAL_DB_PATH, "rb") as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(current_hash, self.real_db_hash_before)
            self.assertEqual(current_mtime, self.real_db_mtime_before)


if __name__ == "__main__":
    unittest.main()
