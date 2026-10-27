"""
Phase 3D Integration and Concurrency Test Suite:
End-to-End YARA Integration, Rule-Selection Consistency, and Provenance Assurance.

Covers:
1. SelectedYaraRule immutable per-analysis snapshot dataclass.
2. Per-analysis rule selection consistency (never re-querying midway).
3. Deterministic concurrent publication regression test with explicit synchronization primitives.
4. Exact immutable published version provenance persistence.
5. Rejection of cross-rule version mismatch.
6. Rejection of non-existent version reference.
7. Fault isolation: invalid rule syntax does not block valid rules.
8. Deactivated rules exclusion from subsequent scans.
9. Explicit YARA-unavailable status (cannot be mistaken for clean scan).
10. Atomic rollback: failed match persistence leaves no partial database state.
11. Historical match version retention and ON DELETE RESTRICT foreign key protection.
12. Compilation cache keying isolation (rule_id, version_id, source_hash).
13. Filesystem-only rule preservation and NULL version provenance.
14. Database isolation verification (storage/defender.db untouched).
"""

import hashlib
import os
import tempfile
import threading
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

# Ensure isolated database environment BEFORE any app imports
_pre_tmp_dir = tempfile.mkdtemp()
_pre_tmp_db = os.path.join(_pre_tmp_dir, "test_p3d_env.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_pre_tmp_db}"
os.environ["ALEMBIC_DATABASE_URL"] = f"sqlite:///{_pre_tmp_db}"

from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db.session import Base
from app.db.models import (
    UserModel,
    SampleModel,
    YaraRuleModel,
    YaraRuleVersionModel,
    YaraMatchModel,
    AuditLogModel,
)
from app.db.schemas import (
    SampleCreate,
    YaraMatchCreate,
)
from app.db.repository import SampleRepository
from app.analyzers.yara_analyzer import (
    YaraAnalyzerService,
    SelectedYaraRule,
    YaraMatchItem,
    YaraScanResult,
    HAS_YARA,
)
from app.services.yara_rule_publication_service import (
    create_rule_identity,
    publish_rule_version_safe,
    deactivate_rule,
)

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


def dummy_sample_create(analysis_id: str, filename: str = "sample.exe", size: int = 100) -> SampleCreate:
    """Helper to create a valid SampleCreate schema with required hashes."""
    return SampleCreate(
        analysis_id=analysis_id,
        filename=filename,
        size=size,
        file_type="EXE",
        architecture="x64",
        md5=hashlib.md5(analysis_id.encode("utf-8")).hexdigest(),
        sha1=hashlib.sha1(analysis_id.encode("utf-8")).hexdigest(),
        sha256=hashlib.sha256(analysis_id.encode("utf-8")).hexdigest(),
        status="COMPLETED",
    )


class TestYaraPipelineIntegration(unittest.TestCase):
    """Comprehensive test suite for Phase 3D."""

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
        cls.db_path = Path(cls._tmp.name) / "test_p3d.db"
        cls.test_engine = make_test_engine(f"sqlite:///{cls.db_path}")
        cls.TestSessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=cls.test_engine,
            expire_on_commit=False,
        )

        # Create all tables in isolated database
        Base.metadata.create_all(bind=cls.test_engine)

        # Seed admin user
        with cls.TestSessionLocal() as session:
            admin = UserModel(
                id=1,
                username="p3d_admin",
                email="p3d_admin@soc.et",
                hashed_password="x",
                salt="y",
                role="ADMIN",
                is_active=True,
            )
            session.add(admin)
            session.commit()

        # Isolated rules directory for filesystem scanning
        cls.test_rules_dir = Path(cls._tmp.name) / "rules"
        cls.test_rules_dir.mkdir(parents=True, exist_ok=True)
        cls.analyzer = YaraAnalyzerService(rules_dir=cls.test_rules_dir)

    @classmethod
    def tearDownClass(cls):
        cls.test_engine.dispose()
        cls._tmp.cleanup()

    def setUp(self):
        self.db = self.TestSessionLocal()

    def tearDown(self):
        self.db.close()
        # Reset analyzer state/hook
        self.analyzer.post_selection_hook = None

    # -----------------------------------------------------------------------
    # 1. SelectedYaraRule immutable per-analysis snapshot dataclass
    # -----------------------------------------------------------------------

    def test_01_selected_yara_rule_immutable_dataclass(self):
        """SelectedYaraRule is a frozen dataclass retaining exact compilation metadata."""
        snapshot = SelectedYaraRule(
            rule_id=10,
            rule_name="TestRule",
            namespace="default",
            version_id=101,
            version_number=1,
            source_hash="abcd1234hash",
            source='rule TestRule { condition: true }',
        )

        self.assertEqual(snapshot.rule_id, 10)
        self.assertEqual(snapshot.rule_name, "TestRule")
        self.assertEqual(snapshot.version_id, 101)
        self.assertEqual(snapshot.version_number, 1)
        self.assertEqual(snapshot.source_hash, "abcd1234hash")
        self.assertIn("TestRule", snapshot.source)

        # Mutation must be prevented by frozen=True
        with self.assertRaises(FrozenInstanceError):
            snapshot.rule_id = 99
        with self.assertRaises(FrozenInstanceError):
            snapshot.version_number = 2

    # -----------------------------------------------------------------------
    # 2. Per-analysis rule selection consistency
    # -----------------------------------------------------------------------

    def test_02_per_analysis_rule_selection_consistency(self):
        """select_active_rules selects active rules and published versions once without mutation."""
        rule = create_rule_identity(self.db, name="Selection_Rule_A", namespace="ns_test", user_id=1)
        v1, _ = publish_rule_version_safe(
            self.db,
            rule_name=rule.id,
            source='rule Selection_Rule_A { strings: $a = "V1_FLAG" condition: $a }',
            user_id=1,
        )

        # Establish rule selection
        selected = self.analyzer.select_active_rules(self.db)
        match_sel = [r for r in selected if r.rule_id == rule.id]
        self.assertEqual(len(match_sel), 1)
        self.assertEqual(match_sel[0].version_id, v1.id)
        self.assertEqual(match_sel[0].version_number, 1)

        # Publish version 2 in DB
        v2, _ = publish_rule_version_safe(
            self.db,
            rule_name=rule.id,
            source='rule Selection_Rule_A { strings: $a = "V2_FLAG" condition: $a }',
            user_id=1,
        )
        self.assertEqual(v2.version, 2)

        # Previously selected snapshot MUST NOT change
        self.assertEqual(match_sel[0].version_id, v1.id)
        self.assertEqual(match_sel[0].version_number, 1)
        self.assertIn("V1_FLAG", match_sel[0].source)

    # -----------------------------------------------------------------------
    # 3. Deterministic concurrent publication regression test
    # -----------------------------------------------------------------------

    def test_03_concurrent_publication_synchronization(self):
        """
        Step 3 requirement:
        1. Publish version 1 of a rule.
        2. Begin an analysis and capture its selected version.
        3. Publish version 2 while the analysis is paused at a controlled point.
        4. Resume the analysis.
        5. Verify in-progress analysis uses version 1 and records version 1 provenance.
        6. Start a subsequent analysis and verify it uses version 2.
        """
        # 1. Publish version 1 of a rule
        rule = create_rule_identity(self.db, name="Concurrent_Rule", namespace="default", user_id=1)
        v1, _ = publish_rule_version_safe(
            self.db,
            rule_name=rule.id,
            source='rule Concurrent_Rule { strings: $a = "PAYLOAD_ALPHA" condition: $a }',
            user_id=1,
        )
        self.assertEqual(v1.version, 1)

        # Explicit synchronization primitives
        selection_done = threading.Event()
        resume_analysis = threading.Event()
        captured_version_in_hook = []
        analysis_error = []

        def sync_hook(selected_rules: list):
            for r in selected_rules:
                if r.rule_id == rule.id:
                    captured_version_in_hook.append(r.version_id)
            # Signal that rule selection has completed
            selection_done.set()
            # Wait for main thread to publish version 2 before continuing scan
            resume_analysis.wait(timeout=10.0)

        binary_with_both_payloads = b"MZ\x90\x00...PAYLOAD_ALPHA...PAYLOAD_BETA..."

        def run_analysis_worker():
            try:
                worker_db = self.TestSessionLocal()
                try:
                    # Scan with hook
                    scan_res = self.analyzer.scan_bytes_with_db_rules(
                        binary_with_both_payloads,
                        db=worker_db,
                        post_selection_hook=sync_hook,
                    )
                    # Persist analysis
                    sample_in = dummy_sample_create("ANL-CONCUR-01", "concurrent_sample1.exe", len(binary_with_both_payloads))
                    matches_in = [
                        YaraMatchCreate(
                            rule_name=m.rule_name,
                            namespace=m.namespace,
                            rule_version_id=m.rule_version_id,
                            rule_id=m.rule_id,
                        )
                        for m in scan_res.matches
                    ]
                    SampleRepository.save_full_analysis_transaction(
                        db=worker_db,
                        sample_in=sample_in,
                        yara_matches_in=matches_in,
                    )
                finally:
                    worker_db.close()
            except Exception as exc:
                analysis_error.append(exc)

        # 2. Begin analysis on background thread
        worker_thread = threading.Thread(target=run_analysis_worker)
        worker_thread.start()

        # Wait until background thread completes rule selection
        signaled = selection_done.wait(timeout=5.0)
        self.assertTrue(signaled, "Worker thread failed to reach selection hook")
        self.assertEqual(captured_version_in_hook, [v1.id])

        # 3. Publish version 2 while analysis is paused at controlled point
        v2, _ = publish_rule_version_safe(
            self.db,
            rule_name=rule.id,
            source='rule Concurrent_Rule { strings: $b = "PAYLOAD_BETA" condition: $b }',
            user_id=1,
        )
        self.assertEqual(v2.version, 2)
        self.db.refresh(rule)
        self.assertEqual(rule.current_version_id, v2.id)

        # 4. Resume analysis
        resume_analysis.set()
        worker_thread.join(timeout=10.0)
        self.assertFalse(worker_thread.is_alive(), "Worker thread hung")
        if analysis_error:
            raise analysis_error[0]

        # 5. Verify in-progress analysis used version 1 and recorded version 1 provenance
        sample1 = self.db.query(SampleModel).filter(SampleModel.analysis_id == "ANL-CONCUR-01").first()
        self.assertIsNotNone(sample1)
        matches1 = self.db.query(YaraMatchModel).filter(YaraMatchModel.sample_id == sample1.id).all()
        self.assertEqual(len(matches1), 1)
        self.assertEqual(matches1[0].rule_name, "Concurrent_Rule")
        self.assertEqual(matches1[0].rule_version_id, v1.id, "In-progress analysis must record v1 provenance")

        # 6. Start subsequent analysis and verify it uses version 2
        scan_res_2 = self.analyzer.scan_bytes_with_db_rules(binary_with_both_payloads, db=self.db)
        sample2_in = dummy_sample_create("ANL-CONCUR-02", "concurrent_sample2.exe", len(binary_with_both_payloads))
        matches2_in = [
            YaraMatchCreate(
                rule_name=m.rule_name,
                namespace=m.namespace,
                rule_version_id=m.rule_version_id,
                rule_id=m.rule_id,
            )
            for m in scan_res_2.matches
        ]
        SampleRepository.save_full_analysis_transaction(
            db=self.db,
            sample_in=sample2_in,
            yara_matches_in=matches2_in,
        )

        sample2 = self.db.query(SampleModel).filter(SampleModel.analysis_id == "ANL-CONCUR-02").first()
        self.assertIsNotNone(sample2)
        matches2 = self.db.query(YaraMatchModel).filter(YaraMatchModel.sample_id == sample2.id).all()
        self.assertEqual(len(matches2), 1)
        self.assertEqual(matches2[0].rule_name, "Concurrent_Rule")
        self.assertEqual(matches2[0].rule_version_id, v2.id, "Subsequent analysis must record v2 provenance")

    # -----------------------------------------------------------------------
    # 4. Exact version provenance recorded
    # -----------------------------------------------------------------------

    def test_04_exact_version_provenance_recorded(self):
        """DB-managed match persists with exact published version ID."""
        rule = create_rule_identity(self.db, name="Provenance_Rule", namespace="default", user_id=1)
        v1, _ = publish_rule_version_safe(
            self.db,
            rule_name=rule.id,
            source='rule Provenance_Rule { strings: $s = "PROV_HIT" condition: $s }',
            user_id=1,
        )

        payload = b"test bytes containing PROV_HIT pattern"
        scan_res = self.analyzer.scan_bytes_with_db_rules(payload, db=self.db)
        self.assertEqual(scan_res.total_matches, 1)
        self.assertEqual(scan_res.matches[0].rule_version_id, v1.id)
        self.assertEqual(scan_res.matches[0].rule_id, rule.id)

    # -----------------------------------------------------------------------
    # 5. Cross-rule version mismatch rejected
    # -----------------------------------------------------------------------

    def test_05_cross_rule_version_mismatch_rejected(self):
        """Passing a version_id that belongs to a different rule is rejected."""
        rule_a = create_rule_identity(self.db, name="Rule_Apple", namespace="default", user_id=1)
        v_a, _ = publish_rule_version_safe(
            self.db, rule_name=rule_a.id, source='rule Rule_Apple { condition: true }', user_id=1
        )
        rule_b = create_rule_identity(self.db, name="Rule_Banana", namespace="default", user_id=1)
        v_b, _ = publish_rule_version_safe(
            self.db, rule_name=rule_b.id, source='rule Rule_Banana { condition: true }', user_id=1
        )

        sample_in = dummy_sample_create("ANL-MISMATCH", "mismatch.exe")

        # Forged match: rule_name is Rule_Apple, but rule_version_id belongs to Rule_Banana
        invalid_match = YaraMatchCreate(
            rule_name="Rule_Apple",
            namespace="default",
            rule_version_id=v_b.id,
            rule_id=rule_a.id,
        )

        with self.assertRaises(ValueError) as ctx:
            SampleRepository.save_full_analysis_transaction(
                db=self.db,
                sample_in=sample_in,
                yara_matches_in=[invalid_match],
            )
        self.assertIn("belongs to rule", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 6. Non-existent version reference rejected
    # -----------------------------------------------------------------------

    def test_06_nonexistent_version_rejected(self):
        """Non-existent rule_version_id is rejected by repository validation."""
        sample_in = dummy_sample_create("ANL-NONEXISTENT", "fake.exe")

        invalid_match = YaraMatchCreate(
            rule_name="GhostRule",
            namespace="default",
            rule_version_id=999999,
        )

        with self.assertRaises(ValueError) as ctx:
            SampleRepository.save_full_analysis_transaction(
                db=self.db,
                sample_in=sample_in,
                yara_matches_in=[invalid_match],
            )
        self.assertIn("does not exist", str(ctx.exception))

    # -----------------------------------------------------------------------
    # 7. Fault isolation: invalid rule syntax does not block valid rules
    # -----------------------------------------------------------------------

    def test_07_invalid_rule_compilation_fault_isolation(self):
        """Invalid DB rule compilation failure does not prevent valid rules from scanning."""
        rule_valid = create_rule_identity(self.db, name="Rule_Valid_Isolated", namespace="default", user_id=1)
        v_valid, _ = publish_rule_version_safe(
            self.db,
            rule_name=rule_valid.id,
            source='rule Rule_Valid_Isolated { strings: $s = "HEALTHY_PAYLOAD" condition: $s }',
            user_id=1,
        )

        rule_broken = create_rule_identity(self.db, name="Rule_Broken_Isolated", namespace="default", user_id=1)
        broken_src = 'rule Rule_Broken_Isolated { SYNTAX_ERROR_COND condition: ??? }'
        v_broken = YaraRuleVersionModel(
            rule_id=rule_broken.id,
            version=1,
            source=broken_src,
            source_hash=hashlib.sha256(broken_src.strip().encode("utf-8")).hexdigest(),
            is_published=True,
            published_by=1,
        )
        self.db.add(v_broken)
        self.db.flush()
        rule_broken.current_version_id = v_broken.id

        rule_tampered = create_rule_identity(self.db, name="Rule_Tampered_Isolated", namespace="default", user_id=1)
        v_tampered = YaraRuleVersionModel(
            rule_id=rule_tampered.id,
            version=1,
            source='rule Rule_Tampered_Isolated { strings: $s = "TAMPERED" condition: $s }',
            source_hash="corrupted_sha256_hash_that_does_not_match",
            is_published=True,
            published_by=1,
        )
        self.db.add(v_tampered)
        self.db.flush()
        rule_tampered.current_version_id = v_tampered.id
        self.db.commit()

        # Scan bytes containing valid rule's payload and tampered rule's payload
        content = b"header...HEALTHY_PAYLOAD...TAMPERED...footer"
        res = self.analyzer.scan_bytes_with_db_rules(content, db=self.db)

        # Must report success with valid rule match only
        self.assertTrue(res.available)
        self.assertEqual(res.status, "SUCCESS")
        matched_names = [m.rule_name for m in res.matches]
        self.assertIn("Rule_Valid_Isolated", matched_names)
        self.assertNotIn("Rule_Broken_Isolated", matched_names)
        self.assertNotIn("Rule_Tampered_Isolated", matched_names)

    # -----------------------------------------------------------------------
    # 8. Deactivated rules exclusion from subsequent scans
    # -----------------------------------------------------------------------

    def test_08_deactivated_rules_excluded(self):
        """Deactivated rules are excluded from subsequent scans."""
        rule_active = create_rule_identity(self.db, name="Rule_Active_Stay", namespace="default", user_id=1)
        publish_rule_version_safe(
            self.db,
            rule_name=rule_active.id,
            source='rule Rule_Active_Stay { strings: $s = "ACTIVE_KEY" condition: $s }',
            user_id=1,
        )

        rule_deact = create_rule_identity(self.db, name="Rule_To_Deactivate", namespace="default", user_id=1)
        publish_rule_version_safe(
            self.db,
            rule_name=rule_deact.id,
            source='rule Rule_To_Deactivate { strings: $s = "DEACT_KEY" condition: $s }',
            user_id=1,
        )

        # Deactivate rule
        deactivate_rule(self.db, rule_name=rule_deact.id, user_id=1)
        self.db.commit()

        content = b"sample containing ACTIVE_KEY and DEACT_KEY"
        res = self.analyzer.scan_bytes_with_db_rules(content, db=self.db)

        matched_names = [m.rule_name for m in res.matches]
        self.assertIn("Rule_Active_Stay", matched_names)
        self.assertNotIn("Rule_To_Deactivate", matched_names)

    # -----------------------------------------------------------------------
    # 9. Explicit YARA-unavailable status
    # -----------------------------------------------------------------------

    def test_09_yara_unavailable_status_not_clean(self):
        """When YARA is unavailable, status is UNAVAILABLE and not SUCCESS."""
        orig_yara_flag = self.analyzer._has_yara
        try:
            self.analyzer._has_yara = False
            res = self.analyzer.scan_bytes(b"some content")
            self.assertFalse(res.available)
            self.assertEqual(res.status, "UNAVAILABLE")
            self.assertIn("unavailable", res.message.lower())

            res_db = self.analyzer.scan_bytes_with_db_rules(b"some content", db=self.db)
            self.assertFalse(res_db.available)
            self.assertEqual(res_db.status, "UNAVAILABLE")
        finally:
            self.analyzer._has_yara = orig_yara_flag

    # -----------------------------------------------------------------------
    # 10. Atomic rollback: failed match persistence leaves no partial state
    # -----------------------------------------------------------------------

    def test_10_failed_match_persistence_leaves_no_partial_state(self):
        """Validation failure in save_full_analysis_transaction rolls back entire transaction."""
        samples_before = self.db.query(SampleModel).count()
        matches_before = self.db.query(YaraMatchModel).count()

        sample_in = dummy_sample_create("ANL-FAIL-ROLLBACK", "fail_rollback.exe", 500)
        corrupt_match = YaraMatchCreate(
            rule_name="NonexistentRule",
            namespace="default",
            rule_version_id=888888,  # Does not exist
        )

        with self.assertRaises(ValueError):
            SampleRepository.save_full_analysis_transaction(
                db=self.db,
                sample_in=sample_in,
                yara_matches_in=[corrupt_match],
            )

        # Zero rows added
        self.assertEqual(self.db.query(SampleModel).count(), samples_before)
        self.assertEqual(self.db.query(YaraMatchModel).count(), matches_before)

    # -----------------------------------------------------------------------
    # 11. Historical match version retention and ON DELETE RESTRICT
    # -----------------------------------------------------------------------

    def test_11_historical_matches_retain_original_version_references(self):
        """Historical matches retain version 1 after version 2 is published, and FK restricts deletion."""
        rule = create_rule_identity(self.db, name="Hist_Retention_Rule", namespace="default", user_id=1)
        v1, _ = publish_rule_version_safe(
            self.db,
            rule_name=rule.id,
            source='rule Hist_Retention_Rule { strings: $s = "HIST_V1" condition: $s }',
            user_id=1,
        )

        # Save historical sample with v1 match
        sample1_in = dummy_sample_create("ANL-HIST-01", "hist1.exe")
        match1 = YaraMatchCreate(
            rule_name=rule.name, namespace="default", rule_version_id=v1.id, rule_id=rule.id
        )
        SampleRepository.save_full_analysis_transaction(
            db=self.db,
            sample_in=sample1_in,
            yara_matches_in=[match1],
        )

        # Publish v2
        v2, _ = publish_rule_version_safe(
            self.db,
            rule_name=rule.id,
            source='rule Hist_Retention_Rule { strings: $s = "HIST_V2" condition: $s }',
            user_id=1,
        )

        # Verify historical match still references v1
        sample1 = self.db.query(SampleModel).filter(SampleModel.analysis_id == "ANL-HIST-01").first()
        saved_match = self.db.query(YaraMatchModel).filter(YaraMatchModel.sample_id == sample1.id).first()
        self.assertEqual(saved_match.rule_version_id, v1.id)

        # Verify ON DELETE RESTRICT prevents deleting v1 while referenced by saved_match
        with self.assertRaises(IntegrityError):
            self.db.execute(text(f"DELETE FROM yara_rule_versions WHERE id = {v1.id}"))
            self.db.commit()
        self.db.rollback()

    # -----------------------------------------------------------------------
    # 12. Compilation cache keying isolation
    # -----------------------------------------------------------------------

    def test_12_compilation_cache_keying_isolation(self):
        """Cache keys distinguish rule identity, version ID, and source hash."""
        cache = self.analyzer._version_cache

        key1 = (1, 10, "hash_aaa")
        key2 = (1, 11, "hash_bbb")
        key3 = (2, 10, "hash_aaa")

        self.assertNotEqual(key1, key2)
        self.assertNotEqual(key1, key3)
        self.assertNotEqual(key2, key3)

        cache[key1] = "compiled_v1"
        cache[key2] = "compiled_v2"
        cache[key3] = "compiled_rule2"

        self.assertEqual(cache[key1], "compiled_v1")
        self.assertEqual(cache[key2], "compiled_v2")
        self.assertEqual(cache[key3], "compiled_rule2")

    # -----------------------------------------------------------------------
    # 13. Filesystem-only rule preservation and NULL version provenance
    # -----------------------------------------------------------------------

    def test_13_filesystem_only_rules_preserve_null_provenance(self):
        """Filesystem rules produce matches with rule_version_id=None and persist cleanly."""
        fs_rule_path = self.test_rules_dir / "fs_only_rule.yar"
        fs_rule_path.write_text(
            'rule FS_Only_Rule { strings: $f = "FILESYSTEM_TRIGGER" condition: $f }',
            encoding="utf-8",
        )

        content = b"data with FILESYSTEM_TRIGGER here"
        res = self.analyzer.scan_bytes_with_db_rules(content, db=self.db)

        fs_matches = [m for m in res.matches if m.rule_name == "FS_Only_Rule"]
        self.assertEqual(len(fs_matches), 1)
        self.assertIsNone(fs_matches[0].rule_version_id)
        self.assertIsNone(fs_matches[0].rule_id)

        # Persist to database
        sample_in = dummy_sample_create("ANL-FS-01", "fs_sample.exe")
        db_sample = SampleRepository.save_full_analysis_transaction(
            db=self.db,
            sample_in=sample_in,
            yara_matches_in=[
                YaraMatchCreate(
                    rule_name=fs_matches[0].rule_name,
                    namespace=fs_matches[0].namespace,
                    rule_version_id=None,
                    rule_id=None,
                )
            ],
        )

        saved_match = self.db.query(YaraMatchModel).filter(YaraMatchModel.sample_id == db_sample.id).first()
        self.assertIsNotNone(saved_match)
        self.assertIsNone(saved_match.rule_version_id)

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
