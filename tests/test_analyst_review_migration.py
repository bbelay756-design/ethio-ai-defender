"""
Focused tests for ML-13B: Analyst Reviews Table Migration & Schema Consistency.

Verifies:
1. Model metadata declaration: exactly 4 unique indexes on analyst_reviews, no duplicates.
2. Migration upgrade from scratch: creates table with columns, constraints, and indexes identical to model metadata.
3. Migration downgrade to a1b2c3d4e5f6: cleanly drops table without errors.
4. Interoperability: if create_all() runs before migration upgrade, no duplicate index OperationalError occurs.
5. Idempotent initialization: repeated init_db() or create_all() calls do not fail.
6. Development database copy verification: upgrade on copy of storage/defender.db succeeds with all existing data preserved.
"""

import os
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from alembic import command
from alembic.config import Config

from app.db.session import Base, init_db
from app.db.models import AnalystReviewModel, SampleModel

ROOT = Path(__file__).resolve().parents[1]
REAL_DB_PATH = ROOT / "storage" / "defender.db"


def run_alembic_cmd(db_path: Path, target: str = "head"):
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    original = os.environ.get("ALEMBIC_DATABASE_URL")
    os.environ["ALEMBIC_DATABASE_URL"] = f"sqlite:///{db_path}"
    try:
        if target == "downgrade":
            command.downgrade(cfg, "a1b2c3d4e5f6")
        else:
            command.upgrade(cfg, target)
    finally:
        if original is None:
            os.environ.pop("ALEMBIC_DATABASE_URL", None)
        else:
            os.environ["ALEMBIC_DATABASE_URL"] = original


class TestAnalystReviewSchemaAndMigration(unittest.TestCase):

    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)
        self.db_path = self.tmp_path / "test_migration.db"

    def tearDown(self):
        self._tmp_dir.cleanup()

    def test_model_metadata_declares_unique_indexes_without_duplicates(self):
        """Verify model metadata declares exactly 4 distinct indexes without duplicates."""
        table = AnalystReviewModel.__table__
        index_names = [idx.name for idx in table.indexes]
        self.assertEqual(len(index_names), len(set(index_names)), "Duplicate index names found in metadata")

        expected_indexes = {
            "ix_analyst_reviews_sample_id": ["sample_id"],
            "ix_analyst_reviews_analysis_id": ["analysis_id"],
            "ix_analyst_reviews_user_id": ["user_id"],
            "ix_analyst_reviews_created_at": ["created_at"],
        }
        actual_indexes = {idx.name: [c.name for c in idx.columns] for idx in table.indexes}
        self.assertEqual(actual_indexes, expected_indexes)

    def test_migration_upgrade_produces_schema_matching_model_metadata(self):
        """A fresh database upgraded via Alembic head must produce identical schema and indexes."""
        run_alembic_cmd(self.db_path, "head")

        engine = create_engine(f"sqlite:///{self.db_path}")
        inspector = inspect(engine)

        # Check table presence
        tables = inspector.get_table_names()
        self.assertIn("analyst_reviews", tables)

        # Check columns match model metadata
        db_cols = {c["name"]: c for c in inspector.get_columns("analyst_reviews")}
        model_cols = AnalystReviewModel.__table__.columns
        for col in model_cols:
            self.assertIn(col.name, db_cols, f"Column {col.name} missing from migrated table")
            self.assertEqual(col.nullable, db_cols[col.name]["nullable"])

        # Check indexes match model metadata
        db_indexes = {idx["name"]: idx["column_names"] for idx in inspector.get_indexes("analyst_reviews")}
        expected_indexes = {
            "ix_analyst_reviews_sample_id": ["sample_id"],
            "ix_analyst_reviews_analysis_id": ["analysis_id"],
            "ix_analyst_reviews_user_id": ["user_id"],
            "ix_analyst_reviews_created_at": ["created_at"],
        }
        for name, cols in expected_indexes.items():
            self.assertIn(name, db_indexes)
            self.assertEqual(db_indexes[name], cols)

        engine.dispose()

    def test_migration_downgrade_and_reupgrade(self):
        """Downgrading to a1b2c3d4e5f6 drops analyst_reviews, and re-upgrading restores it cleanly."""
        run_alembic_cmd(self.db_path, "head")

        # Downgrade to prior head
        run_alembic_cmd(self.db_path, "downgrade")
        engine = create_engine(f"sqlite:///{self.db_path}")
        inspector = inspect(engine)
        self.assertNotIn("analyst_reviews", inspector.get_table_names())
        engine.dispose()

        # Re-upgrade to head
        run_alembic_cmd(self.db_path, "head")
        engine = create_engine(f"sqlite:///{self.db_path}")
        inspector = inspect(engine)
        self.assertIn("analyst_reviews", inspector.get_table_names())
        engine.dispose()

    def test_init_db_and_migration_interoperability_no_duplicate_index_error(self):
        """
        Verify that if create_all() runs before Alembic migration upgrade,
        no OperationalError ('index already exists') is raised.
        """
        engine = create_engine(f"sqlite:///{self.db_path}")
        Base.metadata.create_all(bind=engine)
        engine.dispose()

        # Now run Alembic upgrade head - should succeed idempotently
        run_alembic_cmd(self.db_path, "head")

        engine = create_engine(f"sqlite:///{self.db_path}")
        inspector = inspect(engine)
        self.assertIn("analyst_reviews", inspector.get_table_names())
        engine.dispose()

    def test_repeated_initialization_idempotency(self):
        """Verify repeated Base.metadata.create_all() does not crash."""
        engine = create_engine(f"sqlite:///{self.db_path}")
        Base.metadata.create_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        inspector = inspect(engine)
        self.assertIn("analyst_reviews", inspector.get_table_names())
        engine.dispose()

    def test_unique_constraint_on_analysis_id_blocks_duplicate_review_insertions(self):
        """SEC-04-04 / SEC-06: Verify unique constraint on analysis_id rejects duplicate reviews."""
        run_alembic_cmd(self.db_path, "head")
        engine = create_engine(f"sqlite:///{self.db_path}")
        Session = sessionmaker(bind=engine)
        session = Session()

        now = datetime.now(timezone.utc)
        r1 = AnalystReviewModel(
            analysis_id="anl_test_unique_001",
            sample_id=1,
            user_id=1,
            reviewer_username="analyst_1",
            verdict="CONFIRMED_MALWARE",
            review_state="ANALYST_CONFIRMED",
            previous_state="PENDING_REVIEW",
            rationale="First review valid",
            created_at=now,
        )
        session.add(r1)
        session.commit()

        r2 = AnalystReviewModel(
            analysis_id="anl_test_unique_001",
            sample_id=1,
            user_id=2,
            reviewer_username="analyst_2",
            verdict="REJECTED_FALSE_POSITIVE",
            review_state="ANALYST_REJECTED",
            previous_state="PENDING_REVIEW",
            rationale="Duplicate review attempt should fail",
            created_at=now,
        )
        session.add(r2)
        with self.assertRaises(IntegrityError):
            session.commit()
        session.rollback()
        session.close()
        engine.dispose()

    @unittest.skipUnless(REAL_DB_PATH.exists(), "real development database not present")
    def test_upgrade_on_copy_of_real_development_database(self):
        """
        Verify upgrading a copy of storage/defender.db adds analyst_reviews table and indexes
        while preserving all existing rows and leaving original DB untouched.
        """
        original_mtime = REAL_DB_PATH.stat().st_mtime
        original_size = REAL_DB_PATH.stat().st_size

        copy_path = self.tmp_path / "defender_copy.db"
        shutil.copy2(REAL_DB_PATH, copy_path)

        # Count samples and users before
        con = sqlite3.connect(f"file:{copy_path}?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT count(*) FROM samples")
        samples_before = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM users")
        users_before = cur.fetchone()[0]
        con.close()

        # Run Alembic upgrade head on copy
        run_alembic_cmd(copy_path, "head")

        # Verify analyst_reviews table exists and existing data is intact
        con = sqlite3.connect(f"file:{copy_path}?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT count(*) FROM samples")
        self.assertEqual(cur.fetchone()[0], samples_before)
        cur.execute("SELECT count(*) FROM users")
        self.assertEqual(cur.fetchone()[0], users_before)
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analyst_reviews'")
        self.assertIsNotNone(cur.fetchone())

        cur.execute("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'ix_analyst_reviews%'")
        indexes = {r[0] for r in cur.fetchall()}
        expected = {
            "ix_analyst_reviews_sample_id",
            "ix_analyst_reviews_analysis_id",
            "ix_analyst_reviews_user_id",
            "ix_analyst_reviews_created_at",
        }
        self.assertEqual(indexes, expected)
        con.close()

        # Verify real database untouched
        self.assertEqual(REAL_DB_PATH.stat().st_mtime, original_mtime)
        self.assertEqual(REAL_DB_PATH.stat().st_size, original_size)


if __name__ == "__main__":
    unittest.main()
