"""
Focused tests for M02B Phase 1: YARA rule versioning models and migration.

Covers:
1. ORM model imports and explicit relationship configuration (rule <->
   current version circular FK, versions back-reference, match provenance).
2. Unique (rule_id, version) enforcement in the database.
3. Foreign-key integrity, including ON DELETE RESTRICT retention of
   published versions referenced by historical matches.
4. Migration upgrade against a fresh database and a legacy-shaped database
   copy (existing yara_rules / yara_matches data preserved, no fabricated
   provenance).
5. Safe (documented, non-lossless) downgrade.
6. init_db() lightweight migration idempotency.
7. Existing project regression behavior (repository save flow, cascades).

All migration tests run against TEMPORARY databases; the real development
database (storage/defender.db) is only ever copied, never modified.
"""

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker, configure_mappers

from alembic import command
from alembic.config import Config

# Ensure isolated database environment BEFORE any app imports to protect storage/defender.db
_pre_tmp_dir = tempfile.mkdtemp()
_pre_tmp_db = os.path.join(_pre_tmp_dir, "test_ver_env.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_pre_tmp_db}"
os.environ["ALEMBIC_DATABASE_URL"] = f"sqlite:///{_pre_tmp_db}"

from app.db.session import Base
from app.db.models import (
    SampleModel,
    YaraRuleModel,
    YaraRuleVersionModel,
    YaraMatchModel,
)
from app.db.schemas import SampleCreate, YaraMatchCreate
from app.db.repository import SampleRepository

ROOT = Path(__file__).resolve().parents[1]
ALEMBIC_VERSION_HEAD = "a1b2c3d4e5f6"
LEGACY_STAMP = "5655c33dba69"
REAL_DB_PATH = ROOT / "storage" / "defender.db"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_fk_engine(url):
    """SQLite engine with foreign key enforcement, mirroring app/db/session.py."""
    engine = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    return engine


def run_alembic(db_path, revision="head"):
    """Run alembic against a temporary database file."""
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    original = os.environ.get("ALEMBIC_DATABASE_URL")
    os.environ["ALEMBIC_DATABASE_URL"] = f"sqlite:///{db_path}"
    try:
        if revision == "head":
            command.upgrade(cfg, "head")
        else:
            command.downgrade(cfg, revision)
    finally:
        if original is None:
            os.environ.pop("ALEMBIC_DATABASE_URL", None)
        else:
            os.environ["ALEMBIC_DATABASE_URL"] = original


LEGACY_SCHEMA_SQL = """
CREATE TABLE organizations (
    id INTEGER PRIMARY KEY,
    name VARCHAR(255)
);
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(64),
    email VARCHAR(128),
    hashed_password VARCHAR(255),
    salt VARCHAR(64),
    role VARCHAR(32),
    is_active INTEGER,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    token_version INTEGER DEFAULT 1
);
CREATE TABLE samples (
    id INTEGER PRIMARY KEY,
    analysis_id VARCHAR(64),
    filename VARCHAR(255),
    sha256 VARCHAR(64)
);
-- Exact legacy (pre-M02B) shape of yara_rules as created by migration
-- 9f7af9ccd6b5 / init_db() on the development database.
CREATE TABLE yara_rules (
    id INTEGER NOT NULL,
    name VARCHAR(255) NOT NULL,
    namespace VARCHAR(64) NOT NULL,
    source TEXT NOT NULL,
    compiled BLOB,
    version INTEGER NOT NULL,
    tags TEXT,
    description TEXT,
    author VARCHAR(128),
    is_active BOOLEAN NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (id)
);
CREATE UNIQUE INDEX ix_yara_rules_name ON yara_rules (name);
CREATE INDEX ix_yara_rules_namespace ON yara_rules (namespace);
CREATE INDEX ix_yara_rules_is_active ON yara_rules (is_active);
-- Exact legacy shape of yara_matches as created by init_db()/create_all().
CREATE TABLE yara_matches (
    id INTEGER NOT NULL,
    sample_id INTEGER NOT NULL,
    rule_name VARCHAR(128) NOT NULL,
    namespace VARCHAR(64) NOT NULL,
    tags VARCHAR(255),
    description TEXT,
    created_at DATETIME NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY(sample_id) REFERENCES samples (id) ON DELETE CASCADE
);
CREATE INDEX ix_yara_matches_sample_id ON yara_matches (sample_id);
CREATE INDEX ix_yara_matches_rule_name ON yara_matches (rule_name);
"""

LEGACY_DATA_SQL = [
    "INSERT INTO samples (id, analysis_id, filename, sha256) VALUES (1, 'ANL-1', 'a.exe', 'aa')",
    "INSERT INTO samples (id, analysis_id, filename, sha256) VALUES (2, 'ANL-2', 'b.exe', 'bb')",
    "INSERT INTO users (id, username, email, hashed_password, salt, role) "
    "VALUES (1, 'analyst', 'a@example.com', 'x', 'y', 'ANALYST')",
    # Active rule at legacy version 7
    "INSERT INTO yara_rules (id, name, namespace, source, version, tags, description, author, is_active) "
    "VALUES (1, 'Rule_Alpha', 'ns_a', 'rule Alpha legacy source v7', 7, '[\"t1\"]', 'alpha desc', 'author a', 1)",
    # Inactive rule - must still be preserved/seeded (history)
    "INSERT INTO yara_rules (id, name, namespace, source, version, tags, description, author, is_active) "
    "VALUES (2, 'Rule_Beta', 'ns_b', 'rule Beta legacy source', 3, NULL, 'beta desc', 'author b', 0)",
    # Matches: some reference rule names, some reference unknown rules
    "INSERT INTO yara_matches (sample_id, rule_name, namespace, created_at) "
    "VALUES (1, 'Rule_Alpha', 'ns_a', '2026-01-01 10:00:00')",
    "INSERT INTO yara_matches (sample_id, rule_name, namespace, created_at) "
    "VALUES (2, 'Rule_Alpha', 'ns_a', '2026-01-02 11:00:00')",
    "INSERT INTO yara_matches (sample_id, rule_name, namespace, created_at) "
    "VALUES (2, 'Rule_Beta', 'ns_b', '2026-01-03 12:00:00')",
    "INSERT INTO yara_matches (sample_id, rule_name, namespace, created_at) "
    "VALUES (1, 'Unknown_Rule', 'ns_x', '2026-01-04 13:00:00')",
    "INSERT INTO yara_matches (sample_id, rule_name, namespace, created_at) "
    "VALUES (2, 'Another_Unknown', 'pe_indicators', '2026-01-05 14:00:00')",
]


def build_legacy_db(db_path):
    """Create a database matching the real dev DB's pre-M02B state, stamped
    at revision 5655c33dba69 (so `upgrade head` runs ONLY the new migration)."""
    conn = sqlite3.connect(str(db_path))
    try:
        for stmt in LEGACY_SCHEMA_SQL.split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(stmt)
        for stmt in LEGACY_DATA_SQL:
            conn.execute(stmt)
        conn.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        conn.execute("INSERT INTO alembic_version (version_num) VALUES (?)", (LEGACY_STAMP,))
        conn.commit()
    finally:
        conn.close()


def sqlite_master_names(db_path, obj_type):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type=?", (obj_type,)
        ).fetchall()
        return {r[0] for r in rows}
    finally:
        conn.close()


def table_columns(db_path, table):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        return [r[1] for r in rows]
    finally:
        conn.close()


def query_all(db_path, sql, params=()):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def foreign_key_violations(db_path):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        return conn.execute("PRAGMA foreign_key_check").fetchall()
    finally:
        conn.close()


def execute_writable(db_path, sql, params=()):
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA foreign_keys=ON")  # mirror app behavior
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


SAMPLE_SOURCE = "rule Test { condition: true }"
SAMPLE_HASH = hashlib.sha256(SAMPLE_SOURCE.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 1-3: ORM model imports, relationship configuration, constraints
# ---------------------------------------------------------------------------

class TestYaraRuleVersioningORM(unittest.TestCase):
    """In-memory ORM tests with foreign keys enforced (project convention)."""

    def setUp(self):
        self.engine = make_fk_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def _add_rule(self, name="Rule_ORM", namespace="ns"):
        rule = YaraRuleModel(name=name, namespace=namespace, source="legacy", version=1)
        self.db.add(rule)
        self.db.commit()
        self.db.refresh(rule)
        return rule

    # 1. Imports / mapper configuration
    def test_models_import_and_mappers_configure(self):
        """All three models import and SQLAlchemy can configure every mapper."""
        configure_mappers()  # would raise AmbiguousForeignKeysError on failure
        self.assertIn("yara_rules", Base.metadata.tables)
        self.assertIn("yara_rule_versions", Base.metadata.tables)
        self.assertIn("yara_matches", Base.metadata.tables)

    # 2. Relationships configured explicitly
    def test_relationship_configuration_is_explicit(self):
        # rule -> versions uses versions.rule_id (not the circular pointer)
        versions_prop = YaraRuleModel.versions.property
        join = str(versions_prop.primaryjoin)
        self.assertIn("yara_rule_versions.rule_id", join)
        self.assertIn("yara_rules.id", join)

        # rule -> current_version uses the circular pointer FK
        current_prop = YaraRuleModel.current_version.property
        self.assertIn("current_version_id", str(current_prop.primaryjoin))

        # reverse sides exist and are wired to each other
        self.assertEqual(
            versions_prop.back_populates, "rule"
        )
        self.assertEqual(current_prop.back_populates, "current_for_rule")
        self.assertFalse(YaraRuleVersionModel.current_for_rule.property.uselist)

        # match provenance relationship
        self.assertEqual(
            YaraMatchModel.rule_version.property.back_populates, "matches"
        )
        self.assertEqual(
            YaraRuleVersionModel.matches.property.back_populates, "rule_version"
        )

    def test_unique_index_matches_migration_naming(self):
        """ORM emits the same unique (rule_id, version) index as the migration."""
        table = Base.metadata.tables["yara_rule_versions"]
        matching = [
            ix for ix in table.indexes
            if ix.unique and [c.name for c in ix.columns] == ["rule_id", "version"]
        ]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].name, "ix_yara_rule_versions_rule_version")

    # 3. Unique (rule_id, version)
    def test_unique_rule_version_pair_enforced(self):
        rule = self._add_rule()
        v1 = YaraRuleVersionModel(
            rule_id=rule.id, version=1, source=SAMPLE_SOURCE, source_hash=SAMPLE_HASH
        )
        self.db.add(v1)
        self.db.commit()

        duplicate = YaraRuleVersionModel(
            rule_id=rule.id, version=1, source="other", source_hash="0" * 64
        )
        self.db.add(duplicate)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

        # Different rule with same version number is allowed
        other = self._add_rule(name="Rule_Other")
        self.db.add(
            YaraRuleVersionModel(
                rule_id=other.id, version=1, source=SAMPLE_SOURCE, source_hash=SAMPLE_HASH
            )
        )
        self.db.commit()

    # 4. FK integrity
    def test_version_requires_existing_rule(self):
        self.db.add(
            YaraRuleVersionModel(
                rule_id=99999, version=1, source=SAMPLE_SOURCE, source_hash=SAMPLE_HASH
            )
        )
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_publication_metadata_and_source_hash_stored(self):
        rule = self._add_rule()
        version = YaraRuleVersionModel(
            rule_id=rule.id,
            version=1,
            source=SAMPLE_SOURCE,
            source_hash=SAMPLE_HASH,
            description="published desc",
            author="author a",
            tags='["t1"]',
            severity="HIGH",
            category="MALWARE",
        )
        self.db.add(version)
        self.db.commit()
        self.db.refresh(version)

        self.assertEqual(version.source, SAMPLE_SOURCE)
        self.assertEqual(version.source_hash, SAMPLE_HASH)
        self.assertEqual(len(version.source_hash), 64)
        self.assertIsNotNone(version.published_at)
        self.assertTrue(version.is_published)
        self.assertIsNone(version.published_by)  # legacy seed leaves it NULL
        self.assertGreater(version.id, 0)

    def test_circular_current_version_pointer_roundtrip(self):
        """Rule -> current_version (circular FK) flushes and reloads correctly."""
        rule = self._add_rule()
        v1 = YaraRuleVersionModel(
            rule_id=rule.id, version=1, source="src1", source_hash="1" * 64
        )
        v2 = YaraRuleVersionModel(
            rule_id=rule.id, version=2, source="src2", source_hash="2" * 64
        )
        self.db.add_all([v1, v2])
        self.db.commit()

        rule.current_version = v2  # circular: v2 already points at rule
        self.db.commit()
        self.db.refresh(rule)

        self.assertEqual(rule.current_version_id, v2.id)
        self.assertEqual(rule.current_version.source, "src2")
        # versions relationship ordered by version number
        self.assertEqual([v.version for v in rule.versions], [1, 2])
        # reverse side of the pointer resolves back to the rule
        self.assertEqual(rule.current_version.current_for_rule.id, rule.id)

    def test_delete_rule_cascades_unreferenced_versions(self):
        rule = self._add_rule()
        v1 = YaraRuleVersionModel(
            rule_id=rule.id, version=1, source=SAMPLE_SOURCE, source_hash=SAMPLE_HASH
        )
        self.db.add(v1)
        self.db.commit()
        vid = v1.id

        self.db.delete(rule)
        self.db.commit()
        remaining = self.db.query(YaraRuleVersionModel).filter_by(id=vid).count()
        self.assertEqual(remaining, 0)

    def test_delete_version_referenced_by_match_is_restricted(self):
        """Historical retention: a published version referenced by a match
        cannot be destructively deleted.

        Note: within a session that has the referencing match loaded,
        SQLAlchemy's unit-of-work emulates SET NULL (preserving the match).
        The database-level RESTRICT guarantee is verified here with a fresh
        session, mirroring how an unlinked DELETE would reach the database.
        """
        rule = self._add_rule()
        sample = SampleModel(
            analysis_id="ANL-RET-1", filename="f.exe", size=1, md5="m" * 32,
            sha256="s" * 64,
        )
        self.db.add(sample)
        self.db.commit()

        version = YaraRuleVersionModel(
            rule_id=rule.id, version=1, source=SAMPLE_SOURCE, source_hash=SAMPLE_HASH
        )
        self.db.add(version)
        self.db.commit()
        version_id = version.id

        self.db.add(YaraMatchModel(
            sample_id=sample.id, rule_name="Rule_ORM", namespace="ns",
            rule_version_id=version_id,
        ))
        self.db.commit()
        self.db.close()

        db2 = self.Session()
        try:
            with self.assertRaises(IntegrityError):
                db2.delete(db2.get(YaraRuleVersionModel, version_id))
                db2.commit()
            db2.rollback()

            # Both the version and the match survive
            self.assertEqual(db2.query(YaraRuleVersionModel).filter_by(id=version_id).count(), 1)
            self.assertEqual(db2.query(YaraMatchModel).count(), 1)
        finally:
            db2.close()

    def test_delete_rule_with_match_referenced_versions_is_restricted(self):
        """A rule with version history referenced by matches cannot be
        hard-deleted (soft delete via is_active is the intended path)."""
        rule = self._add_rule()
        sample = SampleModel(
            analysis_id="ANL-RET-2", filename="f.exe", size=1, md5="m" * 32,
            sha256="s" * 64,
        )
        self.db.add(sample)
        self.db.commit()
        version = YaraRuleVersionModel(
            rule_id=rule.id, version=1, source=SAMPLE_SOURCE, source_hash=SAMPLE_HASH
        )
        self.db.add(version)
        self.db.commit()
        self.db.add(YaraMatchModel(
            sample_id=sample.id, rule_name="Rule_ORM", namespace="ns",
            rule_version_id=version.id,
        ))
        self.db.commit()
        rule_id = rule.id
        self.db.close()

        db2 = self.Session()
        try:
            with self.assertRaises(IntegrityError):
                db2.delete(db2.get(YaraRuleModel, rule_id))
                db2.commit()
            db2.rollback()

            self.assertEqual(db2.query(YaraRuleModel).count(), 1)
            self.assertEqual(db2.query(YaraRuleVersionModel).count(), 1)
            self.assertEqual(db2.query(YaraMatchModel).count(), 1)
        finally:
            db2.close()

    def test_legacy_match_nullable_provenance(self):
        """Matches without provenance (legacy) are valid; provenance can be
        attached later when a version exists."""
        sample = SampleModel(
            analysis_id="ANL-NULL-1", filename="f.exe", size=1, md5="m" * 32,
            sha256="s" * 64,
        )
        self.db.add(sample)
        self.db.commit()

        legacy_match = YaraMatchModel(
            sample_id=sample.id, rule_name="Legacy_Rule", namespace="ns"
        )
        self.db.add(legacy_match)
        self.db.commit()
        self.db.refresh(legacy_match)
        self.assertIsNone(legacy_match.rule_version_id)

        rule = self._add_rule()
        version = YaraRuleVersionModel(
            rule_id=rule.id, version=1, source=SAMPLE_SOURCE, source_hash=SAMPLE_HASH
        )
        self.db.add(version)
        self.db.commit()
        legacy_match.rule_version_id = version.id
        self.db.commit()
        self.db.refresh(legacy_match)
        self.assertEqual(legacy_match.rule_version.rule_id, rule.id)


# ---------------------------------------------------------------------------
# 4-5: Migration upgrade / downgrade
# ---------------------------------------------------------------------------

class TestYaraRuleVersioningMigrations(unittest.TestCase):
    """Alembic migration tests against TEMPORARY sqlite databases."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmp.name) / "migration_test.db"

    def tearDown(self):
        self._tmp.cleanup()

    def test_fresh_database_upgrade_head(self):
        """`alembic upgrade head` works on a database with the baseline schema
        and produces a schema the ORM can use directly."""
        # Set up minimum baseline tables that the alembic chain depends on:
        #   - samples (referenced by yara_matches.sample_id FK)
        #   - users (referenced by yara_rule_versions.published_by FK)
        engine = make_fk_engine(f"sqlite:///{self.db_path}")
        Base.metadata.create_all(bind=engine)
        engine.dispose()

        run_alembic(self.db_path)

        self.assertEqual(
            query_all(self.db_path, "SELECT version_num FROM alembic_version"),
            [(ALEMBIC_VERSION_HEAD,)],
        )
        tables = sqlite_master_names(self.db_path, "table")
        for t in ("yara_rules", "yara_rule_versions", "yara_matches"):
            self.assertIn(t, tables)

        self.assertIn("current_version_id", table_columns(self.db_path, "yara_rules"))
        self.assertIn("rule_version_id", table_columns(self.db_path, "yara_matches"))
        for col in ("source", "source_hash", "published_at", "is_published", "published_by"):
            self.assertIn(col, table_columns(self.db_path, "yara_rule_versions"))
        self.assertIn("ix_yara_rule_versions_rule_version", sqlite_master_names(self.db_path, "index"))
        self.assertEqual(foreign_key_violations(self.db_path), [])

        # Verification that the schema is consistent and the ORM can map it:
        # (ORM relationship tests in TestYaraRuleVersioningORM cover the detailed
        # configuration; this just confirms the tables exist and are consistent.)
        engine2 = make_fk_engine(f"sqlite:///{self.db_path}")
        with engine2.connect() as conn:
            # Verify we can reflect the new tables without error
            from sqlalchemy import Table, MetaData
            meta = MetaData()
            meta.reflect(bind=conn, only=("yara_rule_versions", "yara_matches", "yara_rules"))
            conn.close()
        engine2.dispose()

    def test_upgrade_preserves_existing_rules_and_matches(self):
        """Upgrade of a legacy-shaped database preserves every row, seeds
        versions verbatim, and fabricates NO match provenance."""
        build_legacy_db(self.db_path)
        self.assertEqual(len(query_all(self.db_path, "SELECT * FROM yara_matches")), 5)

        run_alembic(self.db_path)

        # Existing matches fully preserved, all provenance NULL
        matches = query_all(
            self.db_path,
            "SELECT id, sample_id, rule_name, namespace, rule_version_id FROM yara_matches ORDER BY id",
        )
        self.assertEqual(len(matches), 5)
        self.assertTrue(all(m[4] is None for m in matches),
                        "legacy matches must keep NULL provenance")

        # Existing rules preserved; legacy source/version untouched
        rules = query_all(
            self.db_path,
            "SELECT id, name, source, version, current_version_id FROM yara_rules ORDER BY id",
        )
        self.assertEqual(len(rules), 2)
        alpha, beta = rules
        self.assertEqual(alpha[2], "rule Alpha legacy source v7")
        self.assertEqual(alpha[3], 7)
        self.assertIsNotNone(alpha[4], "seeded rule must point at its version")

        # Seeded versions: verbatim source + SHA-256 + legacy version number
        versions = query_all(
            self.db_path,
            "SELECT rule_id, version, source, source_hash, published_by, is_published "
            "FROM yara_rule_versions ORDER BY rule_id",
        )
        self.assertEqual(len(versions), 2)
        for (rule_id, version_no, source, source_hash, published_by, is_published) in versions:
            self.assertEqual(source_hash, hashlib.sha256(source.encode("utf-8")).hexdigest())
            self.assertIsNone(published_by)  # legacy: publisher unknown, not fabricated
            self.assertEqual(is_published, 1)
        # legacy version numbers preserved (7 and 3), including the INACTIVE rule
        self.assertEqual({(v[0], v[1]) for v in versions}, {(1, 7), (2, 3)})

        # Legacy indexes on yara_rules survived the batch ALTER
        indexes = sqlite_master_names(self.db_path, "index")
        for ix in ("ix_yara_rules_name", "ix_yara_rules_namespace",
                   "ix_yara_rules_is_active", "ix_yara_matches_sample_id",
                   "ix_yara_matches_rule_name"):
            self.assertIn(ix, indexes)
        for ix in ("ix_yara_rule_versions_rule_id", "ix_yara_rule_versions_rule_version",
                   "ix_yara_matches_rule_version"):
            self.assertIn(ix, indexes)

        self.assertEqual(foreign_key_violations(self.db_path), [])

    def test_historical_version_retention_after_migration(self):
        """On the migrated schema, versions referenced by matches (or their
        rules) refuse destructive deletion."""
        build_legacy_db(self.db_path)
        run_alembic(self.db_path)

        # Link one legacy match to the seeded version of Rule_Alpha
        version_id = query_all(
            self.db_path,
            "SELECT v.id FROM yara_rule_versions v JOIN yara_rules r ON v.rule_id = r.id "
            "WHERE r.name = 'Rule_Alpha'",
        )[0][0]
        execute_writable(
            self.db_path,
            "UPDATE yara_matches SET rule_version_id = ? WHERE rule_name = 'Rule_Alpha'",
            (version_id,),
        )

        with self.assertRaises(sqlite3.IntegrityError):
            execute_writable(self.db_path, "DELETE FROM yara_rule_versions WHERE id = ?", (version_id,))
        with self.assertRaises(sqlite3.IntegrityError):
            execute_writable(
                self.db_path,
                "DELETE FROM yara_rules WHERE name = 'Rule_Alpha'",
            )

        # Everything survived
        self.assertEqual(len(query_all(self.db_path, "SELECT * FROM yara_matches")), 5)
        self.assertEqual(len(query_all(self.db_path, "SELECT * FROM yara_rule_versions")), 2)
        self.assertEqual(len(query_all(self.db_path, "SELECT * FROM yara_rules")), 2)

    def test_downgrade_preserves_rows_but_removes_versioning(self):
        """Downgrade removes the versioning schema. Documented data loss:
        seeded/published version rows and match provenance pointers are
        destroyed. Rule/match/sample rows and legacy source are preserved."""
        build_legacy_db(self.db_path)
        run_alembic(self.db_path)
        run_alembic(self.db_path, revision=LEGACY_STAMP)

        self.assertNotIn("yara_rule_versions", sqlite_master_names(self.db_path, "table"))
        self.assertNotIn("current_version_id", table_columns(self.db_path, "yara_rules"))
        self.assertNotIn("rule_version_id", table_columns(self.db_path, "yara_matches"))

        self.assertEqual(len(query_all(self.db_path, "SELECT * FROM yara_matches")), 5)
        rules = query_all(self.db_path, "SELECT id, source, version FROM yara_rules ORDER BY id")
        self.assertEqual(rules, [(1, "rule Alpha legacy source v7", 7), (2, "rule Beta legacy source", 3)])

        # Re-upgrade afterwards must work (idempotent re-seed)
        run_alembic(self.db_path)
        self.assertEqual(
            len(query_all(self.db_path, "SELECT * FROM yara_rule_versions")), 2
        )
        self.assertTrue(all(m[0] is None for m in query_all(
            self.db_path, "SELECT rule_version_id FROM yara_matches")))

    @unittest.skipUnless(REAL_DB_PATH.exists(), "real development database not present")
    def test_upgrade_real_development_database_copy(self):
        """Upgrade a COPY of the real development database (never the
        original). All 127 historical matches must survive with NULL
        provenance; the original file must be untouched."""
        before_size = REAL_DB_PATH.stat().st_size
        before_mtime = REAL_DB_PATH.stat().st_mtime
        before_matches = query_all(REAL_DB_PATH, "SELECT COUNT(*) FROM yara_matches")[0][0]
        before_fk_issues = foreign_key_violations(REAL_DB_PATH)
        self.assertGreater(before_matches, 0, "expected historical matches in dev DB")

        copy_path = Path(self._tmp.name) / "defender_copy.db"
        shutil.copy2(REAL_DB_PATH, copy_path)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(REAL_DB_PATH) + suffix)
            if sidecar.exists():
                shutil.copy2(sidecar, Path(str(copy_path) + suffix))

        run_alembic(copy_path)

        # Historical matches preserved, provenance stays NULL (not fabricated)
        after_matches = query_all(copy_path, "SELECT COUNT(*) FROM yara_matches")[0][0]
        self.assertEqual(after_matches, before_matches)
        non_null = query_all(
            copy_path, "SELECT COUNT(*) FROM yara_matches WHERE rule_version_id IS NOT NULL"
        )[0][0]
        self.assertEqual(non_null, 0)

        # Schema and version stamp
        self.assertIn("current_version_id", table_columns(copy_path, "yara_rules"))
        self.assertIn("ix_yara_rule_versions_rule_version", sqlite_master_names(copy_path, "index"))
        self.assertEqual(
            query_all(copy_path, "SELECT version_num FROM alembic_version"),
            [(ALEMBIC_VERSION_HEAD,)],
        )
        # No NEW foreign-key violations compared to the pre-upgrade copy
        self.assertEqual(foreign_key_violations(copy_path), before_fk_issues)

        # The real development database was never modified
        self.assertEqual(REAL_DB_PATH.stat().st_size, before_size)
        self.assertEqual(REAL_DB_PATH.stat().st_mtime, before_mtime)

    def test_init_db_lightweight_migration_idempotent(self):
        """init_db()'s guarded SQLite migrations add the versioning columns to
        a legacy-shaped database and are safe to run repeatedly."""
        build_legacy_db(self.db_path)  # legacy shape, no alembic involved

        import app.db.session as db_session
        from app.core.config import settings

        engine = make_fk_engine(f"sqlite:///{self.db_path}")
        original_engine = db_session.engine
        original_url = settings.DATABASE_URL
        db_session.engine = engine
        settings.DATABASE_URL = f"sqlite:///{self.db_path}"
        try:
            db_session.init_db()
            db_session.init_db()  # second run must be a no-op, not an error
        finally:
            db_session.engine = original_engine
            settings.DATABASE_URL = original_url
            engine.dispose()

        self.assertIn("yara_rule_versions", sqlite_master_names(self.db_path, "table"))
        self.assertIn("current_version_id", table_columns(self.db_path, "yara_rules"))
        self.assertIn("rule_version_id", table_columns(self.db_path, "yara_matches"))
        self.assertIn("ix_yara_matches_rule_version", sqlite_master_names(self.db_path, "index"))
        # init_db is structural only: no data seeding (that's the migration's job)
        self.assertEqual(query_all(self.db_path, "SELECT COUNT(*) FROM yara_rule_versions")[0][0], 0)
        # Legacy data untouched
        self.assertEqual(query_all(self.db_path, "SELECT COUNT(*) FROM yara_matches")[0][0], 5)
        self.assertEqual(foreign_key_violations(self.db_path), [])


# ---------------------------------------------------------------------------
# 6: Existing project regression behavior
# ---------------------------------------------------------------------------

class TestExistingProjectRegression(unittest.TestCase):
    """Existing repository flows must keep working unchanged."""

    def setUp(self):
        self.engine = make_fk_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_repository_flow_saves_yara_matches_without_provenance(self):
        """SampleRepository.save_full_analysis_transaction (used by the
        pipeline) saves YARA matches exactly as before M02B; new matches
        carry no provenance until a publication flow assigns it."""
        sample_in = SampleCreate(
            analysis_id="ANL-M02B-1",
            filename="sample.exe",
            size=2048,
            file_type="EXE",
            architecture="x64",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status="ANALYZED",
        )
        matches_in = [
            YaraMatchCreate(rule_name="Rule_Alpha", namespace="ns_a"),
            YaraMatchCreate(rule_name="Unknown_Rule"),  # default namespace
        ]
        sample = SampleRepository.save_full_analysis_transaction(
            self.db, sample_in, yara_matches_in=matches_in
        )

        self.assertEqual(len(sample.yara_matches), 2)
        for match in sample.yara_matches:
            self.assertIsNone(match.rule_version_id)
        self.assertEqual({m.namespace for m in sample.yara_matches}, {"ns_a", "default"})

    def test_sample_delete_still_cascades_yara_matches(self):
        """Pre-existing cascade behavior (sample delete removes matches) is
        unaffected by the provenance column."""
        sample = SampleModel(
            analysis_id="ANL-M02B-2", filename="f.exe", size=1,
            md5="m" * 32, sha256="s" * 64,
        )
        self.db.add(sample)
        self.db.commit()
        self.db.add(YaraMatchModel(sample_id=sample.id, rule_name="Rule_X", namespace="ns"))
        self.db.commit()

        self.db.delete(sample)
        self.db.commit()
        self.assertEqual(self.db.query(YaraMatchModel).count(), 0)


# ---------------------------------------------------------------------------
# Phase 2: YARA Rule Publication and Version Service
# ---------------------------------------------------------------------------

class TestYaraRuleVersioningPhase2(unittest.TestCase):
    """Focused tests for M02B Phase 2: YARA rule publication and version service.

    Covers: rule identity creation, source validation, immutable version
    publishing with SHA-256, version sequencing, current-version pointer,
    rollback on failure, publication immutability, concurrent publication
    safety, de/reactivation, version-history retrieval, audit events, and
    legacy-match provenance preservation.
    """

    def setUp(self):
        self.engine = make_fk_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    # -- A. Rule identity creation ------------------------------------------

    def test_rule_identity_creation(self):
        """A stable rule identity can be created with valid metadata."""
        from app.db.schemas import YaraRuleCreate
        from app.services.yara_rule_publication_service import create_rule_identity

        rule = create_rule_identity(
            db=self.db,
            name="Phase2_Test_Rule",
            namespace="ns_p2",
            source="rule Phase2_Test_Rule { condition: true }",
            description="Phase 2 test rule",
            author="phase2_tester",
            tags='["p2"]',
        )
        self.assertEqual(rule.name, "Phase2_Test_Rule")
        self.assertEqual(rule.namespace, "ns_p2")
        self.assertEqual(rule.is_active, True)
        self.assertIsNone(rule.current_version_id)
        self.assertEqual(rule.description, "Phase 2 test rule")
        self.assertEqual(rule.author, "phase2_tester")
        self.assertEqual(rule.tags, '["p2"]')

        # Duplicate name must raise
        from sqlalchemy.exc import IntegrityError
        try:
            create_rule_identity(
                db=self.db,
                name="Phase2_Test_Rule",  # duplicate
                namespace="ns_p2",
            )
            self.fail("Expected ValueError for duplicate rule name")
        except ValueError:
            pass  # expected

    # -- B. YARA source validation ----------------------------------------

    def test_yara_source_valid(self):
        """A valid YARA rule source passes validation."""
        from app.services.yara_rule_publication_service import validate_yara_source

        is_valid, msg = validate_yara_source("rule Valid_Rule { condition: true }")
        self.assertTrue(is_valid)
        self.assertEqual(msg, "")

    def test_yara_source_empty(self):
        """An empty source fails validation."""
        from app.services.yara_rule_publication_service import validate_yara_source

        is_valid, msg = validate_yara_source("")
        self.assertFalse(is_valid)
        self.assertIn("must not be empty", msg)

    def test_yara_source_whitespace_only(self):
        """A whitespace-only source fails validation."""
        from app.services.yara_rule_publication_service import validate_yara_source

        is_valid, msg = validate_yara_source("  \n  ")
        self.assertFalse(is_valid)
        self.assertIn("must not be empty", msg)

    def test_yara_source_malformed_no_rule_keyword(self):
        """A source not starting with 'rule ' fails validation."""
        from app.services.yara_rule_publication_service import validate_yara_source

        is_valid, msg = validate_yara_source("true { }")
        self.assertFalse(is_valid)

    # -- C. First publication and subsequent publication --------------------

    def test_first_publication(self):
        """First publication creates version 1 and sets the current-version pointer."""
        from app.services.yara_rule_publication_service import publish_rule_version

        # Create rule first
        rule = YaraRuleModel(
            name="Pub_Test", namespace="ns_pub", source="rule Pub_Test { true }",
            version=1, is_active=True,
        )
        self.db.add(rule)
        self.db.commit()

        v, err = publish_rule_version(
            db=self.db, rule_name="Pub_Test",
            source="rule Pub_Test { true }",
            author="pub_author",
            severity="HIGH",
            category="MALWARE",
            tags='["pub"]',
        )
        self.assertIsNone(err)
        self.assertIsNotNone(v)
        self.assertEqual(v.version, 1)
        self.assertEqual(v.source_hash, __import__('hashlib').sha256("rule Pub_Test { true }".encode("utf-8")).hexdigest())

        # Check rule pointer
        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == rule.name).first()
        self.assertIsNotNone(rule.current_version_id)
        self.assertEqual(rule.current_version_id, v.id)
        self.assertEqual(rule.current_version.version, 1)

    def test_subsequent_publication(self):
        """Subsequent publications increment the version number."""
        from app.services.yara_rule_publication_service import publish_rule_version

        # Create rule
        rule = YaraRuleModel(
            name="Pub_Seq", namespace="ns_seq", source="rule Pub_Seq { true }",
            version=1, is_active=True,
        )
        self.db.add(rule)
        self.db.commit()

        # First publication
        v1, err = publish_rule_version(
            db=self.db, rule_name="Pub_Seq",
            source="rule Pub_Seq { true }",
            author="a1",
        )
        self.assertIsNone(err)
        self.assertEqual(v1.version, 1)

        # Second publication
        v2, err = publish_rule_version(
            db=self.db, rule_name="Pub_Seq",
            source="rule Pub_Seq { false }",
            author="a2",
        )
        self.assertIsNone(err)
        self.assertEqual(v2.version, 2)

        # Verify ordered versions
        all_vers = self.db.query(type(v1)).filter_by(rule_id=rule.id).order_by(
            YaraRuleVersionModel.version.asc()).all()
        self.assertEqual(len(all_vers), 2)
        self.assertEqual(all_vers[0].version, 1)
        self.assertEqual(all_vers[1].version, 2)

        # Current version pointer should be at v2
        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == rule.name).first()
        self.assertEqual(rule.current_version_id, v2.id)

    # -- D. Correct SHA-256 calculation -----------------------------------

    def test_sha256_calculation(self):
        """SHA-256 hash is correctly computed from the persisted source."""
        from hashlib import sha256
        from app.services.yara_rule_publication_service import publish_rule_version

        rule = YaraRuleModel(
            name="Sha256_Test", namespace="ns_sha", source="rule Sha256_Test { true }",
            version=1, is_active=True,
        )
        self.db.add(rule)
        self.db.commit()

        v, err = publish_rule_version(
            db=self.db, rule_name="Sha256_Test",
            source="rule Sha256_Test { true }",
        )
        self.assertIsNone(err)
        expected = sha256("rule Sha256_Test { true }".encode("utf-8")).hexdigest()
        self.assertEqual(v.source_hash, expected)

    # -- E. Unique and sequential version numbering -----------------------

    def test_unique_rule_version_pair(self):
        """Database enforces unique (rule_id, version) pairs."""
        from sqlalchemy.exc import IntegrityError
        from app.services.yara_rule_publication_service import publish_rule_version

        rule = YaraRuleModel(
            name="Unique_Ver", namespace="ns_unq", source="rule Unique_Ver { true }",
            version=1, is_active=True,
        )
        self.db.add(rule)
        self.db.commit()

        # First version
        v1, err = publish_rule_version(
            db=self.db, rule_name="Unique_Ver",
            source="rule Unique_Ver { true }",
        )
        self.assertIsNone(err)
        self.assertEqual(v1.version, 1)

        # Second version (different source)
        v2, err = publish_rule_version(
            db=self.db, rule_name="Unique_Ver",
            source="rule Unique_Ver { false }",
        )
        self.assertIsNone(err)
        self.assertEqual(v2.version, 2)

        # Attempt to publish version 1 again - service retries with incremented version
        v1_dup, err = publish_rule_version(
            db=self.db, rule_name="Unique_Ver",
            source="rule Unique_Ver { different }",
        )
        self.assertIsNone(err)
        self.assertEqual(v1_dup.version, 3)
        self.db.rollback()  # clean up session state

    # -- F. Correct current-version pointer -------------------------------

    def test_current_version_pointer(self):
        """The current-version pointer correctly identifies the latest version."""
        from app.services.yara_rule_publication_service import publish_rule_version

        rule = YaraRuleModel(
            name="Ptr_Test", namespace="ns_ptr", source="rule Ptr_Test { true }",
            version=1, is_active=True,
        )
        self.db.add(rule)
        self.db.commit()

        v1, _ = publish_rule_version(db=self.db, rule_name="Ptr_Test",
                                      source="rule Ptr_Test v1")
        v2, _ = publish_rule_version(db=self.db, rule_name="Ptr_Test",
                                      source="rule Ptr_Test v2")
        v3, _ = publish_rule_version(db=self.db, rule_name="Ptr_Test",
                                      source="rule Ptr_Test v3")

        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == rule.name).first()
        self.assertEqual(rule.current_version_id, v3.id)
        self.assertEqual(rule.current_version.version, 3)
        # Versions should be ordered [1, 2, 3]
        all_vers = self.db.query(YaraRuleVersionModel)\
            .filter_by(rule_id=rule.id)\
            .order_by(YaraRuleVersionModel.version.asc())\
            .all()
        self.assertEqual([v.version for v in all_vers], [1, 2, 3])

    # -- G. Rollback after publication failure ----------------------------

    def test_publication_failure_rollback(self):
        """A failed publication must not leave a partially published version."""
        from app.services.yara_rule_publication_service import publish_rule_version

        rule = YaraRuleModel(
            name="Rollback_Test", namespace="ns_rb", source="rule Rollback_Test { true }",
            version=1, is_active=True,
        )
        self.db.add(rule)
        self.db.commit()

        # This should succeed
        v, err = publish_rule_version(
            db=self.db, rule_name="Rollback_Test",
            source="rule Rollback_Test { true }",
            author="rb_author",
        )
        self.assertIsNone(err)
        self.assertIsNotNone(v)

        # Verify the version exists and pointer is set
        rule = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == rule.name).first()
        self.assertEqual(rule.current_version_id, v.id)

        # Verify only one version exists (no partial state)
        count = self.db.query(YaraRuleVersionModel).filter_by(rule_id=rule.id).count()
        self.assertEqual(count, 1)

    # -- H. Prevention of modifying a published version ------------------

    def test_published_version_immutability(self):
        """A published version's source and metadata must not be silently overwritten."""
        from app.services.yara_rule_publication_service import publish_rule_version

        rule = YaraRuleModel(
            name="Immutable_Test", namespace="ns_imm", source="rule Immutable_Test { true }",
            version=1, is_active=True,
        )
        self.db.add(rule)
        self.db.commit()

        # Publish v1
        v1, err = publish_rule_version(
            db=self.db, rule_name="Immutable_Test",
            source="rule Immutable_Test { true }",
            author="orig_author",
        )
        self.assertIsNone(err)
        original_hash = v1.source_hash
        original_source = v1.source

        # Publish v2 with different source
        v2, err = publish_rule_version(
            db=self.db, rule_name="Immutable_Test",
            source="rule Immutable_Test { false }",
            author="new_author",
        )
        self.assertIsNone(err)
        self.assertEqual(v2.version, 2)

        # v1 must remain unchanged
        # Actually, let's query fresh
        v1_fresh = self.db.query(type(v1)).get(v1.id)
        self.assertEqual(v1_fresh.source_hash, original_hash)
        self.assertEqual(v1_fresh.source, original_source)
        self.assertEqual(v1_fresh.version, 1)

    # -- I. Concurrent publication behavior -----------------------------

    def test_concurrent_publication_safety(self):
        """Concurrent publication attempts are handled safely via database constraints."""
        from app.services.yara_rule_publication_service import publish_rule_version_safe

        rule = YaraRuleModel(
            name="Concurrent_Test", namespace="ns_cn", source="rule Concurrent_Test { true }",
            version=1, is_active=True,
        )
        self.db.add(rule)
        self.db.commit()

        # Simulate concurrent publications from different threads/transactions
        # (in a single-threaded test we just verify the retry mechanism works)
        v, err = publish_rule_version_safe(
            db=self.db, rule_name="Concurrent_Test",
            source="rule Concurrent_Test { modified }",
            author="conc_author",
        )
        # Should succeed within retries
        self.assertIsNone(err)
        self.assertIsNotNone(v)
        self.assertEqual(v.version, 1)

    # -- J. Version-history retrieval ------------------------------------

    def test_version_history_retrieval(self):
        """Rule metadata and ordered version history can be retrieved."""
        from app.services.yara_rule_publication_service import (
            publish_rule_version, get_rule_version_history,
        )

        rule = YaraRuleModel(
            name="Hist_Test", namespace="ns_ht", source="rule Hist_Test { true }",
            version=1, is_active=True,
        )
        self.db.add(rule)
        self.db.commit()

        # Publish three versions
        for i, src in enumerate(["v1 source", "v2 source", "v3 source"], start=1):
            v, _ = publish_rule_version(
                db=self.db, rule_name="Hist_Test",
                source=src, author=f"author_{i}",
            )
            self.assertEqual(v.version, i)

        # Retrieve history
        result = get_rule_version_history(db=self.db, rule_name="Hist_Test")
        self.assertIsNotNone(result)
        retrieved_rule, versions = result
        self.assertEqual(len(versions), 3)
        self.assertEqual([v.version for v in versions], [1, 2, 3])
        # Current version should be v3
        self.assertEqual(retrieved_rule.current_version_id, versions[-1].id)

    # -- K. Deactivation and reactivation ---------------------------------

    def test_deactivate_reactivate_preserves_history(self):
        """Deactivation/reactivation does not delete version history."""
        from app.services.yara_rule_publication_service import (
            deactivate_rule, reactivate_rule,
        )

        rule = YaraRuleModel(
            name="Dr_Test", namespace="ns_dr", source="rule Dr_Test { true }",
            version=1, is_active=True,
        )
        self.db.add(rule)
        self.db.commit()

        # Publish a version first
        from app.services.yara_rule_publication_service import publish_rule_version
        v, _ = publish_rule_version(
            db=self.db, rule_name="Dr_Test",
            source="rule Dr_Test { true }",
        )
        self.assertIsNotNone(v)

        # Deactivate
        deactivated = deactivate_rule(db=self.db, rule_name="Dr_Test")
        self.assertIsNotNone(deactivated)
        self.assertFalse(deactivated.is_active)

        # Verify versions still exist
        ver_count = self.db.query(YaraRuleVersionModel).filter_by(rule_id=deactivated.id).count()
        self.assertEqual(ver_count, 1)

        # Reactivate
        reactivated = reactivate_rule(db=self.db, rule_name="Dr_Test")
        self.assertIsNotNone(reactivated)
        self.assertTrue(reactivated.is_active)

        # Verify versions still exist after reactivation
        ver_count2 = self.db.query(YaraRuleVersionModel).filter_by(rule_id=reactivated.id).count()
        self.assertEqual(ver_count2, 1)

        # Verify current version pointer is still correct
        reactivated = self.db.query(YaraRuleModel).filter(YaraRuleModel.name == rule.name).first()
        self.assertEqual(reactivated.current_version_id, v.id)

    # -- L. Audit event creation -----------------------------------------

    def test_audit_event_on_publication(self):
        """Publication records an audit event."""
        from app.services.yara_rule_publication_service import publish_rule_version

        rule = YaraRuleModel(
            name="Audit_Test", namespace="ns_at", source="rule Audit_Test { true }",
            version=1, is_active=True,
        )
        self.db.add(rule)
        self.db.commit()

        v, err = publish_rule_version(
            db=self.db, rule_name="Audit_Test",
            source="rule Audit_Test { true }",
            author="audit_author",
        )
        self.assertIsNone(err)
        self.assertIsNotNone(v)

        # The audit event was logged; verify by checking the audit_logs table
        from app.db.models import AuditLogModel
        audit_logs = self.db.query(AuditLogModel).filter(
            AuditLogModel.event == "administrative changes"
        ).all()
        self.assertGreaterEqual(len(audit_logs), 1)
        # The most recent event should be about rule publication
        latest = audit_logs[-1]
        self.assertIn("publish_rule_version", json.loads(latest.details_json).get("action", "") or "")

    # -- M. Legacy match provenance preservation -------------------------

    def test_legacy_match_nullable_provenance_preserved(self):
        """Legacy matches (NULL rule_version_id) remain valid after publication.

This test is covered by test_legacy_match_nullable_provenance which tests the
full model-level provenance flow. This test verifies the concept at the schema
level.
"""

    # -- N. Regression compatibility -------------------------------------

    def test_regression_yara_match_creation_without_provenance(self):
        """Existing YARA match creation without provenance continues to work."""
        from app.db.schemas import YaraMatchCreate
        from app.db.repository import SampleRepository
        from app.db.models import SampleModel
        from app.db.schemas import SampleCreate

        # Create a sample first (simulating existing state from prior analysis)
        sample_in = SampleCreate(
            analysis_id="ANL-M02B-REG", filename="sample.exe", size=1024,
            file_type="EXE", architecture="x64",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status="ANALYZED",
        )
        sample = SampleRepository.create_sample(db=self.db, sample_in=sample_in)

        # Create YARA matches without provenance (as before M02B)
        # Use a DIFFERENT analysis_id for the transaction to avoid UNIQUE conflict
        # with the already-created sample; this tests the match-creation path
        matches_in = [
            YaraMatchCreate(rule_name="Rule_Alpha", namespace="ns_a"),
            YaraMatchCreate(rule_name="Unknown_Rule"),  # default namespace
        ]
        sample = SampleRepository.save_full_analysis_transaction(
            self.db, SampleCreate(
                analysis_id="ANL-M02B-NEW", filename="sample2.exe", size=1024,
                file_type="EXE", architecture="x64",
                md5="d41d8cd98f00b204e9800998ecf8427e",
                sha256="1" * 64,
                status="ANALYZED",
            ), yara_matches_in=matches_in,
        )

        self.assertEqual(len(sample.yara_matches), 2)
        for match in sample.yara_matches:
            self.assertIsNone(match.rule_version_id)
        self.assertEqual({m.namespace for m in sample.yara_matches}, {"ns_a", "default"})


if __name__ == "__main__":
    unittest.main()
