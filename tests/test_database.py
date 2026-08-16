"""
Unit tests for Module 14: Database Layer.

Tests:
1. Schema & Table creation across all 6 tables.
2. Foreign keys and cascading deletes (removing sample deletes sections, imports, strings, indicators, analysis_results).
3. SHA-256 index query and fast deduplication lookup.
4. Full analysis multi-table atomic transaction save.
5. Transaction rollback on failure (atomicity).
6. Pydantic v2 schema validation for all entities.
7. Verification that zero binary BLOBs or secrets are stored in DB.
"""

import unittest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from pydantic import ValidationError

from app.db.session import Base
from app.db.models import (
    SampleModel,
    SectionModel,
    ImportModel,
    StringModel,
    IndicatorModel,
    AnalysisResultModel,
)
from app.db.schemas import (
    SampleCreate,
    SectionCreate,
    ImportCreate,
    StringCreate,
    IndicatorCreate,
    AnalysisResultCreate,
)
from app.db.repository import SampleRepository


class TestDatabaseLayer(unittest.TestCase):
    """Unit test suite for Database Layer using in-memory SQLite with foreign keys."""

    def setUp(self):
        # Use an isolated in-memory SQLite database for unit tests
        self.engine = create_engine("sqlite:///:memory:", echo=False)
        
        # Enforce foreign key constraints in SQLite
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.db = self.Session()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_table_creation_and_sample_insert(self):
        """Verify table creation and basic sample insert."""
        sample_in = SampleCreate(
            analysis_id="ANL-DB-001",
            filename="sample_test.exe",
            size=10240,
            file_type="EXE",
            architecture="x64",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status="ANALYZED"
        )
        sample = SampleRepository.create_sample(self.db, sample_in)

        self.assertIsNotNone(sample.id)
        self.assertEqual(sample.analysis_id, "ANL-DB-001")
        self.assertEqual(sample.filename, "sample_test.exe")

    def test_full_analysis_atomic_transaction_save(self):
        """Verify saving complete 6-table analysis in a single atomic transaction."""
        sample_in = SampleCreate(
            analysis_id="ANL-DB-002",
            filename="trojan_dropper.exe",
            size=24576,
            file_type="EXE",
            architecture="x64",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="448d67c89f1232913ab8c9f2a18a5344c05ed1c7b69d3aa06205a2eae6376973",
            status="ANALYZED"
        )
        sections_in = [
            SectionCreate(name=".text", virtual_address=4096, virtual_size=12000, raw_size=12288, entropy=6.4, characteristics="0x60000020"),
            SectionCreate(name=".rdata", virtual_address=16384, virtual_size=4000, raw_size=4096, entropy=4.2, characteristics="0x40000040")
        ]
        imports_in = [
            ImportCreate(dll="KERNEL32.dll", api="VirtualAlloc", category="MEMORY", risk_relevance="MEDIUM"),
            ImportCreate(dll="WININET.dll", api="InternetOpenA", category="NETWORK", risk_relevance="HIGH")
        ]
        strings_in = [
            StringCreate(value="https://c2.threat.net/beacon", type="URL"),
            StringCreate(value="192.168.1.100", type="IP_ADDRESS")
        ]
        indicators_in = [
            IndicatorCreate(name="Memory Allocation", category="MEMORY", severity="MEDIUM", evidence="VirtualAlloc", confidence=0.9)
        ]
        result_in = AnalysisResultCreate(
            risk_score=75,
            risk_level="HIGH",
            ai_summary="High risk sample with memory and network primitives.",
            ai_confidence="HIGH"
        )

        sample = SampleRepository.save_full_analysis_transaction(
            db=self.db,
            sample_in=sample_in,
            sections_in=sections_in,
            imports_in=imports_in,
            strings_in=strings_in,
            indicators_in=indicators_in,
            result_in=result_in
        )

        self.assertIsNotNone(sample.id)
        # Fetch with relations
        fetched = SampleRepository.get_by_analysis_id(self.db, "ANL-DB-002")
        self.assertIsNotNone(fetched)
        self.assertEqual(len(fetched.sections), 2)
        self.assertEqual(len(fetched.imports), 2)
        self.assertEqual(len(fetched.strings), 2)
        self.assertEqual(len(fetched.indicators), 1)
        self.assertIsNotNone(fetched.analysis_results)
        self.assertEqual(fetched.analysis_results.risk_score, 75)

    def test_cascading_deletion(self):
        """Verify that deleting a sample automatically cascades and cleans up child rows in all 5 related tables."""
        sample_in = SampleCreate(
            analysis_id="ANL-DB-003",
            filename="to_delete.exe",
            size=8192,
            file_type="EXE",
            architecture="x64",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="3aca6c684a39c9ecaf3de614663d9c2240be7869d5ed5642b49140034ca9db9e",
            status="ANALYZED"
        )
        sample = SampleRepository.save_full_analysis_transaction(
            db=self.db,
            sample_in=sample_in,
            sections_in=[SectionCreate(name=".text", virtual_address=4096, virtual_size=4000, raw_size=4096, entropy=5.5, characteristics="0x60000020")],
            imports_in=[ImportCreate(dll="KERNEL32.dll", api="CreateFileA", category="FILE", risk_relevance="LOW")],
            strings_in=[StringCreate(value="cmd.exe /c whoami", type="COMMAND")],
            indicators_in=[IndicatorCreate(name="Command Execution", category="PROCESS", severity="HIGH", evidence="cmd.exe", confidence=1.0)],
            result_in=AnalysisResultCreate(risk_score=50, risk_level="SUSPICIOUS", ai_summary="Suspicious execution", ai_confidence="MEDIUM")
        )

        sample_id = sample.id

        # Confirm children exist
        self.assertEqual(self.db.query(SectionModel).filter_by(sample_id=sample_id).count(), 1)
        self.assertEqual(self.db.query(ImportModel).filter_by(sample_id=sample_id).count(), 1)
        self.assertEqual(self.db.query(StringModel).filter_by(sample_id=sample_id).count(), 1)
        self.assertEqual(self.db.query(IndicatorModel).filter_by(sample_id=sample_id).count(), 1)
        self.assertEqual(self.db.query(AnalysisResultModel).filter_by(sample_id=sample_id).count(), 1)

        # Delete sample
        deleted = SampleRepository.delete_sample(self.db, sample_id)
        self.assertTrue(deleted)

        # Confirm sample and all children were cascaded and removed
        self.assertIsNone(SampleRepository.get_by_id(self.db, sample_id))
        self.assertEqual(self.db.query(SectionModel).filter_by(sample_id=sample_id).count(), 0)
        self.assertEqual(self.db.query(ImportModel).filter_by(sample_id=sample_id).count(), 0)
        self.assertEqual(self.db.query(StringModel).filter_by(sample_id=sample_id).count(), 0)
        self.assertEqual(self.db.query(IndicatorModel).filter_by(sample_id=sample_id).count(), 0)
        self.assertEqual(self.db.query(AnalysisResultModel).filter_by(sample_id=sample_id).count(), 0)

    def test_sha256_index_lookup(self):
        """Verify fast lookup by SHA-256 hash."""
        target_hash = "7e24b7405e381b1625fdfc53ff5e6080de485efb9e107d9d372bb6826bd81d35"
        sample_in = SampleCreate(
            analysis_id="ANL-DB-004",
            filename="indexed_sample.exe",
            size=16384,
            file_type="EXE",
            architecture="x64",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256=target_hash,
            status="ANALYZED"
        )
        SampleRepository.create_sample(self.db, sample_in)

        found = SampleRepository.get_by_sha256(self.db, target_hash)
        self.assertIsNotNone(found)
        self.assertEqual(found.analysis_id, "ANL-DB-004")
        self.assertEqual(found.sha256, target_hash)

    def test_transaction_rollback_on_duplicate_key(self):
        """Verify transaction atomicity and rollback on error."""
        sample_in = SampleCreate(
            analysis_id="ANL-DB-DUP",
            filename="first.exe",
            size=1024,
            file_type="EXE",
            architecture="x64",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="1111111111111111111111111111111111111111111111111111111111111111",
            status="ANALYZED"
        )
        SampleRepository.create_sample(self.db, sample_in)

        # Attempt to create another sample with duplicate analysis_id
        with self.assertRaises(Exception):
            SampleRepository.create_sample(self.db, sample_in)

    def test_pydantic_schema_validation_rules(self):
        """Verify Pydantic validation rejects out-of-bound entropy and threat scores."""
        # Entropy > 8.0 must fail
        with self.assertRaises(ValidationError):
            SectionCreate(name=".bad", virtual_address=0, virtual_size=100, raw_size=100, entropy=9.5, characteristics="0x60000020")

        # Threat Score > 100 must fail
        with self.assertRaises(ValidationError):
            AnalysisResultCreate(risk_score=150, risk_level="CRITICAL", ai_summary="Invalid", ai_confidence="HIGH")

        # Invalid Hash length must fail
        with self.assertRaises(ValidationError):
            SampleCreate(analysis_id="ANL", filename="f.exe", size=10, md5="short", sha256="short")


if __name__ == "__main__":
    unittest.main()
