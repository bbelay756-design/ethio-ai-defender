"""
Database Repository and Transaction Service Module

Encapsulates CRUD operations, atomic multi-table transactions, and query optimizations for samples.
"""

from typing import List, Optional
from sqlalchemy.orm import Session, joinedload
from app.core.logger import logger
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


class SampleRepository:
    """
    Data Access Layer for Sample and Analysis Entities.
    """

    @staticmethod
    def create_sample(db: Session, sample_in: SampleCreate) -> SampleModel:
        """Creates a single sample record."""
        db_sample = SampleModel(
            analysis_id=sample_in.analysis_id,
            filename=sample_in.filename,
            size=sample_in.size,
            file_type=sample_in.file_type,
            architecture=sample_in.architecture,
            md5=sample_in.md5,
            sha256=sample_in.sha256,
            status=sample_in.status,
        )
        db.add(db_sample)
        db.commit()
        db.refresh(db_sample)
        return db_sample

    @staticmethod
    def get_by_id(db: Session, sample_id: int) -> Optional[SampleModel]:
        """Fetches sample by primary key with relations eagerly loaded."""
        return (
            db.query(SampleModel)
            .options(
                joinedload(SampleModel.sections),
                joinedload(SampleModel.imports),
                joinedload(SampleModel.strings),
                joinedload(SampleModel.indicators),
                joinedload(SampleModel.analysis_results),
            )
            .filter(SampleModel.id == sample_id)
            .first()
        )

    @staticmethod
    def get_by_analysis_id(db: Session, analysis_id: str) -> Optional[SampleModel]:
        """Fetches sample by unique analysis_id with relations."""
        return (
            db.query(SampleModel)
            .options(
                joinedload(SampleModel.sections),
                joinedload(SampleModel.imports),
                joinedload(SampleModel.strings),
                joinedload(SampleModel.indicators),
                joinedload(SampleModel.analysis_results),
            )
            .filter(SampleModel.analysis_id == analysis_id)
            .first()
        )

    @staticmethod
    def get_by_sha256(db: Session, sha256: str) -> Optional[SampleModel]:
        """Fetches the latest sample matching a specific SHA-256 hash using index."""
        return (
            db.query(SampleModel)
            .filter(SampleModel.sha256 == sha256)
            .order_by(SampleModel.created_at.desc())
            .first()
        )

    @staticmethod
    def list_samples(db: Session, skip: int = 0, limit: int = 50) -> List[SampleModel]:
        """Lists samples ordered by creation date descending."""
        return (
            db.query(SampleModel)
            .order_by(SampleModel.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    @staticmethod
    def save_full_analysis_transaction(
        db: Session,
        sample_in: SampleCreate,
        sections_in: List[SectionCreate] = None,
        imports_in: List[ImportCreate] = None,
        strings_in: List[StringCreate] = None,
        indicators_in: List[IndicatorCreate] = None,
        result_in: Optional[AnalysisResultCreate] = None,
    ) -> SampleModel:
        """
        Saves a full multi-table analysis record inside a single atomic database transaction.
        Rolls back automatically on any error.
        """
        sections_in = sections_in or []
        imports_in = imports_in or []
        strings_in = strings_in or []
        indicators_in = indicators_in or []

        try:
            # 1. Create parent Sample
            db_sample = SampleModel(
                analysis_id=sample_in.analysis_id,
                filename=sample_in.filename,
                size=sample_in.size,
                file_type=sample_in.file_type,
                architecture=sample_in.architecture,
                md5=sample_in.md5,
                sha256=sample_in.sha256,
                status=sample_in.status,
            )
            db.add(db_sample)
            db.flush()  # Populates db_sample.id for foreign key references

            # 2. Add Sections
            for sec in sections_in:
                db_sec = SectionModel(
                    sample_id=db_sample.id,
                    name=sec.name,
                    virtual_address=sec.virtual_address,
                    virtual_size=sec.virtual_size,
                    raw_size=sec.raw_size,
                    entropy=sec.entropy,
                    characteristics=sec.characteristics,
                )
                db.add(db_sec)

            # 3. Add Imports
            for imp in imports_in:
                db_imp = ImportModel(
                    sample_id=db_sample.id,
                    dll=imp.dll,
                    api=imp.api,
                    category=imp.category,
                    risk_relevance=imp.risk_relevance,
                )
                db.add(db_imp)

            # 4. Add Strings
            for st in strings_in:
                db_str = StringModel(
                    sample_id=db_sample.id,
                    value=st.value,
                    type=st.type,
                )
                db.add(db_str)

            # 5. Add Indicators
            for ind in indicators_in:
                db_ind = IndicatorModel(
                    sample_id=db_sample.id,
                    name=ind.name,
                    category=ind.category,
                    severity=ind.severity,
                    evidence=ind.evidence,
                    confidence=ind.confidence,
                )
                db.add(db_ind)

            # 6. Add Analysis Result
            if result_in:
                db_res = AnalysisResultModel(
                    sample_id=db_sample.id,
                    risk_score=result_in.risk_score,
                    risk_level=result_in.risk_level,
                    ai_summary=result_in.ai_summary,
                    ai_confidence=result_in.ai_confidence,
                )
                db.add(db_res)

            db.commit()
            db.refresh(db_sample)
            logger.info(f"Successfully committed full analysis transaction for sample '{db_sample.analysis_id}'.")
            return db_sample

        except Exception as e:
            db.rollback()
            logger.error(f"Transaction failed for sample '{sample_in.analysis_id}': {e}. Rolled back.")
            raise

    @staticmethod
    def delete_sample(db: Session, sample_id: int) -> bool:
        """
        Deletes sample by ID. Cascading foreign keys automatically clean up child rows.
        """
        sample = db.query(SampleModel).filter(SampleModel.id == sample_id).first()
        if not sample:
            return False
        db.delete(sample)
        db.commit()
        logger.info(f"Deleted sample ID {sample_id} and all cascading children.")
        return True
