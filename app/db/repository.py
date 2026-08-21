"""
Database Repository and Transaction Service Module

Encapsulates CRUD operations, atomic multi-table transactions, and query optimizations for samples.
"""

from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import or_
from app.core.logger import logger
from app.db.models import (
    SampleModel,
    SectionModel,
    ImportModel,
    StringModel,
    IndicatorModel,
    IOCModel,
    YaraMatchModel,
    RiskFactorModel,
    AnalysisResultModel,
)
from app.db.schemas import (
    SampleCreate,
    SectionCreate,
    ImportCreate,
    StringCreate,
    IndicatorCreate,
    IOCCreate,
    YaraMatchCreate,
    RiskFactorCreate,
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
            sha1=sample_in.sha1,
            sha256=sample_in.sha256,
            status=sample_in.status,
            risk_score=sample_in.risk_score or 0,
            classification=sample_in.classification or "LOW",
            user_id=sample_in.user_id,
            completed_at=sample_in.completed_at or datetime.now(timezone.utc),
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
                joinedload(SampleModel.iocs),
                joinedload(SampleModel.yara_matches),
                joinedload(SampleModel.risk_factors),
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
                joinedload(SampleModel.iocs),
                joinedload(SampleModel.yara_matches),
                joinedload(SampleModel.risk_factors),
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
    def list_samples(
        db: Session,
        skip: int = 0,
        limit: int = 50,
        search: Optional[str] = None,
        status_filter: Optional[str] = None,
        risk_filter: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> List[SampleModel]:
        """Lists samples ordered by creation date descending with optional filtering."""
        query = db.query(SampleModel)

        if user_id is not None:
            query = query.filter(SampleModel.user_id == user_id)

        if search:
            search_term = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    SampleModel.filename.ilike(search_term),
                    SampleModel.sha256.ilike(search_term),
                    SampleModel.analysis_id.ilike(search_term),
                    SampleModel.md5.ilike(search_term),
                )
            )

        if status_filter:
            query = query.filter(SampleModel.status == status_filter.upper())

        if risk_filter:
            query = query.filter(SampleModel.classification == risk_filter.upper())

        return (
            query.order_by(SampleModel.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    @staticmethod
    def count_samples(
        db: Session,
        search: Optional[str] = None,
        status_filter: Optional[str] = None,
        risk_filter: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> int:
        """Counts total samples matching filter."""
        query = db.query(SampleModel)
        if user_id is not None:
            query = query.filter(SampleModel.user_id == user_id)
        if search:
            search_term = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    SampleModel.filename.ilike(search_term),
                    SampleModel.sha256.ilike(search_term),
                    SampleModel.analysis_id.ilike(search_term),
                )
            )
        if status_filter:
            query = query.filter(SampleModel.status == status_filter.upper())
        if risk_filter:
            query = query.filter(SampleModel.classification == risk_filter.upper())
        return query.count()

    @staticmethod
    def save_full_analysis_transaction(
        db: Session,
        sample_in: SampleCreate,
        sections_in: List[SectionCreate] = None,
        imports_in: List[ImportCreate] = None,
        strings_in: List[StringCreate] = None,
        indicators_in: List[IndicatorCreate] = None,
        iocs_in: List[IOCCreate] = None,
        yara_matches_in: List[YaraMatchCreate] = None,
        risk_factors_in: List[RiskFactorCreate] = None,
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
        iocs_in = iocs_in or []
        yara_matches_in = yara_matches_in or []
        risk_factors_in = risk_factors_in or []

        try:
            # 1. Create parent Sample
            db_sample = SampleModel(
                analysis_id=sample_in.analysis_id,
                filename=sample_in.filename,
                size=sample_in.size,
                file_type=sample_in.file_type,
                architecture=sample_in.architecture,
                md5=sample_in.md5,
                sha1=sample_in.sha1,
                sha256=sample_in.sha256,
                status=sample_in.status,
                risk_score=sample_in.risk_score or 0,
                classification=sample_in.classification or "LOW",
                user_id=sample_in.user_id,
                completed_at=sample_in.completed_at or datetime.now(timezone.utc),
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
                    encoding=getattr(st, "encoding", "ASCII") or "ASCII",
                    offset=getattr(st, "offset", None),
                    category=getattr(st, "category", None) or getattr(st, "type", "GENERAL") or "GENERAL",
                    type=getattr(st, "type", "GENERAL") or "GENERAL",
                    suspicious=bool(getattr(st, "suspicious", False)),
                    severity=getattr(st, "severity", "LOW") or "LOW",
                    confidence=float(getattr(st, "confidence", 1.0) or 1.0),
                    reason=getattr(st, "reason", None),
                    mitre_technique=getattr(st, "mitre_technique", None),
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

            # 6. Add IOCs
            for ioc in iocs_in:
                db_ioc = IOCModel(
                    sample_id=db_sample.id,
                    type=ioc.type,
                    value=ioc.value,
                    source=ioc.source,
                    confidence=ioc.confidence,
                )
                db.add(db_ioc)

            # 7. Add YARA matches
            for ym in yara_matches_in:
                db_ym = YaraMatchModel(
                    sample_id=db_sample.id,
                    rule_name=ym.rule_name,
                    namespace=ym.namespace,
                    tags=ym.tags,
                    description=ym.description,
                )
                db.add(db_ym)

            # 8. Add Risk Factors
            for rf in risk_factors_in:
                db_rf = RiskFactorModel(
                    sample_id=db_sample.id,
                    name=rf.name,
                    category=rf.category,
                    severity=rf.severity,
                    weight=rf.weight,
                    evidence=rf.evidence,
                )
                db.add(db_rf)

            # 9. Add Analysis Result
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
    def get_strings_for_sample(
        db: Session,
        sample_id: int,
        skip: int = 0,
        limit: int = 50,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        encoding: Optional[str] = None,
        suspicious_only: bool = False,
        search: Optional[str] = None,
        sort_by: Optional[str] = None,
        sort_order: str = "desc"
    ) -> List[StringModel]:
        """
        Retrieves paginated, filtered, and sorted extracted strings for a specific sample.
        """
        query = db.query(StringModel).filter(StringModel.sample_id == sample_id)

        if category and category.upper() != "ALL":
            cat_upper = category.upper()
            if cat_upper in ("COMMAND", "CMD"):
                query = query.filter((StringModel.category == "COMMAND") | (StringModel.category == "CMD") | (StringModel.type == "COMMAND"))
            elif cat_upper == "URL":
                query = query.filter((StringModel.category == "URL") | (StringModel.type == "URL"))
            elif cat_upper in ("IP", "IP_ADDRESS"):
                query = query.filter((StringModel.category == "IP_ADDRESS") | (StringModel.type == "IP_ADDRESS"))
            elif cat_upper in ("REGISTRY", "REGISTRY_PATH"):
                query = query.filter((StringModel.category == "REGISTRY") | (StringModel.type == "REGISTRY_PATH"))
            else:
                query = query.filter((StringModel.category == cat_upper) | (StringModel.type == cat_upper))

        if severity and severity.upper() != "ALL":
            query = query.filter(StringModel.severity == severity.upper())

        if encoding and encoding.upper() != "ALL":
            query = query.filter(StringModel.encoding == encoding.upper())

        if suspicious_only:
            query = query.filter(StringModel.suspicious == True)

        if search:
            term = f"%{search.strip().lower()}%"
            query = query.filter(
                StringModel.value.ilike(term) |
                StringModel.category.ilike(term) |
                StringModel.reason.ilike(term)
            )

        # Ordering
        if sort_by == "offset":
            query = query.order_by(StringModel.offset.asc() if sort_order == "asc" else StringModel.offset.desc())
        elif sort_by == "value":
            query = query.order_by(StringModel.value.asc() if sort_order == "asc" else StringModel.value.desc())
        elif sort_by == "category":
            query = query.order_by(StringModel.category.asc() if sort_order == "asc" else StringModel.category.desc())
        else:
            # Default: Suspicious and highest severity first, then offset
            query = query.order_by(StringModel.suspicious.desc(), StringModel.id.asc())

        return query.offset(skip).limit(limit).all()

    @staticmethod
    def count_strings_for_sample(
        db: Session,
        sample_id: int,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        encoding: Optional[str] = None,
        suspicious_only: bool = False,
        search: Optional[str] = None
    ) -> int:
        """
        Counts filtered strings for a specific sample.
        """
        query = db.query(StringModel).filter(StringModel.sample_id == sample_id)

        if category and category.upper() != "ALL":
            cat_upper = category.upper()
            if cat_upper in ("COMMAND", "CMD"):
                query = query.filter((StringModel.category == "COMMAND") | (StringModel.category == "CMD") | (StringModel.type == "COMMAND"))
            elif cat_upper == "URL":
                query = query.filter((StringModel.category == "URL") | (StringModel.type == "URL"))
            elif cat_upper in ("IP", "IP_ADDRESS"):
                query = query.filter((StringModel.category == "IP_ADDRESS") | (StringModel.type == "IP_ADDRESS"))
            elif cat_upper in ("REGISTRY", "REGISTRY_PATH"):
                query = query.filter((StringModel.category == "REGISTRY") | (StringModel.type == "REGISTRY_PATH"))
            else:
                query = query.filter((StringModel.category == cat_upper) | (StringModel.type == cat_upper))

        if severity and severity.upper() != "ALL":
            query = query.filter(StringModel.severity == severity.upper())

        if encoding and encoding.upper() != "ALL":
            query = query.filter(StringModel.encoding == encoding.upper())

        if suspicious_only:
            query = query.filter(StringModel.suspicious == True)

        if search:
            term = f"%{search.strip().lower()}%"
            query = query.filter(
                StringModel.value.ilike(term) |
                StringModel.category.ilike(term) |
                StringModel.reason.ilike(term)
            )

        return query.count()

    @staticmethod
    def get_string_statistics_for_sample(db: Session, sample_id: int) -> Dict[str, int]:
        """
        Computes aggregated summary statistics for all strings of a sample.
        """
        all_strings = db.query(StringModel).filter(StringModel.sample_id == sample_id).all()
        total = len(all_strings)
        ascii_count = sum(1 for s in all_strings if (s.encoding or "").upper() == "ASCII")
        unicode_count = sum(1 for s in all_strings if "UTF" in (s.encoding or "").upper() or "UNI" in (s.encoding or "").upper())
        suspicious_count = sum(1 for s in all_strings if s.suspicious)
        urls_count = sum(1 for s in all_strings if s.category == "URL" or s.type == "URL")
        ips_count = sum(1 for s in all_strings if s.category == "IP_ADDRESS" or s.type == "IP_ADDRESS")
        domains_count = sum(1 for s in all_strings if s.category == "DOMAIN" or s.type == "DOMAIN")
        registry_count = sum(1 for s in all_strings if s.category == "REGISTRY" or s.type == "REGISTRY_PATH")
        commands_count = sum(1 for s in all_strings if s.category in ("COMMAND", "CMD") or s.type == "COMMAND")
        powershell_count = sum(1 for s in all_strings if s.category == "POWERSHELL" or s.type == "POWERSHELL")
        file_paths_count = sum(1 for s in all_strings if s.category == "FILE_PATH" or s.type == "FILE_PATH")
        dlls_count = sum(1 for s in all_strings if s.category == "DLL" or s.type == "DLL")
        apis_count = sum(1 for s in all_strings if s.category == "API" or s.type == "API")
        emails_count = sum(1 for s in all_strings if s.category == "EMAIL" or s.type == "EMAIL")

        return {
            "total": total,
            "ascii_count": ascii_count,
            "unicode_count": unicode_count,
            "suspicious_count": suspicious_count,
            "urls_count": urls_count,
            "ips_count": ips_count,
            "domains_count": domains_count,
            "registry_count": registry_count,
            "commands_count": commands_count,
            "powershell_count": powershell_count,
            "file_paths_count": file_paths_count,
            "dlls_count": dlls_count,
            "apis_count": apis_count,
            "emails_count": emails_count,
        }

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
