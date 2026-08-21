"""
SQLAlchemy ORM Models for ETHIO-AI Defender Database Layer

Defines 6 relational tables with foreign keys, cascading deletes, and indexes:
1. SampleModel (samples)
2. SectionModel (sections)
3. ImportModel (imports)
4. StringModel (strings)
5. IndicatorModel (indicators)
6. AnalysisResultModel (analysis_results)
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship
from app.db.session import Base


class SampleModel(Base):
    """
    Core sample catalog table.
    Stores metadata and hashes without saving raw binary payloads in DB.
    """
    __tablename__ = "samples"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(String(64), unique=True, index=True, nullable=False)
    filename = Column(String(255), nullable=False)
    size = Column(Integer, nullable=False)
    file_type = Column(String(32), nullable=False, default="EXE")
    architecture = Column(String(32), nullable=False, default="x64")
    md5 = Column(String(32), nullable=False)
    sha1 = Column(String(40), nullable=True)
    sha256 = Column(String(64), index=True, nullable=False)
    status = Column(String(32), nullable=False, default="COMPLETED")
    risk_score = Column(Integer, nullable=True, default=0)
    classification = Column(String(32), nullable=True, default="LOW")
    case_id = Column(String(64), nullable=True)
    case_status = Column(String(32), nullable=True, default="OPEN")  # OPEN, INVESTIGATING, CONTAINED, RESOLVED
    case_priority = Column(String(32), nullable=True, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=True)

    # Relationships with cascading deletes
    sections = relationship("SectionModel", back_populates="sample", cascade="all, delete-orphan")
    imports = relationship("ImportModel", back_populates="sample", cascade="all, delete-orphan")
    strings = relationship("StringModel", back_populates="sample", cascade="all, delete-orphan")
    indicators = relationship("IndicatorModel", back_populates="sample", cascade="all, delete-orphan")
    iocs = relationship("IOCModel", back_populates="sample", cascade="all, delete-orphan")
    yara_matches = relationship("YaraMatchModel", back_populates="sample", cascade="all, delete-orphan")
    risk_factors = relationship("RiskFactorModel", back_populates="sample", cascade="all, delete-orphan")
    analysis_results = relationship("AnalysisResultModel", back_populates="sample", uselist=False, cascade="all, delete-orphan")
    notes = relationship("AnalystNoteModel", back_populates="sample", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_samples_sha256_created", "sha256", "created_at"),
    )


class SectionModel(Base):
    """
    PE Section records linked to parent sample.
    """
    __tablename__ = "sections"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(64), nullable=False)
    virtual_address = Column(Integer, nullable=False)
    virtual_size = Column(Integer, nullable=False)
    raw_size = Column(Integer, nullable=False)
    entropy = Column(Float, nullable=False)
    characteristics = Column(String(64), nullable=False)

    # Relationship
    sample = relationship("SampleModel", back_populates="sections")


class ImportModel(Base):
    """
    Imported DLLs and Windows APIs linked to parent sample.
    """
    __tablename__ = "imports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    dll = Column(String(128), nullable=False, index=True)
    api = Column(String(128), nullable=False, index=True)
    category = Column(String(64), nullable=False, default="GENERAL")
    risk_relevance = Column(String(32), nullable=False, default="LOW")

    # Relationship
    sample = relationship("SampleModel", back_populates="imports")


class StringModel(Base):
    """
    Extracted ASCII and Unicode strings classified by type with forensic intelligence indicators.
    """
    __tablename__ = "strings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    value = Column(Text, nullable=False)
    encoding = Column(String(16), nullable=False, default="ASCII")
    offset = Column(Integer, nullable=True)
    category = Column(String(64), nullable=False, default="GENERAL", index=True)
    type = Column(String(64), nullable=False, default="GENERAL")
    suspicious = Column(Boolean, nullable=False, default=False, index=True)
    severity = Column(String(32), nullable=False, default="LOW")
    confidence = Column(Float, nullable=False, default=1.0)
    reason = Column(Text, nullable=True)
    mitre_technique = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship
    sample = relationship("SampleModel", back_populates="strings")


class IndicatorModel(Base):
    """
    Correlated threat indicators generated for the sample.
    """
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False)
    evidence = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False, default=1.0)

    # Relationship
    sample = relationship("SampleModel", back_populates="indicators")


class IOCModel(Base):
    """
    Indicators of Compromise (IOCs) extracted from the sample (hashes, IPs, domains, URLs, etc.).
    """
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String(32), nullable=False, index=True)  # HASH, IP, DOMAIN, URL, EMAIL, FILE_PATH, REGISTRY_KEY
    value = Column(Text, nullable=False)
    source = Column(String(64), nullable=False, default="STATIC_ANALYSIS")
    confidence = Column(Float, nullable=False, default=1.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship
    sample = relationship("SampleModel", back_populates="iocs")


class YaraMatchModel(Base):
    """
    YARA rule detection matches recorded for the sample.
    """
    __tablename__ = "yara_matches"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_name = Column(String(128), nullable=False, index=True)
    namespace = Column(String(64), nullable=False, default="default")
    tags = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship
    sample = relationship("SampleModel", back_populates="yara_matches")


class RiskFactorModel(Base):
    """
    Individual evidence-backed scoring factors explaining why the heuristic risk score was generated.
    """
    __tablename__ = "risk_factors"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False)
    weight = Column(Float, nullable=False)
    evidence = Column(Text, nullable=True)

    # Relationship
    sample = relationship("SampleModel", back_populates="risk_factors")


class AnalysisResultModel(Base):
    """
    Heuristic threat score and AI security interpretation results.
    """
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(32), nullable=False)
    ai_summary = Column(Text, nullable=False)
    ai_confidence = Column(String(32), nullable=False, default="MEDIUM")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship
    sample = relationship("SampleModel", back_populates="analysis_results")


class UserModel(Base):
    """
    Platform User and Role-Based Access Control (RBAC) model.
    Stores salted PBKDF2-HMAC-SHA256 password digests with zero plaintext exposure.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    salt = Column(String(64), nullable=False)
    role = Column(String(32), default="STUDENT", nullable=False)  # 'ADMIN', 'ANALYST', 'STUDENT'
    is_active = Column(Integer, default=1, nullable=False)  # 1 = active, 0 = inactive
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class RevokedTokenModel(Base):
    """
    Token blacklist model for secure logout and token invalidation.
    """
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_jti = Column(String(64), unique=True, index=True, nullable=False)
    revoked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime, nullable=False)


class AuditLogModel(Base):
    """
    Structured security audit log table for SOC monitoring and administrator inspection.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    event = Column(String(64), nullable=False, index=True)
    analysis_id = Column(String(64), nullable=True, index=True)
    result = Column(String(32), nullable=False, index=True)
    details_json = Column(Text, nullable=True)
    ip_address = Column(String(64), nullable=True)

    # Relationships
    user = relationship("UserModel", backref="audit_logs", lazy="joined")

    __table_args__ = (
        Index("ix_audit_logs_event_timestamp", "event", "timestamp"),
        Index("ix_audit_logs_user_timestamp", "user_id", "timestamp"),
    )


class AnalystNoteModel(Base):
    """
    Analyst investigation notes, observations, case tags, and findings.
    """
    __tablename__ = "analyst_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    author_username = Column(String(64), nullable=False)
    content = Column(Text, nullable=False)
    tag = Column(String(32), nullable=False, default="OBSERVATION")  # OBSERVATION, IOC_CONFIRMED, MITIGATION_APPLIED, ESCALATION
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    sample = relationship("SampleModel", back_populates="notes")
    user = relationship("UserModel")


