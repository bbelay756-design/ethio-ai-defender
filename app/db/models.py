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
    Sample lifecycle states: NEW, QUEUED, ANALYZING, ANALYSIS_COMPLETE, ANALYST_REVIEW, CONFIRMED_SUSPICIOUS, ESCALATED, CLOSED, FAILED
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
    status = Column(String(32), nullable=False, default="NEW")  # NEW, QUEUED, ANALYZING, ANALYSIS_COMPLETE, ANALYST_REVIEW, CONFIRMED_SUSPICIOUS, ESCALATED, CLOSED, FAILED
    risk_score = Column(Integer, nullable=True, default=0)
    classification = Column(String(32), nullable=True, default="LOW")
    case_id = Column(String(64), nullable=True)
    case_status = Column(String(32), nullable=True, default="OPEN")  # OPEN, INVESTIGATING, CONTAINED, RESOLVED
    case_priority = Column(String(32), nullable=True, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime, nullable=True)

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
    ghidra_analysis = relationship("GhidraAnalysisModel", back_populates="sample", uselist=False, cascade="all, delete-orphan")
    ghidra_functions = relationship("GhidraFunctionModel", back_populates="sample", cascade="all, delete-orphan")
    ghidra_relationships = relationship("GhidraRelationshipModel", back_populates="sample", cascade="all, delete-orphan")
    organization = relationship("OrganizationModel", backref="samples")

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


class YaraRuleModel(Base):
    """
    Stable logical identity of a YARA rule (M02B, Phase 1).

    A rule row represents the *identity* (name/namespace); the authoritative
    rule source lives in immutable rows of YaraRuleVersionModel. The legacy
    mutable ``source``/``version`` columns are retained (mapped) for backward
    compatibility with pre-versioning data; new publications must write to
    ``yara_rule_versions`` instead. The legacy ``compiled`` BLOB column remains
    in the physical table but is deliberately not mapped (no compiled-artifact
    storage in this phase).
    """
    __tablename__ = "yara_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, nullable=False, index=True)
    namespace = Column(String(64), nullable=False, default="default", index=True)
    # Legacy mutable representation (pre-M02B). Kept for schema/data parity
    # with the existing table; new writes go to yara_rule_versions.
    source = Column(Text, nullable=False)  # LEGACY: authoritative source is YaraRuleVersionModel.source
    version = Column(Integer, nullable=False, default=1)  # LEGACY: superseded by yara_rule_versions.version
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    # Denormalized metadata mirroring the current published version
    description = Column(Text, nullable=True)
    author = Column(String(128), nullable=True)
    tags = Column(Text, nullable=True)  # JSON array
    # Pointer to the current published version (circular FK with
    # yara_rule_versions.rule_id; cleared via ON DELETE SET NULL).
    # use_alter=True marks the known circular dependency for SQLAlchemy's
    # table sorting (SQLite still emits the constraint inline in CREATE TABLE).
    current_version_id = Column(
        Integer, ForeignKey("yara_rule_versions.id", ondelete="SET NULL", use_alter=True),
        nullable=True,
    )
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships. Both directions declare foreign_keys explicitly because
    # two FK paths exist between yara_rules and yara_rule_versions
    # (rule -> current_version and version -> rule).
    current_version = relationship(
        "YaraRuleVersionModel",
        foreign_keys="YaraRuleModel.current_version_id",
        back_populates="current_for_rule",
        post_update=True,  # allows flushing the circular rule<->version pointer
    )
    versions = relationship(
        "YaraRuleVersionModel",
        foreign_keys="YaraRuleVersionModel.rule_id",
        back_populates="rule",
        order_by="YaraRuleVersionModel.version",
        cascade="all, delete-orphan",
    )


class YaraRuleVersionModel(Base):
    """
    Immutable published version of a YARA rule (M02B, Phase 1).

    Publication contract:
    - Rows are append-only. Once published (is_published=True), ``version``,
      ``source``, ``source_hash`` and the metadata snapshot must never be
      mutated; a changed rule is published as a NEW version row. The service
      layer (Phase 2) enforces this; the database guarantees uniqueness of
      (rule_id, version) pairs.
    - ``source`` is the authoritative rule text at publication time and
      ``source_hash`` its SHA-256 hex digest.
    - ``published_by``/``published_at`` record who published the version and
      when (unknown for versions seeded from pre-versioning legacy rows).
    - Published versions referenced by historical YaraMatchModel rows are
      protected from destructive deletion by the ON DELETE RESTRICT foreign
      key on yara_matches.rule_version_id.
    """
    __tablename__ = "yara_rule_versions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(Integer, ForeignKey("yara_rules.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    version = Column(Integer, nullable=False)  # monotonically increasing per rule
    source = Column(Text, nullable=False)  # authoritative rule source at publication
    source_hash = Column(String(64), nullable=False)  # SHA-256 of source (hex digest)
    # Metadata snapshot at publication time
    description = Column(Text, nullable=True)
    author = Column(String(128), nullable=True)
    tags = Column(Text, nullable=True)  # JSON array
    severity = Column(String(32), nullable=True)
    category = Column(String(64), nullable=True)
    # Publication metadata (NULL published_by = seeded from legacy data)
    published_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    published_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    is_published = Column(Boolean, nullable=False, default=True)  # False = draft

    # Relationships (foreign_keys explicit: two FK paths link the two tables)
    rule = relationship(
        "YaraRuleModel",
        foreign_keys="YaraRuleVersionModel.rule_id",
        back_populates="versions",
    )
    current_for_rule = relationship(
        "YaraRuleModel",
        foreign_keys="YaraRuleModel.current_version_id",
        back_populates="current_version",
        uselist=False,
    )
    # passive_deletes=True: the Session must NOT emulate SET NULL on delete
    # (which would silently destroy provenance pointers); the database-level
    # ON DELETE RESTRICT on yara_matches.rule_version_id is authoritative and
    # raises IntegrityError, preserving historical matches and versions.
    matches = relationship("YaraMatchModel", back_populates="rule_version",
                           passive_deletes=True)

    __table_args__ = (
        # Unique (rule_id, version) pairs enforced in the database.
        Index("ix_yara_rule_versions_rule_version", "rule_id", "version", unique=True),
    )


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
    
    # Version provenance. Nullable: legacy matches recorded before M02B keep
    # NULL (their exact historical version cannot be established - never
    # fabricate provenance). ON DELETE RESTRICT prevents destructive deletion
    # of published versions referenced by historical matches.
    rule_version_id = Column(Integer, ForeignKey("yara_rule_versions.id", ondelete="RESTRICT"),
                             nullable=True, index=True)

    # Relationship
    sample = relationship("SampleModel", back_populates="yara_matches")
    rule_version = relationship("YaraRuleVersionModel", back_populates="matches")


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


class GhidraAnalysisModel(Base):
    """
    Summary of a Ghidra headless reverse-engineering run for a sample.
    Structured results are stored independently from raw Ghidra project files.
    """
    __tablename__ = "ghidra_analysis"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    status = Column(String(32), nullable=False, default="SUCCESS")  # SUCCESS, UNAVAILABLE, DISABLED, FAILED, TIMEOUT
    message = Column(Text, nullable=True)
    program_name = Column(String(255), nullable=True)
    language_id = Column(String(64), nullable=True)
    processor = Column(String(64), nullable=True)
    compiler = Column(String(64), nullable=True)
    image_base = Column(String(32), nullable=True)
    entry_point = Column(String(32), nullable=True)
    function_count = Column(Integer, nullable=False, default=0)
    import_count = Column(Integer, nullable=False, default=0)
    export_count = Column(Integer, nullable=False, default=0)
    string_count = Column(Integer, nullable=False, default=0)
    relationship_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship
    sample = relationship("SampleModel", back_populates="ghidra_analysis")


class GhidraFunctionModel(Base):
    """
    Individual function recovered from the Ghidra program database for a sample.
    """
    __tablename__ = "ghidra_functions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    address = Column(String(32), nullable=True)
    size = Column(Integer, nullable=False, default=0)
    is_thunk = Column(Boolean, nullable=False, default=False)
    calling_convention = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship
    sample = relationship("SampleModel", back_populates="ghidra_functions")


class GhidraRelationshipModel(Base):
    """
    A call-graph edge recovered from the Ghidra program database for a sample,
    showing one function invoking another.
    """
    __tablename__ = "ghidra_relationships"

    id = Column(Integer, primary_key=True, autoincrement=True)
    sample_id = Column(Integer, ForeignKey("samples.id", ondelete="CASCADE"), nullable=False, index=True)
    from_address = Column(String(32), nullable=True)
    from_name = Column(String(255), nullable=True)
    to_address = Column(String(32), nullable=True)
    to_name = Column(String(255), nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship
    sample = relationship("SampleModel", back_populates="ghidra_relationships")


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
    role = Column(String(32), default="VIEWER", nullable=False)  # 'ADMIN', 'ANALYST', 'VIEWER'
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True)
    is_active = Column(Integer, default=1, nullable=False)  # 1 = active, 0 = inactive
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    token_version = Column(Integer, default=1, nullable=False)  # Incremented on password reset, role change, deactivation

    # Relationship
    organization = relationship("OrganizationModel", backref="users")


class RevokedTokenModel(Base):
    """
    Token blacklist model for secure logout and token invalidation.
    """
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_jti = Column(String(64), unique=True, index=True, nullable=False)
    revoked_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime, nullable=False)


class FailedLoginAttemptModel(Base):
    """
    Database-backed failed login attempt tracking for distributed rate limiting.
    Replaces in-memory rate limiter for multi-worker deployments.
    """
    __tablename__ = "failed_login_attempts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    identifier = Column(String(128), nullable=False, index=True)  # username:ip or ip
    attempt_count = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    last_attempt_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_failed_login_identifier", "identifier"),
    )


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


class OrganizationModel(Base):
    """
    Organization model for Ethiopian organizations.
    Supports configurable organization information including:
    - Name
    - Organization type
    - Sector
    - Region
    - City
    - Status
    - Created date
    """
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    org_type = Column(String(64), nullable=False)  # government, private, ngo, educational, healthcare, financial, ict, other
    sector = Column(String(128), nullable=True, index=True)
    region = Column(String(128), nullable=True)
    city = Column(String(128), nullable=True)
    status = Column(String(32), nullable=False, default="ACTIVE")  # ACTIVE, INACTIVE, SUSPENDED
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship to users (many-to-many through association table)
    # For now, we'll add org_id to UserModel

    __table_args__ = (
        Index("ix_organizations_sector_region", "sector", "region"),
        Index("ix_organizations_status", "status"),
    )


# Add org_id to UserModel (will need migration)
# This is a forward reference, actual column added via migration


