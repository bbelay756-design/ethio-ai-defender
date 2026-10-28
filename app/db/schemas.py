"""
Pydantic Schemas for Database Validation and API Serialization

Validates incoming intake records and serializes database entities.
"""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ----------------------------------------------------
# 1. Section Schemas
# ----------------------------------------------------
class SectionBase(BaseModel):
    name: str = Field(..., max_length=64)
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float = Field(..., ge=0.0, le=8.0)
    characteristics: str = Field(..., max_length=64)


class SectionCreate(SectionBase):
    pass


class SectionRead(SectionBase):
    id: int
    sample_id: int

    model_config = ConfigDict(from_attributes=True)


# ----------------------------------------------------
# 2. Import Schemas
# ----------------------------------------------------
class ImportBase(BaseModel):
    dll: str = Field(..., max_length=128)
    api: str = Field(..., max_length=128)
    category: str = Field("GENERAL", max_length=64)
    risk_relevance: str = Field("LOW", max_length=32)


class ImportCreate(ImportBase):
    pass


class ImportRead(ImportBase):
    id: int
    sample_id: int

    model_config = ConfigDict(from_attributes=True)


# ----------------------------------------------------
# 3. String Schemas
# ----------------------------------------------------
class StringBase(BaseModel):
    value: str
    encoding: str = Field("ASCII", max_length=16)
    offset: Optional[int] = None
    category: str = Field("GENERAL", max_length=64)
    type: str = Field("GENERAL", max_length=64)
    suspicious: bool = False
    severity: str = Field("LOW", max_length=32)
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    reason: Optional[str] = None
    mitre_technique: Optional[str] = None


class StringCreate(StringBase):
    pass


class StringRead(StringBase):
    id: int
    sample_id: int
    offset_hex: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ----------------------------------------------------
# 4. Indicator Schemas
# ----------------------------------------------------
class IndicatorBase(BaseModel):
    name: str = Field(..., max_length=255)
    category: str = Field(..., max_length=64)
    severity: str = Field(..., max_length=32)
    evidence: str
    confidence: float = Field(1.0, ge=0.0, le=1.0)


class IndicatorCreate(IndicatorBase):
    pass


class IndicatorRead(IndicatorBase):
    id: int
    sample_id: int

    model_config = ConfigDict(from_attributes=True)


# ----------------------------------------------------
# 5. Analysis Result Schemas
# ----------------------------------------------------
class AnalysisResultBase(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str = Field(..., max_length=32)
    ai_summary: str
    ai_confidence: str = Field("MEDIUM", max_length=32)


class AnalysisResultCreate(AnalysisResultBase):
    pass


class AnalysisResultRead(AnalysisResultBase):
    id: int
    sample_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ----------------------------------------------------
# 6. IOC, YARA, and Risk Factor Schemas
# ----------------------------------------------------
class IOCCreate(BaseModel):
    type: str = Field(..., max_length=32)
    value: str
    source: str = Field("STATIC_ANALYSIS", max_length=64)
    confidence: float = Field(1.0, ge=0.0, le=1.0)


class IOCRead(IOCCreate):
    id: int
    sample_id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class YaraMatchCreate(BaseModel):
    rule_name: str = Field(..., max_length=128)
    namespace: str = Field("default", max_length=64)
    tags: Optional[str] = None
    description: Optional[str] = None
    rule_version_id: Optional[int] = None
    rule_id: Optional[int] = None  # Internal: exact DB rule identity for ownership validation


class YaraRuleCreate(BaseModel):
    """Schema for creating a stable rule identity (Phase 2 & Phase 3C)."""

    name: str = Field(..., max_length=255)
    namespace: str = Field("default", max_length=64)
    source: Optional[str] = Field(None, max_length=65535, description="YARA rule source text")
    description: Optional[str] = None
    author: Optional[str] = None
    tags: Optional[str] = None


class YaraRulePublish(BaseModel):
    """Schema for publishing a new immutable rule version (Phase 2 & Phase 3C)."""

    source: str = Field(..., max_length=65535, description="YARA rule source text")
    author: Optional[str] = None
    severity: Optional[str] = Field(None, max_length=32)
    category: Optional[str] = Field(None, max_length=64)
    tags: Optional[str] = None


class YaraRuleVersionRead(BaseModel):
    """Read schema for a published rule version."""

    id: int
    rule_id: Optional[int] = None
    version: int
    source_hash: str
    source: Optional[str] = None
    description: Optional[str] = None
    author: Optional[str] = None
    tags: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    published_by: Optional[int] = None
    published_at: datetime
    is_published: bool

    model_config = ConfigDict(from_attributes=True)


class YaraRuleRead(BaseModel):
    """Read schema for a stable YARA rule identity."""

    id: int
    name: str
    namespace: str
    is_active: bool
    description: Optional[str] = None
    author: Optional[str] = None
    tags: Optional[str] = None
    current_version_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    current_version: Optional[YaraRuleVersionRead] = None

    model_config = ConfigDict(from_attributes=True)


class YaraRuleListResponse(BaseModel):
    """Paginated list of YARA rules."""

    items: List[YaraRuleRead]
    total: int
    page: int
    page_size: int
    pages: int


class YaraRuleVersionListResponse(BaseModel):
    """Ordered version history for a YARA rule."""

    rule: YaraRuleRead
    versions: List[YaraRuleVersionRead]
    total_versions: int


class YaraMatchRead(YaraMatchCreate):
    id: int
    sample_id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class RiskFactorCreate(BaseModel):
    name: str = Field(..., max_length=255)
    category: str = Field(..., max_length=64)
    severity: str = Field(..., max_length=32)
    weight: float
    evidence: Optional[str] = None


class RiskFactorRead(RiskFactorCreate):
    id: int
    sample_id: int
    model_config = ConfigDict(from_attributes=True)


# ----------------------------------------------------
# 6b. Ghidra Headless Reverse-Engineering Schemas
# ----------------------------------------------------
class GhidraFunctionCreate(BaseModel):
    name: str = Field(..., max_length=255)
    address: Optional[str] = Field(None, max_length=32)
    size: int = 0
    is_thunk: bool = False
    calling_convention: Optional[str] = Field(None, max_length=64)


class GhidraFunctionRead(GhidraFunctionCreate):
    id: int
    sample_id: int
    model_config = ConfigDict(from_attributes=True)


class GhidraRelationshipCreate(BaseModel):
    from_address: Optional[str] = Field(None, max_length=32)
    from_name: Optional[str] = Field(None, max_length=255)
    to_address: Optional[str] = Field(None, max_length=32)
    to_name: Optional[str] = Field(None, max_length=255)


class GhidraRelationshipRead(GhidraRelationshipCreate):
    id: int
    sample_id: int
    model_config = ConfigDict(from_attributes=True)


class GhidraAnalysisCreate(BaseModel):
    status: str = Field("SUCCESS", max_length=32)
    message: Optional[str] = None
    program_name: Optional[str] = Field(None, max_length=255)
    language_id: Optional[str] = Field(None, max_length=64)
    processor: Optional[str] = Field(None, max_length=64)
    compiler: Optional[str] = Field(None, max_length=64)
    image_base: Optional[str] = Field(None, max_length=32)
    entry_point: Optional[str] = Field(None, max_length=32)
    function_count: int = 0
    import_count: int = 0
    export_count: int = 0
    string_count: int = 0
    relationship_count: int = 0


class GhidraAnalysisRead(GhidraAnalysisCreate):
    id: int
    sample_id: int
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


# ----------------------------------------------------
# 7. Sample Schemas
# ----------------------------------------------------
class SampleBase(BaseModel):
    analysis_id: str = Field(..., max_length=64)
    filename: str = Field(..., max_length=255)
    size: int = Field(..., gt=0)
    file_type: str = Field("EXE", max_length=32)
    architecture: str = Field("x64", max_length=32)
    md5: str = Field(..., min_length=32, max_length=32)
    sha1: Optional[str] = None
    sha256: str = Field(..., min_length=64, max_length=64)
    status: str = Field("COMPLETED", max_length=32)
    risk_score: Optional[int] = 0
    classification: Optional[str] = "LOW"
    user_id: Optional[int] = None


class SampleCreate(SampleBase):
    completed_at: Optional[datetime] = None


class SampleRead(SampleBase):
    id: int
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AnalysisSummaryResponse(BaseModel):
    """Clean API summary response for analysis listing."""
    id: int
    analysis_id: str
    filename: str
    size: int
    file_type: str
    architecture: str
    sha256: str
    sha1: Optional[str] = None
    md5: str
    status: str
    risk_score: int = 0
    classification: str = "LOW"
    created_at: Optional[str] = None
    completed_at: Optional[str] = None
    # Advisory Machine Learning Signal (Experimental / Non-Authoritative)
    ml_score: Optional[float] = None
    ml_status: Optional[str] = "UNAVAILABLE"
    ml_review_priority: Optional[str] = "NOT_EVALUATED"
    is_reliable: bool = False


class SampleWithRelations(SampleRead):
    sections: List[SectionRead] = []
    imports: List[ImportRead] = []
    strings: List[StringRead] = []
    indicators: List[IndicatorRead] = []
    iocs: List[IOCRead] = []
    yara_matches: List[YaraMatchRead] = []
    risk_factors: List[RiskFactorRead] = []
    analysis_results: Optional[AnalysisResultRead] = None
    ghidra_analysis: Optional[GhidraAnalysisRead] = None
    ghidra_functions: List[GhidraFunctionRead] = []
    ghidra_relationships: List[GhidraRelationshipRead] = []

    model_config = ConfigDict(from_attributes=True)
