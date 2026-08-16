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
    type: str = Field("GENERAL", max_length=64)


class StringCreate(StringBase):
    pass


class StringRead(StringBase):
    id: int
    sample_id: int

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
# 6. Sample Schemas
# ----------------------------------------------------
class SampleBase(BaseModel):
    analysis_id: str = Field(..., max_length=64)
    filename: str = Field(..., max_length=255)
    size: int = Field(..., gt=0)
    file_type: str = Field("EXE", max_length=32)
    architecture: str = Field("x64", max_length=32)
    md5: str = Field(..., min_length=32, max_length=32)
    sha256: str = Field(..., min_length=64, max_length=64)
    status: str = Field("ANALYZED", max_length=32)


class SampleCreate(SampleBase):
    pass


class SampleRead(SampleBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SampleWithRelations(SampleRead):
    sections: List[SectionRead] = []
    imports: List[ImportRead] = []
    strings: List[StringRead] = []
    indicators: List[IndicatorRead] = []
    analysis_results: Optional[AnalysisResultRead] = None

    model_config = ConfigDict(from_attributes=True)
