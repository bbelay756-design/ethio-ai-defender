"""
Unified Analysis Models and Data Structures for ETHIO-AI Defender Module 19.
Provides strict typing and dual-interface list wrappers for seamless JSON serialization and dictionary access.
"""

from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class AnalysisSectionList(list):
    """
    Dual-interface section collection.
    Behaves as a standard Python/JSON list `[]` while supporting dictionary key lookups.
    """
    def __init__(
        self,
        items: Optional[List[Dict[str, Any]]] = None,
        total_sections: int = 0,
        has_wx_sections: bool = False,
        status: str = "SUCCESS",
        error_code: Optional[str] = None
    ):
        super().__init__(items or [])
        self.total_sections = total_sections if total_sections else len(self)
        self.has_wx_sections = has_wx_sections
        self.status = status
        self.error_code = error_code

    def __getitem__(self, item):
        if isinstance(item, str):
            if item == "total_sections":
                return self.total_sections
            if item == "has_wx_sections":
                return self.has_wx_sections
            if item == "sections":
                return list(self)
            if item == "status":
                return self.status
            if item == "error_code":
                return self.error_code
            raise KeyError(f"Invalid section dictionary key: {item}")
        return super().__getitem__(item)

    def __contains__(self, item):
        if isinstance(item, str) and item in ("total_sections", "has_wx_sections", "sections", "status", "error_code"):
            return True
        return super().__contains__(item)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default


class AnalysisImportList(list):
    """
    Dual-interface import collection.
    Behaves as a standard Python/JSON list `[]` while supporting dictionary key lookups.
    """
    def __init__(
        self,
        items: Optional[List[Dict[str, Any]]] = None,
        total_imports: int = 0,
        status: str = "SUCCESS",
        error_code: Optional[str] = None
    ):
        super().__init__(items or [])
        self.total_imports = total_imports if total_imports else len(self)
        self.status = status
        self.error_code = error_code

    def __getitem__(self, item):
        if isinstance(item, str):
            if item == "total_imports":
                return self.total_imports
            if item == "imports":
                return list(self)
            if item == "status":
                return self.status
            if item == "error_code":
                return self.error_code
            raise KeyError(f"Invalid import dictionary key: {item}")
        return super().__getitem__(item)

    def __contains__(self, item):
        if isinstance(item, str) and item in ("total_imports", "imports", "status", "error_code"):
            return True
        return super().__contains__(item)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default


class AnalysisIndicatorList(list):
    """
    Dual-interface indicator collection.
    Behaves as a standard Python/JSON list `[]` while supporting dictionary key lookups.
    """
    def __init__(
        self,
        items: Optional[List[Dict[str, Any]]] = None,
        total_indicators: int = 0,
        status: str = "SUCCESS",
        error_code: Optional[str] = None
    ):
        super().__init__(items or [])
        self.total_indicators = total_indicators if total_indicators else len(self)
        self.status = status
        self.error_code = error_code

    def __getitem__(self, item):
        if isinstance(item, str):
            if item == "total_indicators":
                return self.total_indicators
            if item == "indicators":
                return list(self)
            if item == "status":
                return self.status
            if item == "error_code":
                return self.error_code
            raise KeyError(f"Invalid indicator dictionary key: {item}")
        return super().__getitem__(item)

    def __contains__(self, item):
        if isinstance(item, str) and item in ("total_indicators", "indicators", "status", "error_code"):
            return True
        return super().__contains__(item)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default


class UnifiedAnalysisResult(BaseModel):
    """
    Module 19 Unified Analysis Object Specification.
    Strictly encapsulates all static evidence, rule-based indicators, AI assessment, and error logs.
    """
    schema_version: str = "1.0"
    analysis_id: str
    status: str = "COMPLETED"  # 'COMPLETED', 'PARTIAL', 'FAILED'
    file: Dict[str, Any] = Field(default_factory=dict)
    hashes: Dict[str, str] = Field(default_factory=dict)
    pe: Dict[str, Any] = Field(default_factory=dict)
    sections: List[Dict[str, Any]] = Field(default_factory=list)
    entropy: Dict[str, Any] = Field(default_factory=dict)
    strings: Dict[str, Any] = Field(default_factory=dict)
    imports: List[Dict[str, Any]] = Field(default_factory=list)
    indicators: List[Dict[str, Any]] = Field(default_factory=list)
    risk: Dict[str, Any] = Field(default_factory=dict)
    risk_score: Dict[str, Any] = Field(default_factory=dict)
    ethiopian_context: Dict[str, Any] = Field(default_factory=dict)
    ai_assessment: Dict[str, Any] = Field(default_factory=dict)
    report: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}
