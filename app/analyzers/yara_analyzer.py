"""
Module: YARA Static Signature & Rule Analyzer

Responsibility:
Performs static signature and rule matching against binary bytes using YARA rules.
Gracefully handles environments where yara-python is unavailable without failing.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any
from app.core.logger import logger
from app.core.config import BASE_DIR

# Optional import of yara-python
try:
    import yara
    HAS_YARA = True
except ImportError:
    yara = None
    HAS_YARA = False


@dataclass
class YaraMatchItem:
    """Represents a single YARA rule match."""
    rule_name: str
    namespace: str = "default"
    tags: List[str] = field(default_factory=list)
    description: str = ""
    severity: str = "MEDIUM"
    category: str = "GENERAL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "namespace": self.namespace,
            "tags": self.tags,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
        }


@dataclass
class YaraScanResult:
    """Outcome of the YARA scan."""
    available: bool = True
    status: str = "SUCCESS"  # 'SUCCESS', 'UNAVAILABLE', 'FAILED'
    message: str = "YARA scan completed."
    total_matches: int = 0
    matches: List[YaraMatchItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "status": self.status,
            "message": self.message,
            "total_matches": self.total_matches,
            "matches": [m.to_dict() for m in self.matches],
        }


class YaraAnalyzerService:
    """
    Service for loading and executing YARA rules against uploaded binaries.
    """

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or (BASE_DIR / "rules")
        self._compiled_rules = None
        self._has_yara = HAS_YARA

        if self._has_yara:
            self._compile_rules()

    def _compile_rules(self) -> None:
        """Compiles all .yar files located in the rules directory."""
        if not self._has_yara or not yara:
            return

        if not self.rules_dir.exists():
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            return

        rule_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))
        if not rule_files:
            logger.info("No YARA rule files found in rules directory.")
            return

        filepaths = {p.stem: str(p) for p in rule_files}
        try:
            self._compiled_rules = yara.compile(filepaths=filepaths)
            logger.info(f"Successfully compiled {len(rule_files)} YARA rule sets.")
        except Exception as e:
            logger.warning(f"Failed to compile YARA rules from {self.rules_dir}: {e}")
            self._compiled_rules = None

    def scan_bytes(self, content: bytes) -> YaraScanResult:
        """
        Executes YARA scan against byte content in memory without execution.
        """
        if not self._has_yara or yara is None:
            return YaraScanResult(
                available=False,
                status="UNAVAILABLE",
                message="YARA engine unavailable",
                total_matches=0,
                matches=[]
            )

        if self._compiled_rules is None:
            # Try recompiling in case rules were added
            self._compile_rules()

        if self._compiled_rules is None:
            return YaraScanResult(
                available=True,
                status="SUCCESS",
                message="YARA engine available (0 active rule sets compiled).",
                total_matches=0,
                matches=[]
            )

        try:
            raw_matches = self._compiled_rules.match(data=content)
            match_items: List[YaraMatchItem] = []

            for rm in raw_matches:
                meta = getattr(rm, "meta", {}) or {}
                match_items.append(YaraMatchItem(
                    rule_name=rm.rule,
                    namespace=getattr(rm, "namespace", "default") or "default",
                    tags=list(getattr(rm, "tags", [])) if hasattr(rm, "tags") else [],
                    description=meta.get("description", "Matched YARA rule pattern"),
                    severity=meta.get("severity", "MEDIUM"),
                    category=meta.get("category", "GENERAL"),
                ))

            return YaraScanResult(
                available=True,
                status="SUCCESS",
                message=f"YARA scan completed with {len(match_items)} match(es).",
                total_matches=len(match_items),
                matches=match_items
            )
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            return YaraScanResult(
                available=True,
                status="FAILED",
                message=f"YARA scan error: {str(e)}",
                total_matches=0,
                matches=[]
            )


# Global singleton instance
yara_analyzer_service = YaraAnalyzerService()
