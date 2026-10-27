"""
Module: YARA Static Signature & Rule Analyzer

Responsibility:
Performs static signature and rule matching against binary bytes using YARA rules.
Gracefully handles environments where yara-python is unavailable without failing.
"""

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Callable
from app.core.logger import logger
from app.core.config import BASE_DIR

# Optional import of yara-python
try:
    import yara
    HAS_YARA = True
except ImportError:
    yara = None
    HAS_YARA = False


@dataclass(frozen=True)
class SelectedYaraRule:
    """
    Immutable snapshot of an eligible DB-managed YARA rule and its published version,
    selected once per analysis to guarantee rule-selection consistency.
    """
    rule_id: int
    rule_name: str
    namespace: str
    version_id: int
    version_number: int
    source_hash: str
    source: str


@dataclass
class YaraMatchItem:
    """Represents a single YARA rule match."""
    rule_name: str
    namespace: str = "default"
    tags: List[str] = field(default_factory=list)
    description: str = ""
    severity: str = "MEDIUM"
    category: str = "GENERAL"
    rule_version_id: Optional[int] = None
    rule_id: Optional[int] = None  # Exact DB rule identity for ownership validation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "namespace": self.namespace,
            "tags": self.tags,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "rule_version_id": self.rule_version_id,
            "rule_id": self.rule_id,
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
        # Version-keyed compilation cache: {(rule_id, version_id, source_hash): compiled_rule}
        self._version_cache: Dict[Tuple[int, int, str], Any] = {}
        # Optional synchronization/test hook called immediately after per-analysis rule selection
        self.post_selection_hook: Optional[Callable[[List[SelectedYaraRule]], None]] = None

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

    def select_active_rules(self, db) -> List[SelectedYaraRule]:
        """
        Atomically selects eligible active rules and their current published versions once.
        Returns immutable SelectedYaraRule snapshots to ensure consistency during the analysis.
        """
        if db is None:
            return []
        try:
            from app.db.models import YaraRuleModel, YaraRuleVersionModel
            rows = (
                db.query(YaraRuleModel, YaraRuleVersionModel)
                .join(
                    YaraRuleVersionModel,
                    (YaraRuleVersionModel.id == YaraRuleModel.current_version_id)
                    & (YaraRuleVersionModel.rule_id == YaraRuleModel.id),
                )
                .filter(
                    YaraRuleModel.is_active == True,
                    YaraRuleModel.current_version_id.isnot(None),
                    YaraRuleVersionModel.is_published == True,
                )
                .all()
            )
            return [
                SelectedYaraRule(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    namespace=rule.namespace or "default",
                    version_id=version.id,
                    version_number=version.version,
                    source_hash=version.source_hash,
                    source=version.source,
                )
                for rule, version in rows
            ]
        except Exception as e:
            logger.warning(f"Error querying active YARA rules from DB: {e}")
            return []

    def scan_bytes_with_db_rules(
        self,
        content: bytes,
        db=None,
        selected_rules: Optional[List[SelectedYaraRule]] = None,
        post_selection_hook: Optional[Callable[[List[SelectedYaraRule]], None]] = None,
    ) -> YaraScanResult:
        """
        Scan using database-managed rules (active rules with valid current versions).
        Rules are selected once (or passed via selected_rules) and held immutable
        throughout the scan to ensure version-selection consistency.
        Falls back to filesystem scan if db is None or no DB rules exist.
        """
        if not self._has_yara or yara is None:
            return YaraScanResult(
                available=False,
                status="UNAVAILABLE",
                message="YARA engine unavailable",
                total_matches=0,
                matches=[],
            )

        if db is None and selected_rules is None:
            # Fall back to filesystem scan
            return self.scan_bytes(content)

        try:
            # 1. Establish rule selection once if not pre-selected
            if selected_rules is None:
                selected_rules = self.select_active_rules(db)

            # 2. Trigger test/synchronization hook if present
            hook = post_selection_hook or self.post_selection_hook
            if hook is not None:
                hook(selected_rules)

            # 3. Compile and scan selected DB-managed rules
            match_items: List[YaraMatchItem] = []
            db_rule_keys: set = set()

            for s_rule in selected_rules:
                db_rule_keys.add((s_rule.rule_name, s_rule.namespace))
                cache_key = (s_rule.rule_id, s_rule.version_id, s_rule.source_hash)
                compiled = self._version_cache.get(cache_key)

                if compiled is None:
                    # Check source hash against exact compilation bytes with publication normalization
                    normalized_source = s_rule.source.strip() if s_rule.source else ""
                    computed_hash = hashlib.sha256(normalized_source.encode("utf-8")).hexdigest()
                    if computed_hash != s_rule.source_hash:
                        logger.warning(
                            f"Source hash mismatch for rule {s_rule.rule_name} v{s_rule.version_number}: "
                            f"expected {s_rule.source_hash}, computed {computed_hash}. Skipping compilation."
                        )
                        continue

                    try:
                        compiled = yara.compile(source=normalized_source)
                        self._version_cache[cache_key] = compiled
                    except Exception as e:
                        logger.warning(
                            f"Failed to compile rule {s_rule.rule_name} v{s_rule.version_number}: {e}"
                        )
                        continue

                try:
                    raw_matches = compiled.match(data=content)
                    for rm in raw_matches:
                        meta = getattr(rm, "meta", {}) or {}
                        match_items.append(
                            YaraMatchItem(
                                rule_name=rm.rule if hasattr(rm, "rule") else s_rule.rule_name,
                                namespace=s_rule.namespace,
                                tags=list(getattr(rm, "tags", [])) if hasattr(rm, "tags") else [],
                                description=meta.get("description", "Matched YARA rule pattern"),
                                severity=meta.get("severity", "MEDIUM"),
                                category=meta.get("category", "GENERAL"),
                                rule_version_id=s_rule.version_id,
                                rule_id=s_rule.rule_id,
                            )
                        )
                except Exception as e:
                    logger.warning(f"YARA scan error for rule {s_rule.rule_name}: {e}")

            # 4. Scan filesystem rules that are NOT managed by DB
            # Deduplicate by (name, namespace) - only scan if no DB rule with same key
            if self.rules_dir.exists():
                fs_rule_files = list(self.rules_dir.glob("*.yar")) + list(
                    self.rules_dir.glob("*.yara")
                )
                fs_to_scan = []
                for p in fs_rule_files:
                    if (p.stem, "default") not in db_rule_keys:
                        fs_to_scan.append(p)

                if fs_to_scan:
                    filepaths = {p.stem: str(p) for p in fs_to_scan}
                    try:
                        fs_compiled = yara.compile(filepaths=filepaths)
                        raw_matches = fs_compiled.match(data=content)
                        for rm in raw_matches:
                            meta = getattr(rm, "meta", {}) or {}
                            match_items.append(
                                YaraMatchItem(
                                    rule_name=rm.rule,
                                    namespace=getattr(rm, "namespace", "default") or "default",
                                    tags=list(getattr(rm, "tags", [])) if hasattr(rm, "tags") else [],
                                    description=meta.get("description", "Matched YARA rule pattern"),
                                    severity=meta.get("severity", "MEDIUM"),
                                    category=meta.get("category", "GENERAL"),
                                    rule_version_id=None,  # filesystem-only: no version provenance
                                    rule_id=None,
                                )
                            )
                    except Exception as e:
                        logger.warning(f"Filesystem YARA scan error: {e}")

            if not selected_rules and not (
                self.rules_dir.exists()
                and (any(self.rules_dir.glob("*.yar")) or any(self.rules_dir.glob("*.yara")))
            ):
                # No rules at all
                return YaraScanResult(
                    available=True,
                    status="SUCCESS",
                    message="YARA engine available (0 active rule sets compiled).",
                    total_matches=0,
                    matches=[],
                )

            return YaraScanResult(
                available=True,
                status="SUCCESS",
                message=f"YARA scan completed with {len(match_items)} match(es).",
                total_matches=len(match_items),
                matches=match_items,
            )
        except Exception as e:
            logger.error(f"DB-driven YARA scan error: {e}")
            return self.scan_bytes(content)


# Global singleton instance
yara_analyzer_service = YaraAnalyzerService()
