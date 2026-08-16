"""
Module 08: Suspicious Indicator Engine

Responsibility:
Correlates static findings from PE structure, sections, entropy, strings, and API imports
to produce explainable, evidence-backed security indicators.

Categories:
- PE_STRUCTURE        : Section permissions, header anomalies, entry point abnormalities
- PACKING             : High entropy + raw/virtual discrepancies, packed section names
- OBFUSCATION         : Anti-debugging APIs, encoded strings, obfuscated constructs
- NETWORK             : Embedded URLs/IPs/domains correlated with network socket/HTTP APIs
- PROCESS             : Process manipulation, termination, and process injection primitives
- MEMORY              : Dynamic memory allocation, permission changes, and remote writes
- FILE_ACTIVITY       : Temporary directory staging, dropper artifacts, file modifications
- REGISTRY            : Registry keys, querying, and system setting modifications
- PERSISTENCE         : Autostart Run keys, Windows service installation, scheduled tasks
- COMMAND_EXECUTION   : Command-line (cmd.exe) and PowerShell execution primitives

Key Scientific Principles:
- Prefer correlated multi-factor evidence over single-feature triggers.
- Never claim runtime behavior from static evidence.
- Detection rules are modular and configurable.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Any, Callable, Set

from app.core.logger import logger
from app.analyzers.pe_analyzer import PEAnalysisResult
from app.analyzers.section_analyzer import PESectionAnalysisResult
from app.analyzers.entropy_analyzer import EntropyAnalysisResult
from app.analyzers.string_analyzer import StringAnalysisResult
from app.analyzers.import_analyzer import ImportAnalysisResult


@dataclass
class SuspiciousIndicator:
    """
    Explainable static security indicator backed by correlated evidence.
    """
    id: str
    name: str
    category: str
    severity: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    evidence: str
    confidence: float  # 0.0 to 1.0
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        """Returns the exact Module 08 JSON schema contract."""
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "evidence": self.evidence,
            "confidence": round(self.confidence, 2),
            "explanation": self.explanation,
        }


@dataclass
class IndicatorAnalysisResult:
    """
    Aggregated outcome of the Suspicious Indicator Engine.
    """
    total_indicators: int = 0
    high_severity_count: int = 0
    categories_present: List[str] = field(default_factory=list)
    indicators: List[SuspiciousIndicator] = field(default_factory=list)
    is_valid: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns the structured indicators report."""
        return {
            "total_indicators": self.total_indicators,
            "high_severity_count": self.high_severity_count,
            "categories_present": self.categories_present,
            "indicators": [ind.to_dict() for ind in self.indicators],
        }


@dataclass
class AnalysisContext:
    """
    Consolidated static context passed to indicator rules.
    """
    pe: Optional[PEAnalysisResult] = None
    sections: Optional[PESectionAnalysisResult] = None
    entropy: Optional[EntropyAnalysisResult] = None
    strings: Optional[StringAnalysisResult] = None
    imports: Optional[ImportAnalysisResult] = None

    # Helper lookup sets
    imported_apis: Set[str] = field(default_factory=set)
    imported_dlls: Set[str] = field(default_factory=set)

    def __post_init__(self):
        if self.imports and self.imports.imports:
            self.imported_apis = {imp.api.lower() for imp in self.imports.imports}
            self.imported_dlls = {imp.dll.lower() for imp in self.imports.imports}

    def has_api(self, *api_names: str) -> bool:
        """Checks if any of the provided API names are present in imports."""
        return any(a.lower() in self.imported_apis for a in api_names)

    def has_all_apis(self, *api_names: str) -> bool:
        """Checks if all of the provided API names are present in imports."""
        return all(a.lower() in self.imported_apis for a in api_names)


class SuspiciousIndicatorEngine:
    """
    Multi-Feature Correlation and Explainable Indicator Detection Engine.
    """

    def __init__(self):
        self.rules: List[Callable[[AnalysisContext], Optional[SuspiciousIndicator]]] = []
        self._register_default_rules()

    def register_rule(self, rule_func: Callable[[AnalysisContext], Optional[SuspiciousIndicator]]) -> None:
        """Registers a custom indicator correlation rule."""
        self.rules.append(rule_func)

    def _register_default_rules(self) -> None:
        """Registers the standard 10 correlated detection rules."""

        # 1. Category: PE_STRUCTURE
        def rule_wx_sections(ctx: AnalysisContext) -> Optional[SuspiciousIndicator]:
            if ctx.sections and ctx.sections.has_wx_sections:
                wx_names = [s.name for s in ctx.sections.sections if s.writable and s.executable]
                return SuspiciousIndicator(
                    id="IND-STR-001",
                    name="Writable and Executable (W+X) Section Detected",
                    category="PE_STRUCTURE",
                    severity="HIGH",
                    evidence=f"Section(s) with simultaneous W+X permissions: {', '.join(wx_names)}",
                    confidence=0.90,
                    explanation="PE section memory headers violate standard W^X defensive policies by granting simultaneous write and execute rights."
                )
            return None

        # 2. Category: PACKING
        def rule_packing_and_expansion(ctx: AnalysisContext) -> Optional[SuspiciousIndicator]:
            high_entropy_secs = []
            zero_raw_secs = []
            if ctx.entropy and ctx.entropy.sections:
                high_entropy_secs = [s.name for s in ctx.entropy.sections if s.classification in ("HIGH", "VERY_HIGH")]
            if ctx.sections and ctx.sections.sections:
                zero_raw_secs = [s.name for s in ctx.sections.sections if s.raw_size == 0 and s.virtual_size > 0]

            if high_entropy_secs and (zero_raw_secs or (ctx.entropy and ctx.entropy.file_entropy > 7.0)):
                return SuspiciousIndicator(
                    id="IND-PAK-001",
                    name="Correlated Code Packing / Compressed Staging Anomaly",
                    category="PACKING",
                    severity="HIGH",
                    evidence=f"High entropy sections: {high_entropy_secs}; Zero-raw size allocations: {zero_raw_secs}",
                    confidence=0.88,
                    explanation="Elevated entropy combined with virtual/raw size discrepancy indicates static code compression, packing, or encrypted payload staging."
                )
            return None

        # 3. Category: MEMORY
        def rule_memory_injection_staging(ctx: AnalysisContext) -> Optional[SuspiciousIndicator]:
            has_alloc = ctx.has_api("VirtualAlloc", "VirtualAllocEx")
            has_protect = ctx.has_api("VirtualProtect", "VirtualProtectEx")
            has_write = ctx.has_api("WriteProcessMemory")

            if (has_alloc and has_protect) or (has_alloc and has_write):
                evidence_list = []
                if has_alloc: evidence_list.append("VirtualAlloc/Ex")
                if has_protect: evidence_list.append("VirtualProtect/Ex")
                if has_write: evidence_list.append("WriteProcessMemory")

                # Higher severity if correlated with anomalous sections or thread injection
                is_cross_proc = ctx.has_api("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread")
                sev = "HIGH" if is_cross_proc else "MEDIUM"
                conf = 0.85 if is_cross_proc else 0.75

                return SuspiciousIndicator(
                    id="IND-MEM-001",
                    name="Correlated Dynamic Memory Allocation and Protection Modification",
                    category="MEMORY",
                    severity=sev,
                    evidence=f"Imported memory APIs: {', '.join(evidence_list)}",
                    confidence=conf,
                    explanation="Static evidence shows capabilities to allocate virtual memory and modify page execution permissions, frequently utilized for dynamic code staging or in-memory injection."
                )
            return None

        # 4. Category: PROCESS
        def rule_process_injection(ctx: AnalysisContext) -> Optional[SuspiciousIndicator]:
            has_proc = ctx.has_api("OpenProcess", "CreateProcessA", "CreateProcessW")
            has_thread = ctx.has_api("CreateRemoteThread", "SetThreadContext", "QueueUserAPC")

            if has_proc and has_thread:
                evidence_apis = []
                if ctx.has_api("OpenProcess"): evidence_apis.append("OpenProcess")
                if ctx.has_api("CreateRemoteThread"): evidence_apis.append("CreateRemoteThread")
                if ctx.has_api("SetThreadContext"): evidence_apis.append("SetThreadContext")
                if ctx.has_api("QueueUserAPC"): evidence_apis.append("QueueUserAPC")

                return SuspiciousIndicator(
                    id="IND-PROC-001",
                    name="Correlated Inter-Process Manipulation and Thread Injection",
                    category="PROCESS",
                    severity="HIGH",
                    evidence=f"Correlated process & thread injection APIs: {', '.join(evidence_apis)}",
                    confidence=0.88,
                    explanation="Binary statically references both process access and remote thread execution APIs, establishing structural primitives for inter-process injection."
                )
            return None

        # 5. Category: NETWORK
        def rule_network_communication(ctx: AnalysisContext) -> Optional[SuspiciousIndicator]:
            has_net_apis = ctx.has_api("InternetOpenA", "InternetOpenUrlA", "URLDownloadToFileA", "connect", "HttpSendRequestA", "socket")
            has_net_strings = bool(ctx.strings and (ctx.strings.urls or ctx.strings.ip_addresses))

            if has_net_apis and has_net_strings:
                endpoints = []
                if ctx.strings and ctx.strings.urls: endpoints.extend(ctx.strings.urls[:3])
                if ctx.strings and ctx.strings.ip_addresses: endpoints.extend(ctx.strings.ip_addresses[:3])

                sev = "HIGH" if ctx.has_api("URLDownloadToFileA", "URLDownloadToFileW") else "MEDIUM"

                return SuspiciousIndicator(
                    id="IND-NET-001",
                    name="Correlated Remote Network Endpoints and Communication APIs",
                    category="NETWORK",
                    severity=sev,
                    evidence=f"Identified endpoints: {endpoints}; Active Network APIs present in Import Table",
                    confidence=0.82,
                    explanation="Static artifacts contain embedded remote network locations correlated with active network communication and download APIs."
                )
            return None

        # 6. Category: PERSISTENCE
        def rule_host_persistence(ctx: AnalysisContext) -> Optional[SuspiciousIndicator]:
            has_run_keys = False
            if ctx.strings and ctx.strings.registry_paths:
                has_run_keys = any("CurrentVersion\\Run" in r or "RunOnce" in r for r in ctx.strings.registry_paths)

            has_reg_write = ctx.has_api("RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW")
            has_service_create = ctx.has_api("CreateServiceA", "CreateServiceW")

            if (has_run_keys and has_reg_write) or has_service_create:
                evidence = []
                if has_run_keys: evidence.append("Registry Run/RunOnce path strings")
                if has_reg_write: evidence.append("RegSetValueEx/RegCreateKeyEx")
                if has_service_create: evidence.append("CreateService API")

                return SuspiciousIndicator(
                    id="IND-PER-001",
                    name="Correlated Host Persistence via Autostart Registry or Service Creation",
                    category="PERSISTENCE",
                    severity="HIGH",
                    evidence=f"Persistence indicators: {', '.join(evidence)}",
                    confidence=0.86,
                    explanation="Presence of autostart registry paths paired with registry write APIs or service creation functions indicates capability to maintain persistent execution across reboots."
                )
            return None

        # 7. Category: COMMAND_EXECUTION
        def rule_command_interpreter(ctx: AnalysisContext) -> Optional[SuspiciousIndicator]:
            has_cmd_strings = bool(ctx.strings and (ctx.strings.commands or ctx.strings.powershell_references))
            has_exec_api = ctx.has_api("WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW")

            if has_cmd_strings and has_exec_api:
                cmd_sample = []
                if ctx.strings and ctx.strings.commands: cmd_sample.extend(ctx.strings.commands[:2])
                if ctx.strings and ctx.strings.powershell_references: cmd_sample.extend(ctx.strings.powershell_references[:2])

                return SuspiciousIndicator(
                    id="IND-CMD-001",
                    name="Correlated Script and Command Interpreter Execution",
                    category="COMMAND_EXECUTION",
                    severity="HIGH",
                    evidence=f"Extracted command references: {cmd_sample}; Process execution APIs present",
                    confidence=0.84,
                    explanation="Binary contains command-line (cmd.exe/PowerShell) strings paired with system process execution APIs, indicating capability to spawn auxiliary shell commands."
                )
            return None

        # 8. Category: OBFUSCATION
        def rule_anti_analysis_debugger(ctx: AnalysisContext) -> Optional[SuspiciousIndicator]:
            has_debug = ctx.has_api("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA")
            has_dense = bool(ctx.entropy and ctx.entropy.file_entropy > 6.5)

            if has_debug and has_dense:
                return SuspiciousIndicator(
                    id="IND-OBF-001",
                    name="Correlated Anti-Analysis & Debugger Detection Primitives",
                    category="OBFUSCATION",
                    severity="MEDIUM",
                    evidence="Anti-debugging APIs (IsDebuggerPresent/CheckRemoteDebuggerPresent) paired with high data entropy",
                    confidence=0.78,
                    explanation="Binary references host debugger detection functions in combination with dense data structures, indicating anti-analysis or inspection evasion capabilities."
                )
            return None

        # 9. Category: FILE_ACTIVITY
        def rule_file_activity_staging(ctx: AnalysisContext) -> Optional[SuspiciousIndicator]:
            has_file_api = ctx.has_api("CreateFileA", "CreateFileW", "WriteFile", "DeleteFileA")
            has_temp_path = False
            if ctx.strings and ctx.strings.file_paths:
                has_temp_path = any("temp" in p.lower() or "%appdata%" in p.lower() for p in ctx.strings.file_paths)
            if ctx.has_api("GetTempPathA", "GetTempPathW"):
                has_temp_path = True

            if has_file_api and has_temp_path:
                return SuspiciousIndicator(
                    id="IND-FIL-001",
                    name="Correlated Temporary File Activity & Staging Artifacts",
                    category="FILE_ACTIVITY",
                    severity="LOW",
                    evidence="File I/O APIs (CreateFile/WriteFile) correlated with temporary folder paths",
                    confidence=0.70,
                    explanation="Static evidence shows file write and deletion capabilities paired with temporary directory targets."
                )
            return None

        # 10. Category: REGISTRY
        def rule_registry_inspection(ctx: AnalysisContext) -> Optional[SuspiciousIndicator]:
            has_reg_api = ctx.has_api("RegOpenKeyExA", "RegOpenKeyExW", "RegQueryValueExA", "RegQueryValueExW")
            has_reg_strings = bool(ctx.strings and ctx.strings.registry_paths)

            if has_reg_api and has_reg_strings:
                sample_keys = ctx.strings.registry_paths[:2] if ctx.strings else []
                return SuspiciousIndicator(
                    id="IND-REG-001",
                    name="Correlated System Registry Querying & Inspection",
                    category="REGISTRY",
                    severity="LOW",
                    evidence=f"Registry query APIs correlated with target registry keys: {sample_keys}",
                    confidence=0.68,
                    explanation="Static evidence indicates capabilities to query and inspect Windows system registry configuration keys."
                )
            return None

        # Register all rules in order
        self.rules = [
            rule_wx_sections,
            rule_packing_and_expansion,
            rule_memory_injection_staging,
            rule_process_injection,
            rule_network_communication,
            rule_host_persistence,
            rule_command_interpreter,
            rule_anti_analysis_debugger,
            rule_file_activity_staging,
            rule_registry_inspection,
        ]

    def evaluate(
        self,
        pe: Optional[PEAnalysisResult] = None,
        sections: Optional[PESectionAnalysisResult] = None,
        entropy: Optional[EntropyAnalysisResult] = None,
        strings: Optional[StringAnalysisResult] = None,
        imports: Optional[ImportAnalysisResult] = None
    ) -> IndicatorAnalysisResult:
        """
        Evaluates registered correlation rules across all static analysis modules.
        """
        ctx = AnalysisContext(
            pe=pe,
            sections=sections,
            entropy=entropy,
            strings=strings,
            imports=imports
        )

        indicators: List[SuspiciousIndicator] = []
        categories_set: Set[str] = set()
        high_severity = 0

        for rule in self.rules:
            try:
                ind = rule(ctx)
                if ind:
                    indicators.append(ind)
                    categories_set.add(ind.category)
                    if ind.severity in ("HIGH", "CRITICAL"):
                        high_severity += 1
            except Exception as e:
                logger.warning(f"Error evaluating indicator rule {rule.__name__}: {e}")

        return IndicatorAnalysisResult(
            total_indicators=len(indicators),
            high_severity_count=high_severity,
            categories_present=sorted(list(categories_set)),
            indicators=indicators,
            is_valid=True,
            error_message=None
        )


# Global singleton instance
suspicious_indicator_engine_service = SuspiciousIndicatorEngine()


if __name__ == "__main__":
    import json

    print("=" * 68)
    print("  ETHIO-AI Defender - Module 08: Suspicious Indicator Engine Demo")
    print("=" * 68)

    engine = SuspiciousIndicatorEngine()
    print(f"Total Configured Indicator Rules: {len(engine.rules)}")
    print("=" * 68)
