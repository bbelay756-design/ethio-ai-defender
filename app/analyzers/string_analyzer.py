"""
Module 06: String Analyzer & Intelligence Engine

Responsibility:
Performs static string extraction, forensic categorization, and suspicious indicator
detection on binary byte sequences without runtime execution.

Extracts:
1. ASCII string sequences ([\x20-\x7E]{min_length,})
2. UTF-16LE / Unicode string sequences ((?:[\x20-\x7E]\x00){min_length,})

Categorizes strings into standard intelligence categories:
- URL: Web and network URLs (http, https, ftp)
- DOMAIN: Internet domain hostnames
- IP_ADDRESS: IPv4 addresses
- EMAIL: Email addresses
- REGISTRY: Windows Registry keys and persistence paths
- FILE_PATH: Windows file and directory paths
- COMMAND: Operating system CLI commands (whoami, net user, vssadmin, etc.)
- POWERSHELL: PowerShell cmdlets, scripts, and execution arguments
- CMD: Windows Command Prompt execution strings (cmd.exe /c, etc.)
- SCRIPT: Scripting host artifacts (.ps1, .vbs, .js, .bat, cscript, mshta)
- DLL: Dynamic Link Library module names
- API: Critical Windows system APIs (VirtualAlloc, CreateRemoteThread, etc.)
- SUSPICIOUS: High-risk security keywords (mimikatz, credential dumping, etc.)
- GENERAL: Clean application metadata and printable text

Safety & Educational Principles:
- Strictly static in-memory inspection; NEVER executes discovered strings or commands.
- Objective defensive classification: Suspicious strings are flagged as "Suspicious indicators",
  not confirmed malware, maintaining strict analytical discipline.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.logger import logger


# ============================================================================
# EXTRACTION REGULAR EXPRESSIONS
# ============================================================================
ASCII_STRING_REGEX = re.compile(rb"[\x20-\x7E]{4,}")
UNICODE_STRING_REGEX = re.compile(rb"(?:[\x20-\x7E]\x00){4,}")

# Classification Patterns
URL_PATTERN = re.compile(r"\b(?:https?|ftp)://[A-Za-z0-9\-_.]+(?::\d+)?(?:/[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"\b(?!(?:https?|ftp)://)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:com|org|net|edu|gov|io|et|info|biz|co|cc|tv|ru|cn|xyz|top|site|online|mil)\b", re.IGNORECASE)
REGISTRY_PATTERN = re.compile(r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|Software\\Microsoft\\Windows\\CurrentVersion)\\[A-Za-z0-9_\\\-.\s]+", re.IGNORECASE)
FILE_PATH_PATTERN = re.compile(r"(?:[a-zA-Z]:\\(?:[A-Za-z0-9_\-\s.]+\\?)+|\\\\[A-Za-z0-9_\-]+\\(?:[A-Za-z0-9_\-\s.]+\\?)+|%[A-Za-z0-9_]+%\\(?:[A-Za-z0-9_\-\s.]+\\?)+)", re.IGNORECASE)
POWERSHELL_PATTERN = re.compile(r"(?:powershell(?:\.exe)?|Invoke-Expression|\bIEX\b|DownloadString|DownloadFile|Set-ExecutionPolicy|\bBypass\b|-enc\b|-encodedcommand|-nop\b|-noprofile\b|Add-MpPreference)", re.IGNORECASE)
CMD_PATTERN = re.compile(r"(?:cmd(?:\.exe)?\s+(?:\/c|\/k)|\bcmd\s+(?:\/c|\/k))", re.IGNORECASE)
COMMAND_PATTERN = re.compile(r"(?:cmd(?:\.exe)?\s+(?:\/c|\/k)|\bnet\s+(?:user|localgroup|share|use|stop|start)\b|\bvssadmin(?:\.exe)?\b|\bwhoami(?:\.exe)?\b|\bipconfig(?:\.exe)?\b|\btaskkill(?:\.exe)?\b|\breg(?:\.exe)?\s+(?:add|delete|query)\b|\bschtasks(?:\.exe)?\b|\battrib\s+[+\-][rhsa]\b|\bcertutil(?:\.exe)?\s+(?:-urlcache|-decode|-f)\b|\brundll32(?:\.exe)?\b)", re.IGNORECASE)
SCRIPT_PATTERN = re.compile(r"\b[A-Za-z0-9_\-.]+\.(?:ps1|vbs|vbe|js|jse|bat|cmd|wsh|wsf)\b|\b(?:cscript|wscript|mshta)(?:\.exe)?\b", re.IGNORECASE)
DLL_PATTERN = re.compile(r"\b[A-Za-z0-9_\-.]+\.dll\b", re.IGNORECASE)
SUSPICIOUS_KEYWORD_PATTERN = re.compile(r"\b(?:mimikatz|sekurlsa|samdump|lsass\.exe|passwords\.txt|shadowcopy|ransomware|encrypt_all|keylogger|GetAsyncKeyState)\b", re.IGNORECASE)

# Known Critical Windows System & Security APIs with MITRE mappings
KNOWN_WINDOWS_APIS: Dict[str, Dict[str, Any]] = {
    # Process Injection / Memory Manipulation (T1055)
    "VirtualAlloc": {"severity": "HIGH", "reason": "Process memory allocation primitive", "mitre_id": "T1055", "mitre_technique": "Process Injection"},
    "VirtualAllocEx": {"severity": "HIGH", "reason": "Remote process memory allocation primitive", "mitre_id": "T1055", "mitre_technique": "Process Injection"},
    "VirtualProtect": {"severity": "HIGH", "reason": "Memory page protection modification (e.g. RWX)", "mitre_id": "T1055", "mitre_technique": "Process Injection"},
    "VirtualProtectEx": {"severity": "HIGH", "reason": "Remote memory page protection modification", "mitre_id": "T1055", "mitre_technique": "Process Injection"},
    "CreateRemoteThread": {"severity": "CRITICAL", "reason": "Remote thread execution in target process", "mitre_id": "T1055.002", "mitre_technique": "Process Injection: Portable Executable Injection"},
    "WriteProcessMemory": {"severity": "HIGH", "reason": "Direct write to foreign process virtual memory", "mitre_id": "T1055", "mitre_technique": "Process Injection"},
    "ReadProcessMemory": {"severity": "MEDIUM", "reason": "Read foreign process virtual memory", "mitre_id": "T1055", "mitre_technique": "Process Injection"},
    "OpenProcess": {"severity": "MEDIUM", "reason": "Process handle acquisition for manipulation or inspection", "mitre_id": "T1057", "mitre_technique": "Process Discovery"},
    "QueueUserAPC": {"severity": "HIGH", "reason": "Asynchronous procedure call injection", "mitre_id": "T1055.004", "mitre_technique": "Process Injection: Asynchronous Procedure Call"},
    "SetThreadContext": {"severity": "HIGH", "reason": "Thread context modification / execution hijacking", "mitre_id": "T1055.003", "mitre_technique": "Process Injection: Thread Execution Hijacking"},
    "GetThreadContext": {"severity": "MEDIUM", "reason": "Thread register and context retrieval", "mitre_id": "T1055.003", "mitre_technique": "Process Injection: Thread Execution Hijacking"},
    "NtUnmapViewOfSection": {"severity": "CRITICAL", "reason": "Section unmapping commonly used in process hollowing", "mitre_id": "T1055.012", "mitre_technique": "Process Injection: Process Hollowing"},
    "ZwUnmapViewOfSection": {"severity": "CRITICAL", "reason": "Native section unmapping (process hollowing)", "mitre_id": "T1055.012", "mitre_technique": "Process Injection: Process Hollowing"},

    # Dynamic Loading & Execution (T1129, T1106)
    "LoadLibraryA": {"severity": "MEDIUM", "reason": "Dynamic library loading primitive", "mitre_id": "T1129", "mitre_technique": "Shared Modules"},
    "LoadLibraryW": {"severity": "MEDIUM", "reason": "Dynamic library loading primitive (Unicode)", "mitre_id": "T1129", "mitre_technique": "Shared Modules"},
    "LoadLibraryExA": {"severity": "MEDIUM", "reason": "Extended dynamic library loading primitive", "mitre_id": "T1129", "mitre_technique": "Shared Modules"},
    "LoadLibraryExW": {"severity": "MEDIUM", "reason": "Extended dynamic library loading primitive", "mitre_id": "T1129", "mitre_technique": "Shared Modules"},
    "GetProcAddress": {"severity": "MEDIUM", "reason": "Dynamic API symbol resolution (evasion / unpacking)", "mitre_id": "T1129", "mitre_technique": "Shared Modules"},
    "WinExec": {"severity": "HIGH", "reason": "Legacy command/binary execution API", "mitre_id": "T1106", "mitre_technique": "Native API"},
    "ShellExecuteA": {"severity": "MEDIUM", "reason": "Shell execution primitive", "mitre_id": "T1106", "mitre_technique": "Native API"},
    "ShellExecuteW": {"severity": "MEDIUM", "reason": "Shell execution primitive (Unicode)", "mitre_id": "T1106", "mitre_technique": "Native API"},
    "CreateProcessA": {"severity": "MEDIUM", "reason": "Process creation primitive", "mitre_id": "T1106", "mitre_technique": "Native API"},
    "CreateProcessW": {"severity": "MEDIUM", "reason": "Process creation primitive (Unicode)", "mitre_id": "T1106", "mitre_technique": "Native API"},
    "CreateProcessInternalW": {"severity": "HIGH", "reason": "Undocumented internal process creation", "mitre_id": "T1106", "mitre_technique": "Native API"},

    # Network Ingress & Egress (T1105, T1071)
    "URLDownloadToFileA": {"severity": "HIGH", "reason": "Direct remote payload file download", "mitre_id": "T1105", "mitre_technique": "Ingress Tool Transfer"},
    "URLDownloadToFileW": {"severity": "HIGH", "reason": "Direct remote payload file download (Unicode)", "mitre_id": "T1105", "mitre_technique": "Ingress Tool Transfer"},
    "InternetOpenA": {"severity": "MEDIUM", "reason": "WinINet network initialization", "mitre_id": "T1071", "mitre_technique": "Application Layer Protocol"},
    "InternetOpenW": {"severity": "MEDIUM", "reason": "WinINet network initialization", "mitre_id": "T1071", "mitre_technique": "Application Layer Protocol"},
    "InternetOpenUrlA": {"severity": "MEDIUM", "reason": "WinINet direct URL connection", "mitre_id": "T1071", "mitre_technique": "Application Layer Protocol"},
    "InternetOpenUrlW": {"severity": "MEDIUM", "reason": "WinINet direct URL connection", "mitre_id": "T1071", "mitre_technique": "Application Layer Protocol"},
    "HttpSendRequestA": {"severity": "MEDIUM", "reason": "HTTP request transmission", "mitre_id": "T1071.001", "mitre_technique": "Web Protocols"},
    "HttpSendRequestW": {"severity": "MEDIUM", "reason": "HTTP request transmission", "mitre_id": "T1071.001", "mitre_technique": "Web Protocols"},

    # Anti-Analysis & Debugger Checks (T1497, T1622)
    "IsDebuggerPresent": {"severity": "MEDIUM", "reason": "Active user-mode debugger presence check", "mitre_id": "T1622", "mitre_technique": "Debugger Evasion"},
    "CheckRemoteDebuggerPresent": {"severity": "MEDIUM", "reason": "Process debugger detection check", "mitre_id": "T1622", "mitre_technique": "Debugger Evasion"},
    "OutputDebugStringA": {"severity": "LOW", "reason": "Debug logging string output", "mitre_id": "T1622", "mitre_technique": "Debugger Evasion"},

    # Persistence / Registry (T1547.001)
    "RegOpenKeyExA": {"severity": "LOW", "reason": "Registry key inspection API", "mitre_id": "T1012", "mitre_technique": "Query Registry"},
    "RegOpenKeyExW": {"severity": "LOW", "reason": "Registry key inspection API", "mitre_id": "T1012", "mitre_technique": "Query Registry"},
    "RegSetValueExA": {"severity": "MEDIUM", "reason": "Registry value modification API (potential persistence)", "mitre_id": "T1547.001", "mitre_technique": "Registry Run Keys / Startup Folder"},
    "RegSetValueExW": {"severity": "MEDIUM", "reason": "Registry value modification API (potential persistence)", "mitre_id": "T1547.001", "mitre_technique": "Registry Run Keys / Startup Folder"},
    "RegCreateKeyExA": {"severity": "MEDIUM", "reason": "Registry key creation API", "mitre_id": "T1547.001", "mitre_technique": "Registry Run Keys / Startup Folder"},
}


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ExtractedStringItem:
    """
    Detailed metadata for an individual extracted string sequence.
    """
    value: str
    encoding: str                       # 'ASCII' or 'UTF-16LE'
    offset: int                         # Byte offset in binary
    offset_hex: str                     # e.g., '0x00001A40'
    category: str                       # URL, DOMAIN, IP_ADDRESS, REGISTRY, COMMAND, etc.
    suspicious: bool = False
    severity: str = "INFO"              # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float = 1.0
    reason: str = "Standard binary string"
    mitre_technique: Optional[str] = None
    mitre_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "encoding": self.encoding,
            "offset": self.offset,
            "offset_hex": self.offset_hex,
            "category": self.category,
            "suspicious": self.suspicious,
            "severity": self.severity,
            "confidence": self.confidence,
            "reason": self.reason,
            "mitre_technique": self.mitre_technique,
            "mitre_id": self.mitre_id,
        }


@dataclass
class StringAnalysisResult:
    """
    Categorized string analysis result with full intelligence metadata.
    """
    total_strings: int = 0
    ascii_count: int = 0
    unicode_count: int = 0
    suspicious_count: int = 0

    # Categorized string collections (backward-compatible)
    urls: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    registry_paths: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    powershell_references: List[str] = field(default_factory=list)
    dlls: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    apis: List[str] = field(default_factory=list)
    all_extracted_strings: List[str] = field(default_factory=list)

    # Rich item list
    items: List[ExtractedStringItem] = field(default_factory=list)

    # Forensic summary breakdown
    statistics: Dict[str, int] = field(default_factory=dict)
    ai_summary: str = ""

    is_valid: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns comprehensive Module 06 standard schema."""
        return {
            "total_strings": self.total_strings,
            "ascii_count": self.ascii_count,
            "unicode_count": self.unicode_count,
            "suspicious_count": self.suspicious_count,
            "urls": self.urls,
            "ip_addresses": self.ip_addresses,
            "domains": self.domains,
            "registry_paths": self.registry_paths,
            "commands": self.commands,
            "powershell_references": self.powershell_references,
            "dlls": self.dlls,
            "emails": self.emails,
            "file_paths": self.file_paths,
            "apis": self.apis,
            "items": [item.to_dict() for item in self.items],
            "statistics": self.statistics or {
                "total": self.total_strings,
                "ascii_count": self.ascii_count,
                "unicode_count": self.unicode_count,
                "suspicious_count": self.suspicious_count,
                "urls_count": len(self.urls),
                "ips_count": len(self.ip_addresses),
                "domains_count": len(self.domains),
                "registry_count": len(self.registry_paths),
                "commands_count": len(self.commands),
                "powershell_count": len(self.powershell_references),
                "file_paths_count": len(self.file_paths),
                "dlls_count": len(self.dlls),
                "apis_count": len(self.apis),
                "emails_count": len(self.emails),
            },
            "ai_summary": self.ai_summary,
        }

    def to_extended_dict(self) -> Dict[str, Any]:
        """Returns extended dictionary."""
        return self.to_dict()


# ============================================================================
# STRING ANALYZER ENGINE
# ============================================================================

class StringAnalyzer:
    """
    Forensic Static String Extraction and Categorization Engine.
    """

    def __init__(self, min_length: int = 4):
        self.min_length = max(3, min_length)

    def extract_raw_strings(self, data: bytes, min_length: Optional[int] = None) -> List[str]:
        """
        Extracts plain string list from raw binary bytes.
        """
        if not data:
            return []

        limit = min_length if min_length is not None else self.min_length
        results: Set[str] = set()

        # 1. ASCII
        regex_ascii = re.compile(rb"[\x20-\x7E]{" + str(limit).encode() + rb",}")
        for match in regex_ascii.finditer(data):
            try:
                s = match.group().decode("ascii", errors="ignore").strip()
                if len(s) >= limit:
                    results.add(s)
            except Exception:
                continue

        # 2. Unicode
        regex_uni = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(limit).encode() + rb",}")
        for match in regex_uni.finditer(data):
            try:
                s = match.group().decode("utf-16le", errors="ignore").strip()
                if len(s) >= limit:
                    results.add(s)
            except Exception:
                continue

        return sorted(list(results))

    def classify_string(self, s: str, encoding: str, offset: int) -> ExtractedStringItem:
        """
        Classifies an individual string into an intelligence category and evaluates suspiciousness.
        """
        offset_hex = f"0x{offset:08X}"
        val_lower = s.lower()

        # 1. Email Address (Evaluated early so domains inside email aren't misclassified)
        if EMAIL_PATTERN.search(s):
            return ExtractedStringItem(
                value=s,
                encoding=encoding,
                offset=offset,
                offset_hex=offset_hex,
                category="EMAIL",
                suspicious=False,
                severity="INFO",
                confidence=0.95,
                reason="Electronic mail address artifact"
            )

        # 2. PowerShell Indicator
        if POWERSHELL_PATTERN.search(s):
            is_crit = any(k in val_lower for k in ["-enc", "downloadstring", "bypass", "invoke-expression", "iex"])
            severity = "HIGH" if is_crit else "MEDIUM"
            return ExtractedStringItem(
                value=s,
                encoding=encoding,
                offset=offset,
                offset_hex=offset_hex,
                category="POWERSHELL",
                suspicious=True,
                severity=severity,
                confidence=0.92,
                reason="PowerShell execution and command parameter indicator",
                mitre_technique="Command and Scripting Interpreter: PowerShell",
                mitre_id="T1059.001"
            )

        # 3. CMD / Command Line execution
        if CMD_PATTERN.search(s):
            return ExtractedStringItem(
                value=s,
                encoding=encoding,
                offset=offset,
                offset_hex=offset_hex,
                category="CMD",
                suspicious=True,
                severity="MEDIUM",
                confidence=0.88,
                reason="Windows Command Prompt execution parameter",
                mitre_technique="Command and Scripting Interpreter: Windows Command Shell",
                mitre_id="T1059.003"
            )

        # 4. CLI Administration / Recovery / Persistence Commands
        if COMMAND_PATTERN.search(s):
            is_high = any(k in val_lower for k in ["vssadmin", "certutil", "schtasks", "reg add", "taskkill /f"])
            severity = "HIGH" if is_high else "MEDIUM"
            mitre_id = "T1490" if "vssadmin" in val_lower else ("T1053.005" if "schtasks" in val_lower else "T1082")
            mitre_name = "Inhibit System Recovery" if "vssadmin" in val_lower else ("Scheduled Task" if "schtasks" in val_lower else "System Information Discovery")
            return ExtractedStringItem(
                value=s,
                encoding=encoding,
                offset=offset,
                offset_hex=offset_hex,
                category="COMMAND",
                suspicious=True,
                severity=severity,
                confidence=0.85,
                reason="System discovery, task scheduling, or recovery tampering command reference",
                mitre_technique=mitre_name,
                mitre_id=mitre_id
            )

        # 5. Script Host Artifacts
        if SCRIPT_PATTERN.search(s):
            is_script_tool = any(k in val_lower for k in ["mshta", "cscript", "wscript"])
            return ExtractedStringItem(
                value=s,
                encoding=encoding,
                offset=offset,
                offset_hex=offset_hex,
                category="SCRIPT",
                suspicious=is_script_tool,
                severity="MEDIUM" if is_script_tool else "LOW",
                confidence=0.80,
                reason="Windows Script Host or script interpreter artifact reference",
                mitre_technique="Visual Basic or JavaScript Interpreter",
                mitre_id="T1059.005"
            )

        # 6. Suspicious Tool / Credential Keywords
        if SUSPICIOUS_KEYWORD_PATTERN.search(s):
            return ExtractedStringItem(
                value=s,
                encoding=encoding,
                offset=offset,
                offset_hex=offset_hex,
                category="SUSPICIOUS",
                suspicious=True,
                severity="HIGH",
                confidence=0.90,
                reason="Potentially suspicious tool or credential dumping keyword reference",
                mitre_technique="OS Credential Dumping",
                mitre_id="T1003"
            )

        # 7. Critical Windows API References
        for api_name, api_info in KNOWN_WINDOWS_APIS.items():
            if s == api_name or (len(s) <= 40 and re.search(r"\b" + re.escape(api_name) + r"\b", s)):
                is_susp = api_info["severity"] in ("HIGH", "CRITICAL", "MEDIUM")
                return ExtractedStringItem(
                    value=s,
                    encoding=encoding,
                    offset=offset,
                    offset_hex=offset_hex,
                    category="API",
                    suspicious=is_susp,
                    severity=api_info["severity"],
                    confidence=0.95,
                    reason=api_info["reason"],
                    mitre_technique=api_info.get("mitre_technique"),
                    mitre_id=api_info.get("mitre_id")
                )

        # 8. URL
        if URL_PATTERN.search(s):
            url_match = URL_PATTERN.search(s).group()
            is_ip_url = bool(IPV4_PATTERN.search(url_match))
            is_onion_paste = any(k in url_match.lower() for k in [".onion", "pastebin.com", "discordapp.com/api", "raw.githubusercontent.com"])
            severity = "HIGH" if (is_ip_url or is_onion_paste) else ("MEDIUM" if url_match.lower().startswith("http://") else "LOW")
            return ExtractedStringItem(
                value=s,
                encoding=encoding,
                offset=offset,
                offset_hex=offset_hex,
                category="URL",
                suspicious=severity in ("HIGH", "MEDIUM"),
                severity=severity,
                confidence=0.90,
                reason="Network URL endpoint reference",
                mitre_technique="Application Layer Protocol: Web Protocols",
                mitre_id="T1071.001"
            )

        # 9. IP Address
        if IPV4_PATTERN.search(s):
            ip_val = IPV4_PATTERN.search(s).group()
            is_loopback_or_zero = ip_val in ("127.0.0.1", "0.0.0.0", "255.255.255.255")
            severity = "INFO" if is_loopback_or_zero else "MEDIUM"
            return ExtractedStringItem(
                value=s,
                encoding=encoding,
                offset=offset,
                offset_hex=offset_hex,
                category="IP_ADDRESS",
                suspicious=not is_loopback_or_zero,
                severity=severity,
                confidence=0.88,
                reason="Direct IPv4 destination address target",
                mitre_technique="Application Layer Protocol",
                mitre_id="T1071"
            )

        # 10. Registry Paths
        if REGISTRY_PATTERN.search(s):
            is_autorun = any(k in val_lower for k in ["currentversion\\run", "runonce", "winlogon", "image file execution options", "appinit_dlls"])
            severity = "HIGH" if is_autorun else "INFO"
            return ExtractedStringItem(
                value=s,
                encoding=encoding,
                offset=offset,
                offset_hex=offset_hex,
                category="REGISTRY",
                suspicious=is_autorun,
                severity=severity,
                confidence=0.90,
                reason="Windows Registry autorun persistence or system configuration key" if is_autorun else "Windows Registry configuration path",
                mitre_technique="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder" if is_autorun else "Query Registry",
                mitre_id="T1547.001" if is_autorun else "T1012"
            )

        # 11. File Paths
        if FILE_PATH_PATTERN.search(s):
            is_susp_path = any(k in val_lower for k in ["\\temp\\", "\\appdata\\", "\\startup\\", "%temp%", "%appdata%"])
            severity = "MEDIUM" if is_susp_path else "INFO"
            return ExtractedStringItem(
                value=s,
                encoding=encoding,
                offset=offset,
                offset_hex=offset_hex,
                category="FILE_PATH",
                suspicious=is_susp_path,
                severity=severity,
                confidence=0.82,
                reason="File system path reference (temporary/user directory)" if is_susp_path else "File system path reference",
                mitre_technique="File and Directory Discovery",
                mitre_id="T1083"
            )

        # 12. Domain Names
        if DOMAIN_PATTERN.search(s) and not s.lower().endswith(".dll"):
            return ExtractedStringItem(
                value=s,
                encoding=encoding,
                offset=offset,
                offset_hex=offset_hex,
                category="DOMAIN",
                suspicious=False,
                severity="INFO",
                confidence=0.85,
                reason="Internet domain hostname reference",
                mitre_technique="Application Layer Protocol: Web Protocols",
                mitre_id="T1071.001"
            )

        # 13. DLL Modules
        if DLL_PATTERN.search(s):
            return ExtractedStringItem(
                value=s,
                encoding=encoding,
                offset=offset,
                offset_hex=offset_hex,
                category="DLL",
                suspicious=False,
                severity="INFO",
                confidence=0.90,
                reason="Dynamic Link Library module dependency reference",
                mitre_technique="Shared Modules",
                mitre_id="T1129"
            )

        # 14. General Text / Metadata
        return ExtractedStringItem(
            value=s,
            encoding=encoding,
            offset=offset,
            offset_hex=offset_hex,
            category="GENERAL",
            suspicious=False,
            severity="INFO",
            confidence=1.0,
            reason="Standard application text or binary metadata"
        )

    def analyze_bytes(self, data: bytes, min_length: Optional[int] = None) -> StringAnalysisResult:
        """
        Extracts, classifies, and assesses strings from raw binary byte data without execution.
        """
        if not data:
            return StringAnalysisResult(
                total_strings=0,
                is_valid=True
            )

        limit = min_length if min_length is not None else self.min_length
        items: List[ExtractedStringItem] = []
        raw_strings: List[str] = []
        seen_strings: Set[Tuple[str, str, int]] = set()

        # 1. Extract ASCII strings with byte offsets
        regex_ascii = re.compile(rb"[\x20-\x7E]{" + str(limit).encode() + rb",}")
        ascii_count = 0
        for match in regex_ascii.finditer(data):
            try:
                s = match.group().decode("ascii", errors="ignore").strip()
                if len(s) >= limit:
                    offset = match.start()
                    key = (s, "ASCII", offset)
                    raw_strings.append(s)
                    if key not in seen_strings:
                        seen_strings.add(key)
                        item = self.classify_string(s, encoding="ASCII", offset=offset)
                        items.append(item)
                        ascii_count += 1
            except Exception:
                continue

        # 2. Extract Unicode (UTF-16LE) strings with byte offsets
        regex_uni = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(limit).encode() + rb",}")
        unicode_count = 0
        for match in regex_uni.finditer(data):
            try:
                s = match.group().decode("utf-16le", errors="ignore").strip()
                if len(s) >= limit:
                    offset = match.start()
                    key = (s, "UTF-16LE", offset)
                    raw_strings.append(s)
                    if key not in seen_strings:
                        seen_strings.add(key)
                        item = self.classify_string(s, encoding="UTF-16LE", offset=offset)
                        items.append(item)
                        unicode_count += 1
            except Exception:
                continue

        # Sort items: suspicious / high severity first, then by offset
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        items.sort(key=lambda x: (severity_order.get(x.severity, 5), x.offset))

        # Comprehensive sub-pattern matching across all extracted strings
        all_urls: Set[str] = set()
        all_ips: Set[str] = set()
        all_domains: Set[str] = set()
        all_regs: Set[str] = set()
        all_cmds: Set[str] = set()
        all_ps: Set[str] = set()
        all_dlls: Set[str] = set()
        all_emails: Set[str] = set()
        all_paths: Set[str] = set()
        all_apis: Set[str] = set()

        for s in raw_strings:
            for u in URL_PATTERN.findall(s):
                all_urls.add(u)
            for ip in IPV4_PATTERN.findall(s):
                all_ips.add(ip)
            for em in EMAIL_PATTERN.findall(s):
                all_emails.add(em)
            for d in DOMAIN_PATTERN.findall(s):
                if not d.lower().endswith(".dll"):
                    all_domains.add(d)

        for i in items:
            s_val = i.value
            if i.category == "URL":
                all_urls.add(s_val)
            elif i.category == "IP_ADDRESS":
                all_ips.add(s_val)
            elif i.category == "DOMAIN":
                all_domains.add(s_val)
            elif i.category == "REGISTRY" or REGISTRY_PATTERN.search(s_val):
                all_regs.add(s_val)
            elif i.category in ("COMMAND", "CMD") or COMMAND_PATTERN.search(s_val) or CMD_PATTERN.search(s_val):
                all_cmds.add(s_val)
            elif i.category == "POWERSHELL" or POWERSHELL_PATTERN.search(s_val):
                all_ps.add(s_val)
            elif i.category == "DLL" or DLL_PATTERN.search(s_val):
                all_dlls.add(s_val)
            elif i.category == "EMAIL":
                all_emails.add(s_val)
            elif i.category == "FILE_PATH" or FILE_PATH_PATTERN.search(s_val):
                all_paths.add(s_val)
            elif i.category == "API":
                all_apis.add(s_val)
            else:
                for api in KNOWN_WINDOWS_APIS.keys():
                    if api in s_val:
                        all_apis.add(api)

        urls = sorted(list(all_urls))
        ip_addresses = sorted(list(all_ips))
        domains = sorted(list(all_domains))
        registry_paths = sorted(list(all_regs))
        commands = sorted(list(all_cmds))
        powershell_refs = sorted(list(all_ps))
        dlls = sorted(list(all_dlls))
        emails = sorted(list(all_emails))
        file_paths = sorted(list(all_paths))
        apis = sorted(list(all_apis))

        suspicious_count = sum(1 for i in items if i.suspicious)
        total_strings = len(items)

        # Forensic summary statistics
        stats = {
            "total": total_strings,
            "ascii_count": ascii_count,
            "unicode_count": unicode_count,
            "suspicious_count": suspicious_count,
            "urls_count": len(urls),
            "ips_count": len(ip_addresses),
            "domains_count": len(domains),
            "registry_count": len(registry_paths),
            "commands_count": len(commands),
            "powershell_count": len(powershell_refs),
            "file_paths_count": len(file_paths),
            "dlls_count": len(dlls),
            "apis_count": len(apis),
            "emails_count": len(emails),
        }

        # Rule-based AI/Intelligence Summary
        susp_findings = []
        if powershell_refs:
            susp_findings.append(f"{len(powershell_refs)} PowerShell command/script references")
        if commands:
            susp_findings.append(f"{len(commands)} command execution sequences")
        if urls or ip_addresses:
            susp_findings.append(f"{len(urls) + len(ip_addresses)} network endpoints/IP targets")
        if registry_paths:
            susp_findings.append(f"{len(registry_paths)} registry persistence/configuration keys")
        if apis:
            susp_findings.append(f"{len(apis)} critical Windows API references")

        if susp_findings:
            ai_summary = (
                f"Extracted {total_strings:,} strings ({ascii_count:,} ASCII, {unicode_count:,} Unicode). "
                f"Identified {suspicious_count} suspicious indicators including {', '.join(susp_findings[:3])}. "
                "Important Note: Static string presence provides investigative triage context but does not confirm malicious behavior without dynamic runtime correlation."
            )
        else:
            ai_summary = (
                f"Extracted {total_strings:,} strings ({ascii_count:,} ASCII, {unicode_count:,} Unicode). "
                "No overt suspicious commands, persistence keys, or unauthorized network indicators were identified in static strings."
            )

        return StringAnalysisResult(
            total_strings=total_strings,
            ascii_count=ascii_count,
            unicode_count=unicode_count,
            suspicious_count=suspicious_count,
            urls=urls,
            ip_addresses=ip_addresses,
            domains=domains,
            registry_paths=registry_paths,
            commands=commands,
            powershell_references=powershell_refs,
            dlls=dlls,
            emails=emails,
            file_paths=file_paths,
            apis=apis,
            all_extracted_strings=[i.value for i in items],
            items=items,
            statistics=stats,
            ai_summary=ai_summary,
            is_valid=True,
            error_message=None
        )

    def analyze_file(self, file_path: Union[str, Path], min_length: Optional[int] = None) -> StringAnalysisResult:
        """
        Loads a file from disk and performs static string extraction without execution.
        """
        target = Path(file_path)
        if not target.exists() or not target.is_file():
            return StringAnalysisResult(
                total_strings=0,
                is_valid=False,
                error_message=f"Target file not found at path: {file_path}"
            )

        try:
            with open(target, "rb") as f:
                content = f.read()
            return self.analyze_bytes(content, min_length=min_length)
        except PermissionError as pe:
            return StringAnalysisResult(
                total_strings=0,
                is_valid=False,
                error_message=f"Permission denied reading file '{file_path}': {pe}"
            )
        except Exception as e:
            return StringAnalysisResult(
                total_strings=0,
                is_valid=False,
                error_message=f"Failed to read file '{file_path}': {str(e)}"
            )


# Global singleton instance
string_analyzer_service = StringAnalyzer()
