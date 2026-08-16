"""
Module 06: String Analyzer

Responsibility:
Performs static string extraction and forensic categorization on binary byte sequences.
Extracts both ASCII and Unicode (UTF-16LE) strings without execution.

Categorizes strings into:
- URLs (http, https, ftp)
- IPv4 Addresses
- Domains (Internet domain names)
- Registry Paths (HKLM, HKCU, HKEY_LOCAL_MACHINE, etc.)
- File Paths (Windows drive letters, UNC paths, environment variables)
- Commands (cmd.exe /c, whoami, net user, vssadmin, etc.)
- PowerShell References (powershell.exe, Invoke-Expression, DownloadString, ExecutionPolicy, etc.)
- DLL Names (kernel32.dll, user32.dll, etc.)
- Email Addresses
- Windows API Function Names

Safety & Educational Principles:
- Strictly static in-memory pattern matching; NEVER executes any discovered strings or commands.
- Do NOT label strings malicious merely because they contain suspicious keywords.
- All extracted strings are reported objectively as technical evidence.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Set, Tuple
from dataclasses import dataclass, field

from app.core.logger import logger

# Extraction Regular Expressions
ASCII_STRING_REGEX = re.compile(rb"[\x20-\x7E]{4,}")
UNICODE_STRING_REGEX = re.compile(rb"(?:[\x20-\x7E]\x00){4,}")

# Classification Patterns
URL_PATTERN = re.compile(r"\b(?:https?|ftp)://[A-Za-z0-9\-_.]+(?::\d+)?(?:/[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
DOMAIN_PATTERN = re.compile(r"\b(?!(?:https?|ftp)://)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:com|org|net|edu|gov|io|et|info|biz|co|cc|tv|ru|cn|xyz|top|site|online|mil)\b", re.IGNORECASE)
REGISTRY_PATTERN = re.compile(r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU)\\[A-Za-z0-9_\\\-.\s]+", re.IGNORECASE)
FILE_PATH_PATTERN = re.compile(r"(?:[a-zA-Z]:\\(?:[A-Za-z0-9_\-\s.]+\\?)+|\\\\[A-Za-z0-9_\-]+\\(?:[A-Za-z0-9_\-\s.]+\\?)+|%[A-Za-z0-9_]+%\\(?:[A-Za-z0-9_\-\s.]+\\?)+)", re.IGNORECASE)
POWERSHELL_PATTERN = re.compile(r"(?:powershell(?:\.exe)?|Invoke-Expression|\bIEX\b|DownloadString|DownloadFile|Set-ExecutionPolicy|\bBypass\b|-enc\b|-encodedcommand|-nop\b|-noprofile\b)", re.IGNORECASE)
COMMAND_PATTERN = re.compile(r"(?:cmd(?:\.exe)?\s+(?:\/c|\/k)|\bnet\s+(?:user|localgroup|share|use|stop|start)\b|\bvssadmin(?:\.exe)?\b|\bwhoami(?:\.exe)?\b|\bipconfig(?:\.exe)?\b|\btaskkill(?:\.exe)?\b|\breg(?:\.exe)?\s+(?:add|delete|query)\b|\bschtasks(?:\.exe)?\b|\battrib\s+[+\-][rhsa]\b)", re.IGNORECASE)
DLL_PATTERN = re.compile(r"\b[A-Za-z0-9_\-.]+\.dll\b", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.IGNORECASE)

# Recognized Windows Security & System APIs
KNOWN_WINDOWS_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
    "OpenProcess", "QueueUserAPC", "SetThreadContext", "GetThreadContext",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "WinExec", "ShellExecuteA", "ShellExecuteW",
    "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
    "InternetOpenUrlA", "InternetOpenUrlW", "HttpSendRequestA", "HttpSendRequestW",
    "CreateProcessA", "CreateProcessW", "CreateProcessInternalW", "RegOpenKeyExA",
    "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "MapViewOfFile",
    "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "DeleteFileA", "DeleteFileW",
}


@dataclass
class StringAnalysisResult:
    """
    Categorized string analysis result matching the Module 06 specification.
    """
    total_strings: int = 0
    urls: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    registry_paths: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    powershell_references: List[str] = field(default_factory=list)

    # Extended Forensic Categorization
    dlls: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    apis: List[str] = field(default_factory=list)
    all_extracted_strings: List[str] = field(default_factory=list)

    is_valid: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns the exact Module 06 standard schema."""
        return {
            "total_strings": self.total_strings,
            "urls": self.urls,
            "ip_addresses": self.ip_addresses,
            "domains": self.domains,
            "registry_paths": self.registry_paths,
            "commands": self.commands,
            "powershell_references": self.powershell_references,
        }

    def to_extended_dict(self) -> Dict[str, Any]:
        """Returns all categorized strings including DLLs, APIs, and file paths."""
        d = self.to_dict()
        d.update({
            "dlls": self.dlls,
            "emails": self.emails,
            "file_paths": self.file_paths,
            "apis": self.apis,
        })
        return d


class StringAnalyzer:
    """
    Forensic Static String Extraction and Categorization Engine.
    """

    def __init__(self, min_length: int = 4):
        self.min_length = max(3, min_length)

    def extract_raw_strings(self, data: bytes) -> List[str]:
        """
        Extracts both ASCII and Unicode (UTF-16LE) strings from raw binary bytes.
        """
        if not data:
            return []

        results: Set[str] = set()

        # 1. Extract ASCII strings
        for match in ASCII_STRING_REGEX.finditer(data):
            try:
                s = match.group().decode("ascii", errors="ignore").strip()
                if len(s) >= self.min_length:
                    results.add(s)
            except Exception:
                continue

        # 2. Extract Unicode (UTF-16LE) strings
        for match in UNICODE_STRING_REGEX.finditer(data):
            try:
                s = match.group().decode("utf-16le", errors="ignore").strip()
                if len(s) >= self.min_length:
                    results.add(s)
            except Exception:
                continue

        return sorted(list(results))

    def analyze_bytes(self, data: bytes) -> StringAnalysisResult:
        """
        Extracts and classifies strings from raw binary byte data.

        Args:
            data: Raw binary bytes.

        Returns:
            StringAnalysisResult object.
        """
        if not data:
            return StringAnalysisResult(
                total_strings=0,
                is_valid=True
            )

        extracted_strings = self.extract_raw_strings(data)

        urls: Set[str] = set()
        ip_addresses: Set[str] = set()
        domains: Set[str] = set()
        registry_paths: Set[str] = set()
        commands: Set[str] = set()
        powershell_refs: Set[str] = set()
        dlls: Set[str] = set()
        emails: Set[str] = set()
        file_paths: Set[str] = set()
        apis: Set[str] = set()

        for s in extracted_strings:
            # Check URLs
            url_matches = URL_PATTERN.findall(s)
            for m in url_matches:
                urls.add(m)

            # Check IPv4 Addresses
            ip_matches = IPV4_PATTERN.findall(s)
            for m in ip_matches:
                ip_addresses.add(m)

            # Check Domains (avoid duplicates that are DLLs or already in URLs)
            domain_matches = DOMAIN_PATTERN.findall(s)
            for m in domain_matches:
                if not m.lower().endswith(".dll") and not any(m in u for u in urls):
                    domains.add(m)

            # Check Registry Paths
            reg_matches = REGISTRY_PATTERN.findall(s)
            for m in reg_matches:
                registry_paths.add(m)

            # Check Windows File Paths
            path_matches = FILE_PATH_PATTERN.findall(s)
            for m in path_matches:
                file_paths.add(m)

            # Check PowerShell references
            if POWERSHELL_PATTERN.search(s):
                powershell_refs.add(s)

            # Check CLI Commands
            if COMMAND_PATTERN.search(s):
                commands.add(s)

            # Check DLLs
            dll_matches = DLL_PATTERN.findall(s)
            for m in dll_matches:
                dlls.add(m)

            # Check Emails
            email_matches = EMAIL_PATTERN.findall(s)
            for m in email_matches:
                emails.add(m)

            # Check Known Windows APIs
            if s in KNOWN_WINDOWS_APIS:
                apis.add(s)

        return StringAnalysisResult(
            total_strings=len(extracted_strings),
            urls=sorted(list(urls)),
            ip_addresses=sorted(list(ip_addresses)),
            domains=sorted(list(domains)),
            registry_paths=sorted(list(registry_paths)),
            commands=sorted(list(commands)),
            powershell_references=sorted(list(powershell_refs)),
            dlls=sorted(list(dlls)),
            emails=sorted(list(emails)),
            file_paths=sorted(list(file_paths)),
            apis=sorted(list(apis)),
            all_extracted_strings=extracted_strings,
            is_valid=True,
            error_message=None
        )

    def analyze_file(self, file_path: Union[str, Path]) -> StringAnalysisResult:
        """
        Loads a file from disk and performs static string extraction without execution.

        Args:
            file_path: Path to target file.

        Returns:
            StringAnalysisResult object.
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
            return self.analyze_bytes(content)
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


if __name__ == "__main__":
    import json

    print("=" * 68)
    print("  ETHIO-AI Defender - Module 06: String Analyzer Demo")
    print("=" * 68)

    analyzer = StringAnalyzer()

    # Synthetic sample containing multiple forensic string categories
    sample_payload = (
        b"Welcome to ETHIO-AI Defender static analysis engine.\x00"
        b"https://cybersecurity.gov.et/alerts/report\x00"
        b"192.168.1.105\x00"
        b"c2-telecom.ethio.et\x00"
        b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        b"powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgA\x00"
        b"cmd.exe /c whoami >> C:\\Windows\\Temp\\output.txt\x00"
        b"kernel32.dll\x00user32.dll\x00ws2_32.dll\x00"
        b"analyst@insa.gov.et\x00"
        b"VirtualAlloc\x00CreateRemoteThread\x00WriteProcessMemory\x00"
    )

    res = analyzer.analyze_bytes(sample_payload)
    print("Structured Output Contract:")
    print(json.dumps(res.to_dict(), indent=2))
    print("=" * 68)
