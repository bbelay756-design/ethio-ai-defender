"""
Module 07: Windows API Import Analyzer

Responsibility:
Statically inspects the Import Directory Table (IDT) and Import Address Table (IAT) of PE files.
Extracts imported DLLs and API function names, and maps them to defensive functional categories.

Categories:
- FILE               : File I/O and filesystem interaction (e.g., CreateFileA, ReadFile, WriteFile)
- PROCESS            : Process creation, inspection, and termination (e.g., CreateProcessA, OpenProcess, WinExec)
- MEMORY             : Memory allocation, page protection, and direct memory writes (e.g., VirtualAlloc, VirtualProtect, WriteProcessMemory)
- NETWORK            : Sockets, HTTP/HTTPS requests, and URL downloads (e.g., InternetOpenA, URLDownloadToFileA, WSAStartup, connect)
- REGISTRY           : Windows registry querying and persistence keys (e.g., RegOpenKeyExA, RegSetValueExA)
- SERVICE            : Windows service installation, control, and deletion (e.g., OpenSCManagerA, CreateServiceA, StartServiceA)
- CRYPTOGRAPHY       : Encryption, hashing, and key derivation (e.g., CryptAcquireContextA, CryptEncrypt, BCryptEncrypt)
- SYSTEM_INFORMATION : Host discovery, OS version, hardware info, and anti-debugging (e.g., GetSystemInfo, IsDebuggerPresent, GetComputerNameA)
- GUI                : Windows desktop, window management, and message dialogs (e.g., MessageBoxA, CreateWindowExA, ShowWindow)
- THREAD             : Thread execution, remote thread injection, and APC queues (e.g., CreateThread, CreateRemoteThread, SetThreadContext)
- SECURITY           : Token privileges, impersonation, and authentication (e.g., AdjustTokenPrivileges, OpenProcessToken, LogonUserA)

Educational & Defensive Principles:
- Strictly static inspection; NEVER executes the file.
- An API does NOT prove malicious behavior (e.g., legitimate applications frequently use VirtualAlloc, CreateFile, and RegOpenKeyEx).
- Categories and risk relevance scores provide triage assistance to security analysts.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple
import pefile

from app.core.logger import logger

# Configurable API Knowledge Base: (Category, Risk Relevance, Explanation)
DEFAULT_API_DATABASE: Dict[str, Tuple[str, str, str]] = {
    # 1. FILE
    "createfilea": ("FILE", "LOW", "Creates or opens a file or I/O device."),
    "createfilew": ("FILE", "LOW", "Creates or opens a file or I/O device (Unicode)."),
    "readfile": ("FILE", "LOW", "Reads data from the specified file or input/output device."),
    "writefile": ("FILE", "LOW", "Writes data to the specified file or input/output device."),
    "deletefilea": ("FILE", "LOW", "Deletes an existing file on disk."),
    "deletefilew": ("FILE", "LOW", "Deletes an existing file on disk (Unicode)."),
    "copyfilea": ("FILE", "LOW", "Copies an existing file to a new file."),
    "copyfilew": ("FILE", "LOW", "Copies an existing file to a new file (Unicode)."),
    "movefilea": ("FILE", "LOW", "Moves an existing file or directory."),
    "movefilew": ("FILE", "LOW", "Moves an existing file or directory (Unicode)."),
    "findfirstfilea": ("FILE", "LOW", "Searches a directory for a file or subdirectory."),
    "findfirstfilew": ("FILE", "LOW", "Searches a directory for a file or subdirectory (Unicode)."),
    "findnextfilea": ("FILE", "LOW", "Continues a file search from a previous call."),
    "findnextfilew": ("FILE", "LOW", "Continues a file search from a previous call (Unicode)."),
    "gettemppatha": ("FILE", "LOW", "Retrieves the path of the directory designated for temporary files."),
    "gettemppathw": ("FILE", "LOW", "Retrieves the path of the directory designated for temporary files (Unicode)."),
    "setfileattributesa": ("FILE", "LOW", "Sets the attributes for a file or directory."),
    "setfileattributesw": ("FILE", "LOW", "Sets the attributes for a file or directory (Unicode)."),

    # 2. PROCESS
    "createprocessa": ("PROCESS", "MEDIUM", "Creates a new process and its primary thread."),
    "createprocessw": ("PROCESS", "MEDIUM", "Creates a new process and its primary thread (Unicode)."),
    "createprocessinternalw": ("PROCESS", "HIGH", "Low-level undocumented process creation API."),
    "openprocess": ("PROCESS", "MEDIUM", "Opens an existing local process object."),
    "terminateprocess": ("PROCESS", "MEDIUM", "Terminates the specified process and all of its threads."),
    "winexec": ("PROCESS", "MEDIUM", "Runs the specified application (legacy command execution)."),
    "shellexecutea": ("PROCESS", "MEDIUM", "Performs an operation on a specified file or command."),
    "shellexecutew": ("PROCESS", "MEDIUM", "Performs an operation on a specified file or command (Unicode)."),
    "shellexecuteexa": ("PROCESS", "MEDIUM", "Extended execution of an application or document."),
    "shellexecuteexw": ("PROCESS", "MEDIUM", "Extended execution of an application or document (Unicode)."),
    "exitprocess": ("PROCESS", "LOW", "Ends the calling process and all its threads."),

    # 3. MEMORY
    "virtualalloc": ("MEMORY", "MEDIUM", "Allocates virtual memory pages in the calling process."),
    "virtualallocEx": ("MEMORY", "HIGH", "Allocates memory pages in the address space of another process (common in process injection)."),
    "virtualprotect": ("MEMORY", "MEDIUM", "Changes the protection on a region of committed pages in memory."),
    "virtualprotectex": ("MEMORY", "HIGH", "Changes memory protection in another process."),
    "writeprocessmemory": ("MEMORY", "HIGH", "Writes data to an area of memory in a specified remote process."),
    "readprocessmemory": ("MEMORY", "MEDIUM", "Reads data from an area of memory in a specified process."),
    "mapviewoffile": ("MEMORY", "LOW", "Maps a view of a file mapping into the address space."),
    "mapviewoffileex": ("MEMORY", "LOW", "Maps a view of a file mapping with a preferred base address."),
    "heapalloc": ("MEMORY", "LOW", "Allocates a block of memory from a heap."),
    "globalalloc": ("MEMORY", "LOW", "Allocates the specified number of bytes from the global heap."),
    "virtualfree": ("MEMORY", "LOW", "Releases or decommits a region of pages in virtual memory."),

    # 4. NETWORK
    "internetopena": ("NETWORK", "MEDIUM", "Initializes an application's use of WinINet functions."),
    "internetopenw": ("NETWORK", "MEDIUM", "Initializes an application's use of WinINet functions (Unicode)."),
    "internetopenurla": ("NETWORK", "MEDIUM", "Opens a resource specified by a complete FTP or HTTP URL."),
    "internetopenurlw": ("NETWORK", "MEDIUM", "Opens a resource specified by a complete FTP or HTTP URL (Unicode)."),
    "internetreadfile": ("NETWORK", "MEDIUM", "Reads data from an open Internet handle."),
    "httpsendrequesta": ("NETWORK", "MEDIUM", "Sends the specified HTTP request to the HTTP server."),
    "httpsendrequestw": ("NETWORK", "MEDIUM", "Sends the specified HTTP request to the HTTP server (Unicode)."),
    "urldownloadtofilea": ("NETWORK", "HIGH", "Downloads bits from the Internet and saves them to a file."),
    "urldownloadtofilew": ("NETWORK", "HIGH", "Downloads bits from the Internet and saves them to a file (Unicode)."),
    "wsastartup": ("NETWORK", "LOW", "Initiates use of the Winsock DLL by a process."),
    "socket": ("NETWORK", "LOW", "Creates a socket bound to a specific transport service provider."),
    "connect": ("NETWORK", "MEDIUM", "Establishes a connection to a specified socket/host."),
    "send": ("NETWORK", "LOW", "Sends data on a connected socket."),
    "recv": ("NETWORK", "LOW", "Receives data from a connected socket."),
    "gethostbyname": ("NETWORK", "LOW", "Retrieves host information corresponding to a host name."),

    # 5. REGISTRY
    "regopenkeyexa": ("REGISTRY", "LOW", "Opens the specified registry key."),
    "regopenkeyexw": ("REGISTRY", "LOW", "Opens the specified registry key (Unicode)."),
    "regcreatekeyexa": ("REGISTRY", "MEDIUM", "Creates the specified registry key."),
    "regcreatekeyexw": ("REGISTRY", "MEDIUM", "Creates the specified registry key (Unicode)."),
    "regsetvalueexa": ("REGISTRY", "MEDIUM", "Sets the data and type of a specified value under a registry key."),
    "regsetvalueexw": ("REGISTRY", "MEDIUM", "Sets the data and type of a specified value under a registry key (Unicode)."),
    "regdeletekeya": ("REGISTRY", "MEDIUM", "Deletes a subkey and its values from the registry."),
    "regdeletekeyw": ("REGISTRY", "MEDIUM", "Deletes a subkey and its values from the registry (Unicode)."),
    "regqueryvalueexa": ("REGISTRY", "LOW", "Retrieves the type and data for a specified registry value name."),
    "regqueryvalueexw": ("REGISTRY", "LOW", "Retrieves the type and data for a specified registry value name (Unicode)."),
    "regclosekey": ("REGISTRY", "LOW", "Closes a handle to the specified registry key."),

    # 6. SERVICE
    "openscmanagera": ("SERVICE", "MEDIUM", "Establishes a connection to the Service Control Manager."),
    "openscmanagerw": ("SERVICE", "MEDIUM", "Establishes a connection to the Service Control Manager (Unicode)."),
    "createservicea": ("SERVICE", "HIGH", "Creates a Windows service object and adds it to the SCM database."),
    "createservicew": ("SERVICE", "HIGH", "Creates a Windows service object and adds it to the SCM database (Unicode)."),
    "startservicea": ("SERVICE", "MEDIUM", "Starts a Windows service."),
    "startservicew": ("SERVICE", "MEDIUM", "Starts a Windows service (Unicode)."),
    "controlservice": ("SERVICE", "MEDIUM", "Sends a control code to a Windows service."),
    "deleteservice": ("SERVICE", "MEDIUM", "Marks the specified service for deletion from the SCM."),

    # 7. CRYPTOGRAPHY
    "cryptacquirecontexta": ("CRYPTOGRAPHY", "LOW", "Acquires a handle to a particular cryptographic service provider (CSP)."),
    "cryptacquirecontextw": ("CRYPTOGRAPHY", "LOW", "Acquires a handle to a cryptographic service provider (Unicode)."),
    "cryptencrypt": ("CRYPTOGRAPHY", "MEDIUM", "Encrypts data using a cryptographic key."),
    "cryptdecrypt": ("CRYPTOGRAPHY", "MEDIUM", "Decrypts data previously encrypted by CryptEncrypt."),
    "cryptcreatehash": ("CRYPTOGRAPHY", "LOW", "Initiates the hashing of a stream of data."),
    "crypthashdata": ("CRYPTOGRAPHY", "LOW", "Adds data to a specified hash object."),
    "cryptderivekey": ("CRYPTOGRAPHY", "LOW", "Derives a cryptographic session key from a hash value."),
    "bcryptencrypt": ("CRYPTOGRAPHY", "MEDIUM", "Encrypts a block of data using Windows CNG API."),
    "bcryptdecrypt": ("CRYPTOGRAPHY", "MEDIUM", "Decrypts a block of data using Windows CNG API."),

    # 8. SYSTEM_INFORMATION
    "getsysteminfo": ("SYSTEM_INFORMATION", "LOW", "Retrieves information about the current computer system."),
    "getcomputernamea": ("SYSTEM_INFORMATION", "LOW", "Retrieves the NetBIOS name of the local computer."),
    "getcomputernamew": ("SYSTEM_INFORMATION", "LOW", "Retrieves the NetBIOS name of the local computer (Unicode)."),
    "getusernamea": ("SYSTEM_INFORMATION", "LOW", "Retrieves the name of the user associated with the current thread."),
    "getusernamew": ("SYSTEM_INFORMATION", "LOW", "Retrieves the name of the user associated with the current thread (Unicode)."),
    "getversionexa": ("SYSTEM_INFORMATION", "LOW", "Retrieves information about the operating system version."),
    "getversionexw": ("SYSTEM_INFORMATION", "LOW", "Retrieves information about the operating system version (Unicode)."),
    "isdebuggerpresent": ("SYSTEM_INFORMATION", "MEDIUM", "Determines whether the calling process is being debugged."),
    "checkremotedebuggerpresent": ("SYSTEM_INFORMATION", "MEDIUM", "Checks if a process is being debugged by another process."),
    "gettickcount": ("SYSTEM_INFORMATION", "LOW", "Retrieves the number of milliseconds elapsed since the system started."),
    "createtoolhelp32snapshot": ("SYSTEM_INFORMATION", "MEDIUM", "Takes a snapshot of processes, threads, modules, and heaps."),
    "process32first": ("SYSTEM_INFORMATION", "LOW", "Retrieves information about the first process in a system snapshot."),
    "process32next": ("SYSTEM_INFORMATION", "LOW", "Retrieves information about the next process in a system snapshot."),

    # 9. GUI
    "messageboxa": ("GUI", "LOW", "Displays a modal dialog box that contains a message."),
    "messageboxw": ("GUI", "LOW", "Displays a modal dialog box that contains a message (Unicode)."),
    "createwindowexa": ("GUI", "LOW", "Creates an overlapped, pop-up, or child window with an extended window style."),
    "createwindowexw": ("GUI", "LOW", "Creates a window with an extended window style (Unicode)."),
    "showwindow": ("GUI", "LOW", "Sets the specified window's show state."),
    "getmessagea": ("GUI", "LOW", "Retrieves a message from the calling thread's message queue."),
    "getmessagew": ("GUI", "LOW", "Retrieves a message from the calling thread's message queue (Unicode)."),
    "dispatchmessagea": ("GUI", "LOW", "Dispatches a message to a window procedure."),
    "dispatchmessagew": ("GUI", "LOW", "Dispatches a message to a window procedure (Unicode)."),

    # 10. THREAD
    "createthread": ("THREAD", "LOW", "Creates a thread to execute within the virtual address space of the calling process."),
    "createremotethread": ("THREAD", "HIGH", "Creates a thread that runs in the virtual address space of another process (process injection)."),
    "setthreadcontext": ("THREAD", "HIGH", "Sets the context for the specified thread (used in process hollowing / hooking)."),
    "getthreadcontext": ("THREAD", "MEDIUM", "Retrieves the context of the specified thread."),
    "resumethread": ("THREAD", "LOW", "Decrements a thread's suspend count."),
    "suspendthread": ("THREAD", "LOW", "Suspends the specified thread."),
    "queueuserapc": ("THREAD", "HIGH", "Adds a user-mode asynchronous procedure call (APC) object to the thread APC queue."),

    # 11. SECURITY
    "adjusttokenprivileges": ("SECURITY", "HIGH", "Enables or disables privileges in the specified access token (privilege escalation)."),
    "openprocesstoken": ("SECURITY", "MEDIUM", "Opens the access token associated with a process."),
    "lookupprivilegevaluea": ("SECURITY", "LOW", "Retrieves the locally unique identifier (LUID) for a privilege name."),
    "lookupprivilegevaluew": ("SECURITY", "LOW", "Retrieves the LUID for a privilege name (Unicode)."),
    "impersonateloggedonuser": ("SECURITY", "HIGH", "Lets the calling thread impersonate the security context of a logged-on user."),
    "logonusera": ("SECURITY", "MEDIUM", "Logs a user onto the local computer."),
    "logonuserw": ("SECURITY", "MEDIUM", "Logs a user onto the local computer (Unicode)."),
}


@dataclass
class ImportInfo:
    """
    Detailed information for an individual imported Windows API function.
    """
    dll: str
    api: str
    category: str
    risk_relevance: str
    explanation: str
    ordinal: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns the exact Module 07 item contract."""
        return {
            "dll": self.dll,
            "api": self.api,
            "category": self.category,
            "risk_relevance": self.risk_relevance,
            "explanation": self.explanation,
        }


@dataclass
class ImportAnalysisResult:
    """
    Structured outcome of the Windows API Import Analysis.
    """
    total_dlls: int = 0
    total_imports: int = 0
    categories_summary: Dict[str, int] = field(default_factory=dict)
    imports: List[ImportInfo] = field(default_factory=list)
    is_valid: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns the structured summary and imports list."""
        return {
            "total_dlls": self.total_dlls,
            "total_imports": self.total_imports,
            "categories_summary": self.categories_summary,
            "imports": [imp.to_dict() for imp in self.imports],
        }


class WindowsAPIImportAnalyzer:
    """
    Static Windows PE Import Table Analyzer.
    """

    def __init__(self, custom_api_db: Optional[Dict[str, Tuple[str, str, str]]] = None):
        self.api_db = dict(DEFAULT_API_DATABASE)
        if custom_api_db:
            # Normalize keys to lowercase for case-insensitive lookup
            for k, v in custom_api_db.items():
                self.api_db[k.lower()] = v

    def register_api(self, api_name: str, category: str, risk_relevance: str, explanation: str) -> None:
        """Dynamically registers or overrides an API category configuration."""
        self.api_db[api_name.lower()] = (category.upper(), risk_relevance.upper(), explanation)

    def classify_api(self, api_name: str) -> Tuple[str, str, str]:
        """
        Classifies an API function name into category, risk_relevance, and explanation.
        """
        lookup_key = api_name.lower()
        if lookup_key in self.api_db:
            return self.api_db[lookup_key]

        # Generic heuristics for common prefixes
        if lookup_key.startswith(("reg", "advapi")):
            return "REGISTRY", "LOW", "Windows Registry or Security API."
        elif lookup_key.startswith(("crypt", "bcrypt", "ncrypt")):
            return "CRYPTOGRAPHY", "LOW", "Cryptographic operation API."
        elif lookup_key.startswith(("net", "socket", "wsa", "http", "ftp", "internet")):
            return "NETWORK", "LOW", "Network communication API."
        elif lookup_key.startswith(("file", "io", "dir")):
            return "FILE", "LOW", "File or I/O system API."
        elif lookup_key.startswith(("proc", "thread", "exec")):
            return "PROCESS", "LOW", "Process or Thread management API."
        else:
            return "OTHER", "LOW", "General system or application runtime API."

    @staticmethod
    def _sanitize_name(raw_name: Union[bytes, str]) -> str:
        """Cleans and decodes byte string names."""
        if isinstance(raw_name, bytes):
            return raw_name.decode("latin-1", errors="replace").strip()
        return str(raw_name).strip()

    def analyze_bytes(self, data: bytes) -> ImportAnalysisResult:
        """
        Parses PE import tables from raw byte data statically.

        Args:
            data: Raw binary byte sequence.

        Returns:
            ImportAnalysisResult object.
        """
        if not data:
            return ImportAnalysisResult(
                total_dlls=0,
                total_imports=0,
                categories_summary={},
                imports=[],
                is_valid=True,
                error_message=None
            )

        if len(data) < 64 or data[:2] != b"MZ":
            return ImportAnalysisResult(
                total_dlls=0,
                total_imports=0,
                categories_summary={},
                imports=[],
                is_valid=False,
                error_message="Input data is not a valid Windows PE binary (Missing DOS MZ signature)."
            )

        try:
            pe = pefile.PE(data=data, fast_load=False)
        except pefile.PEFormatError as pe_err:
            return ImportAnalysisResult(
                total_dlls=0,
                total_imports=0,
                categories_summary={},
                imports=[],
                is_valid=False,
                error_message=f"Failed to parse PE binary headers: {pe_err}"
            )
        except Exception as e:
            return ImportAnalysisResult(
                total_dlls=0,
                total_imports=0,
                categories_summary={},
                imports=[],
                is_valid=False,
                error_message=f"Unexpected error initializing PE parser: {e}"
            )

        extracted_imports: List[ImportInfo] = []
        dll_count = 0
        categories_count: Dict[str, int] = {}

        try:
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = self._sanitize_name(getattr(entry, "dll", b"UNKNOWN.dll"))

                    for imp in getattr(entry, "imports", []):
                        if getattr(imp, "name", None):
                            api_name = self._sanitize_name(imp.name)
                            ordinal = getattr(imp, "ordinal", None)
                        else:
                            ordinal = getattr(imp, "ordinal", 0)
                            api_name = f"Ordinal_{ordinal}"

                        category, risk, explanation = self.classify_api(api_name)

                        categories_count[category] = categories_count.get(category, 0) + 1

                        extracted_imports.append(ImportInfo(
                            dll=dll_name,
                            api=api_name,
                            category=category,
                            risk_relevance=risk,
                            explanation=explanation,
                            ordinal=ordinal
                        ))
        finally:
            pe.close()

        return ImportAnalysisResult(
            total_dlls=dll_count,
            total_imports=len(extracted_imports),
            categories_summary=categories_count,
            imports=extracted_imports,
            is_valid=True,
            error_message=None
        )

    def analyze_file(self, file_path: Union[str, Path]) -> ImportAnalysisResult:
        """
        Loads a file from disk and parses its imports statically without execution.

        Args:
            file_path: Path to target file.

        Returns:
            ImportAnalysisResult object.
        """
        target = Path(file_path)
        if not target.exists() or not target.is_file():
            return ImportAnalysisResult(
                total_dlls=0,
                total_imports=0,
                categories_summary={},
                imports=[],
                is_valid=False,
                error_message=f"Target file not found at path: {file_path}"
            )

        try:
            with open(target, "rb") as f:
                content = f.read()
            return self.analyze_bytes(content)
        except PermissionError as pe:
            return ImportAnalysisResult(
                total_dlls=0,
                total_imports=0,
                categories_summary={},
                imports=[],
                is_valid=False,
                error_message=f"Permission denied reading file '{file_path}': {pe}"
            )
        except Exception as e:
            return ImportAnalysisResult(
                total_dlls=0,
                total_imports=0,
                categories_summary={},
                imports=[],
                is_valid=False,
                error_message=f"Failed to read file '{file_path}': {str(e)}"
            )


# Global singleton instance
windows_api_import_analyzer_service = WindowsAPIImportAnalyzer()


if __name__ == "__main__":
    import json

    print("=" * 68)
    print("  ETHIO-AI Defender - Module 07: Windows API Import Analyzer Demo")
    print("=" * 68)

    analyzer = WindowsAPIImportAnalyzer()

    # Demonstration classification check
    apis_to_check = [
        "CreateFileA", "CreateProcessA", "VirtualAlloc", "VirtualProtect",
        "InternetOpenA", "RegOpenKeyExA", "CreateServiceA", "CryptEncrypt",
        "GetSystemInfo", "MessageBoxA", "CreateRemoteThread", "AdjustTokenPrivileges"
    ]

    print("\nAPI Classification Verification:")
    for api in apis_to_check:
        cat, risk, exp = analyzer.classify_api(api)
        sample_item = {
            "dll": "KERNEL32.dll",
            "api": api,
            "category": cat,
            "risk_relevance": risk,
            "explanation": exp,
        }
        print(f"  - {api:<22} -> [{cat:<18}] Risk: {risk:<6} | {exp}")

    print("=" * 68)
