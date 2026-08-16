"""
Module 04: PE Section Analyzer

Responsibility:
Performs deep static inspection of all sections within a Windows Portable Executable (PE) binary.

Analyzes per section:
- Name (.text, .rdata, .data, .rsrc, .reloc, etc.)
- Virtual Address & Virtual Size (memory layout)
- Raw Size & Raw Data Offset (disk footprint)
- Section Characteristics & Permission Flags (Readable, Writable, Executable)
- Recognition of standard vs non-standard section names

Detects Potential Section Anomalies:
- W+X (Writable and Executable) sections (violates W^X security principle).
- Virtual Size vs Raw Size discrepancies (e.g., raw_size == 0 with virtual_size > 0, or extreme expansion).
- Raw Size significantly exceeding Virtual Size (slack/steganographic payload risk).
- Unusual permissions for standard sections (e.g., .text writable, .data executable, .rsrc executable).
- Non-standard executable section names (common in packers, crypters, and custom stagers).
- Unusually large sections exceeding typical binary thresholds.
- Sections with zero permissions (neither R, W, nor X).

Safety & Educational Disclaimer:
- Strictly static inspection; NEVER executes the file.
- An unusual section is NOT automatically malware.
- All anomalies are reported objectively as technical evidence.
"""

from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Set
from dataclasses import dataclass, field
import pefile

from app.core.logger import logger

# Recognized Standard PE Section Names
STANDARD_SECTION_NAMES: Set[str] = {
    ".text",     # Executable code
    ".data",     # Read/write initialized data
    ".rdata",    # Read-only initialized data
    ".bss",      # Uninitialized data
    ".idata",    # Import tables
    ".edata",    # Export tables
    ".rsrc",     # Resource directory (icons, dialogs, manifests)
    ".reloc",    # Base relocations
    ".pdata",    # Exception handling tables (x64)
    ".tls",      # Thread local storage
    ".gfids",    # Guard CF memory table
    ".00cfg",    # Control Flow Guard function table
    ".cormeta",  # CLR metadata (.NET)
    ".CRT",      # C++ runtime initialization
    ".wixburn",  # WiX bootstrapper
    ".debug",    # Debugging symbols
    "CODE",      # Borland/Delphi legacy code section
    "DATA",      # Borland/Delphi legacy data section
    "BSS",       # Borland/Delphi legacy BSS section
}

# Characteristics Flag Bitmasks
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000

# Mapping of section characteristics to human-readable strings
SECTION_FLAGS_MAP: Dict[int, str] = {
    0x00000020: "IMAGE_SCN_CNT_CODE",
    0x00000040: "IMAGE_SCN_CNT_INITIALIZED_DATA",
    0x00000080: "IMAGE_SCN_CNT_UNINITIALIZED_DATA",
    0x02000000: "IMAGE_SCN_MEM_DISCARDABLE",
    0x04000000: "IMAGE_SCN_MEM_NOT_CACHED",
    0x08000000: "IMAGE_SCN_MEM_NOT_PAGED",
    0x10000000: "IMAGE_SCN_MEM_SHARED",
    0x20000000: "IMAGE_SCN_MEM_EXECUTE",
    0x40000000: "IMAGE_SCN_MEM_READ",
    0x80000000: "IMAGE_SCN_MEM_WRITE",
}


@dataclass
class SectionInfo:
    """
    Detailed technical representation of a single PE section.
    """
    name: str
    virtual_address: str
    virtual_size: int
    raw_size: int
    raw_offset: str
    readable: bool
    writable: bool
    executable: bool
    characteristics: List[str] = field(default_factory=list)
    characteristics_raw: str = "0x0"
    is_standard_name: bool = True
    indicators: List[str] = field(default_factory=list)
    virtual_address_int: int = 0
    raw_offset_int: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """
        Returns the section dictionary formatted precisely to the Module 04 contract.
        """
        return {
            "name": self.name,
            "virtual_address": self.virtual_address,
            "virtual_size": self.virtual_size,
            "raw_size": self.raw_size,
            "readable": self.readable,
            "writable": self.writable,
            "executable": self.executable,
            "indicators": self.indicators,
        }

    def to_extended_dict(self) -> Dict[str, Any]:
        """
        Returns full detailed metadata including raw offsets and decoded flags.
        """
        d = self.to_dict()
        d.update({
            "raw_offset": self.raw_offset,
            "characteristics": self.characteristics,
            "characteristics_raw": self.characteristics_raw,
            "is_standard_name": self.is_standard_name,
        })
        return d


@dataclass
class PESectionAnalysisResult:
    """
    Complete outcome of the PE Section Analyzer.
    """
    total_sections: int = 0
    sections: List[SectionInfo] = field(default_factory=list)
    anomalous_sections_count: int = 0
    has_wx_sections: bool = False
    is_valid: bool = False
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns the complete structured JSON response for Module 04."""
        return {
            "total_sections": self.total_sections,
            "has_wx_sections": self.has_wx_sections,
            "anomalous_sections_count": self.anomalous_sections_count,
            "sections": [sec.to_dict() for sec in self.sections],
        }


class PESectionAnalyzer:
    """
    PE Section Analyzer Engine.
    Inspects all section headers and evaluates potential structural anomalies.
    """

    @staticmethod
    def _parse_characteristics_flags(raw_val: int) -> List[str]:
        """Decodes raw 32-bit section characteristics into standard flag strings."""
        flags: List[str] = []
        for mask, name in SECTION_FLAGS_MAP.items():
            if raw_val & mask:
                flags.append(name)
        return flags

    @staticmethod
    def _sanitize_section_name(name_bytes: bytes) -> str:
        """Decodes and cleans up section names, removing trailing null padding."""
        try:
            name_str = name_bytes.decode("latin-1", errors="replace")
            return name_str.split("\x00")[0].strip()
        except Exception:
            return "unknown"

    def _evaluate_section_anomalies(
        self,
        name: str,
        virtual_size: int,
        raw_size: int,
        readable: bool,
        writable: bool,
        executable: bool,
        is_standard_name: bool
    ) -> List[str]:
        """
        Evaluates potential anomalies for a section without calling it malware.
        """
        indicators: List[str] = []
        name_lower = name.lower()

        # 1. W+X (Writable + Executable) violation
        if writable and executable:
            indicators.append(
                "Writable and Executable (W+X): Section permits both memory modification and execution (violates W^X policy)."
            )

        # 2. Virtual Size >> Raw Size (Packing / Dynamic Buffer indicator)
        if virtual_size > 0 and raw_size == 0:
            indicators.append(
                "Zero Raw Size: Section occupies memory (VirtualSize > 0) but has 0 bytes on disk (uninitialized buffer or packed code staging)."
            )
        elif raw_size > 512 and virtual_size > (raw_size * 5):
            indicators.append(
                f"Virtual/Raw Size Discrepancy: Virtual size ({virtual_size} bytes) is over 5x larger than disk raw size ({raw_size} bytes)."
            )

        # 3. Raw Size >> Virtual Size (Slack space / Hidden payload indicator)
        if raw_size > 0 and virtual_size > 0 and raw_size > (virtual_size + 4096):
            indicators.append(
                f"Disk Slack Discrepancy: Raw size on disk ({raw_size} bytes) significantly exceeds virtual memory size ({virtual_size} bytes)."
            )

        # 4. Unusual Permissions for Standard Section Names
        if name_lower == ".text" and writable:
            indicators.append(
                "Unusual Permission: Standard code section (.text) is marked Writable."
            )
        if name_lower in {".data", ".rdata", ".bss"} and executable:
            indicators.append(
                f"Unusual Permission: Standard data section ({name}) is marked Executable."
            )
        if name_lower == ".rsrc" and (executable or writable):
            indicators.append(
                f"Unusual Permission: Standard resource section (.rsrc) is marked {'Executable' if executable else 'Writable'}."
            )
        if name_lower == ".reloc" and (executable or writable):
            indicators.append(
                f"Unusual Permission: Relocation section (.reloc) is marked {'Executable' if executable else 'Writable'}."
            )

        # 5. Non-Standard Section Name with Executable Flag
        if executable and not is_standard_name:
            indicators.append(
                f"Non-Standard Executable Section: Section '{name}' contains executable code with a non-standard name."
            )

        # 6. Zero Permissions (neither R, W, nor X)
        if not readable and not writable and not executable:
            indicators.append(
                "Zero Permissions: Section has no read, write, or execute permissions defined."
            )

        # 7. Unusually Large Section (> 50 MB)
        if raw_size > 50 * 1024 * 1024 or virtual_size > 50 * 1024 * 1024:
            indicators.append(
                "Unusually Large Section: Section dimensions exceed 50 MB."
            )

        return indicators

    def analyze_pe(self, pe: pefile.PE) -> PESectionAnalysisResult:
        """
        Parses all sections from an already loaded pefile.PE instance.
        """
        if not hasattr(pe, "sections") or not pe.sections:
            return PESectionAnalysisResult(
                total_sections=0,
                sections=[],
                anomalous_sections_count=0,
                has_wx_sections=False,
                is_valid=True,
                error_message=None
            )

        parsed_sections: List[SectionInfo] = []
        anomalous_count = 0
        has_wx = False

        for sec in pe.sections:
            raw_name = getattr(sec, "Name", b"")
            name = self._sanitize_section_name(raw_name)
            is_standard = name in STANDARD_SECTION_NAMES

            char_val = getattr(sec, "Characteristics", 0)
            readable = bool(char_val & IMAGE_SCN_MEM_READ)
            writable = bool(char_val & IMAGE_SCN_MEM_WRITE)
            executable = bool(char_val & IMAGE_SCN_MEM_EXECUTE)

            if writable and executable:
                has_wx = True

            v_addr = getattr(sec, "VirtualAddress", 0)
            v_size = getattr(sec, "Misc_VirtualSize", 0)
            r_size = getattr(sec, "SizeOfRawData", 0)
            r_offset = getattr(sec, "PointerToRawData", 0)

            char_flags = self._parse_characteristics_flags(char_val)

            # Evaluate potential anomaly indicators
            indicators = self._evaluate_section_anomalies(
                name=name,
                virtual_size=v_size,
                raw_size=r_size,
                readable=readable,
                writable=writable,
                executable=executable,
                is_standard_name=is_standard
            )

            if indicators:
                anomalous_count += 1

            sec_info = SectionInfo(
                name=name,
                virtual_address=hex(v_addr),
                virtual_size=v_size,
                raw_size=r_size,
                raw_offset=hex(r_offset),
                readable=readable,
                writable=writable,
                executable=executable,
                characteristics=char_flags,
                characteristics_raw=hex(char_val),
                is_standard_name=is_standard,
                indicators=indicators,
                virtual_address_int=v_addr,
                raw_offset_int=r_offset,
            )
            parsed_sections.append(sec_info)

        return PESectionAnalysisResult(
            total_sections=len(parsed_sections),
            sections=parsed_sections,
            anomalous_sections_count=anomalous_count,
            has_wx_sections=has_wx,
            is_valid=True,
            error_message=None
        )

    def analyze_bytes(self, data: bytes) -> PESectionAnalysisResult:
        """
        Parses all sections from raw binary bytes.
        """
        if not data or len(data) < 64:
            return PESectionAnalysisResult(
                is_valid=False,
                error_message="Binary data too small to contain valid PE section headers."
            )

        if data[:2] != b"MZ":
            return PESectionAnalysisResult(
                is_valid=False,
                error_message="Missing DOS 'MZ' signature at byte offset 0."
            )

        try:
            pe = pefile.PE(data=data, fast_load=False)
            res = self.analyze_pe(pe)
            pe.close()
            return res
        except pefile.PEFormatError as err:
            logger.warning(f"PE Section parsing error: {err}")
            return PESectionAnalysisResult(
                is_valid=False,
                error_message=f"Corrupt or malformed PE format: {str(err)}"
            )
        except Exception as err:
            logger.error(f"Unexpected error during PE section analysis: {err}")
            return PESectionAnalysisResult(
                is_valid=False,
                error_message=f"Internal section parsing exception: {str(err)}"
            )

    def analyze_file(self, file_path: Union[str, Path]) -> PESectionAnalysisResult:
        """
        Loads a file from disk and parses its sections safely without execution.
        """
        target = Path(file_path)
        if not target.exists() or not target.is_file():
            return PESectionAnalysisResult(
                is_valid=False,
                error_message=f"Target file not found at path: {file_path}"
            )

        try:
            with open(target, "rb") as f:
                content = f.read()
            return self.analyze_bytes(content)
        except PermissionError as pe:
            return PESectionAnalysisResult(
                is_valid=False,
                error_message=f"Permission denied accessing file '{file_path}': {pe}"
            )
        except Exception as e:
            return PESectionAnalysisResult(
                is_valid=False,
                error_message=f"Failed to read file '{file_path}': {str(e)}"
            )


# Global singleton instance
pe_section_analyzer_service = PESectionAnalyzer()


if __name__ == "__main__":
    import json
    from tests.test_pe_analyzer import build_synthetic_pe

    print("=" * 68)
    print("  ETHIO-AI Defender - Module 04: PE Section Analyzer Demo")
    print("=" * 68)

    analyzer = PESectionAnalyzer()
    demo_pe = build_synthetic_pe(is_64bit=True, is_dll=False, num_sections=2)
    result = analyzer.analyze_bytes(demo_pe)

    print(f"Total Sections Analyzed : {result.total_sections}")
    print(f"Has W+X Violations      : {result.has_wx_sections}")
    print(f"Anomalous Sections Count: {result.anomalous_sections_count}")
    print("\nSections JSON Output:")
    print(json.dumps(result.to_dict(), indent=2))
    print("=" * 68)
