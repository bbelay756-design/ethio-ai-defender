"""
Module 03: PE Static Analyzer

Responsibility:
Performs deep static structure analysis of Windows Portable Executable (PE) binaries
using the `pefile` library without execution.

Analyzes:
- DOS Header (e_magic, e_lfanew)
- PE / COFF File Header (Machine, NumberOfSections, TimeDateStamp, Characteristics)
- Optional Header (Magic, Entry Point, Image Base, Alignment, Subsystem, DllCharacteristics)
- Architecture classification (PE32 / PE32+, x86 / x64 / ARM / ARM64)
- File kind identification (EXE, DLL, SYS)
- Section header table extraction

Safety:
- Strictly static in-memory parsing.
- Handles corrupted, truncated, or malformed headers gracefully.
- Never designates malformed headers as malicious.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, field
import pefile

from app.core.logger import logger

# Machine Architecture Mappings
MACHINE_TYPE_MAP: Dict[int, str] = {
    0x014C: "x86",        # IMAGE_FILE_MACHINE_I386
    0x8664: "x64",        # IMAGE_FILE_MACHINE_AMD64
    0x01C0: "ARM",        # IMAGE_FILE_MACHINE_ARM
    0xAA64: "ARM64",      # IMAGE_FILE_MACHINE_ARM64
    0x0200: "IA64",       # IMAGE_FILE_MACHINE_IA64
}

# Optional Header Magic Mappings
OPTIONAL_MAGIC_MAP: Dict[int, str] = {
    0x10B: "PE32",        # 32-bit executable
    0x20B: "PE32+",       # 64-bit executable (PE32+)
    0x107: "ROM",         # ROM image
}

# Windows Subsystem Mappings
SUBSYSTEM_MAP: Dict[int, str] = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI (Console)",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    14: "Xbox",
}

# Common File Header Characteristics Flags
FILE_CHARACTERISTICS_FLAGS: Dict[int, str] = {
    0x0001: "IMAGE_FILE_RELOCS_STRIPPED",
    0x0002: "IMAGE_FILE_EXECUTABLE_IMAGE",
    0x0004: "IMAGE_FILE_LINE_NUMS_STRIPPED",
    0x0008: "IMAGE_FILE_LOCAL_SYMS_STRIPPED",
    0x0010: "IMAGE_FILE_AGGRESIVE_WS_TRIM",
    0x0020: "IMAGE_FILE_LARGE_ADDRESS_AWARE",
    0x0080: "IMAGE_FILE_BYTES_REVERSED_LO",
    0x0100: "IMAGE_FILE_32BIT_MACHINE",
    0x0200: "IMAGE_FILE_DEBUG_STRIPPED",
    0x0400: "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",
    0x0800: "IMAGE_FILE_NET_RUN_FROM_SWAP",
    0x1000: "IMAGE_FILE_SYSTEM",
    0x2000: "IMAGE_FILE_DLL",
    0x4000: "IMAGE_FILE_UP_SYSTEM_ONLY",
    0x8000: "IMAGE_FILE_BYTES_REVERSED_HI",
}

# Common DLL Characteristics Flags
DLL_CHARACTERISTICS_FLAGS: Dict[int, str] = {
    0x0020: "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
    0x0040: "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
    0x0080: "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
    0x0100: "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
    0x0200: "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
    0x0400: "IMAGE_DLLCHARACTERISTICS_NO_SEH",
    0x0800: "IMAGE_DLLCHARACTERISTICS_NO_BIND",
    0x1000: "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
    0x2000: "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
    0x4000: "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
    0x8000: "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE",
}


@dataclass
class SectionHeaderSummary:
    """Summary of a single PE section header."""
    name: str
    virtual_address: str
    virtual_size: int
    raw_size: int
    characteristics: List[str] = field(default_factory=list)


@dataclass
class PEAnalysisResult:
    """
    Structured outcome of the PE Static Analysis process.
    """
    type: str = "UNKNOWN"                     # PE32, PE32+, UNKNOWN
    architecture: str = "UNKNOWN"             # x86, x64, ARM, ARM64, UNKNOWN
    file_kind: str = "UNKNOWN"                # EXE, DLL, SYS, UNKNOWN
    entry_point: str = "0x0"                  # e.g., "0x1000"
    image_base: str = "0x0"                   # e.g., "0x400000" or "0x140000000"
    number_of_sections: int = 0
    subsystem: str = "UNKNOWN"                # Windows GUI, Windows CUI, etc.
    characteristics: List[str] = field(default_factory=list)
    dll_characteristics: List[str] = field(default_factory=list)

    # Detailed Audit & Forensic Metadata
    is_valid: bool = False
    error_message: Optional[str] = None
    compile_timestamp_epoch: int = 0
    compile_timestamp_utc: Optional[str] = None
    dos_header: Dict[str, Any] = field(default_factory=dict)
    file_header: Dict[str, Any] = field(default_factory=dict)
    optional_header: Dict[str, Any] = field(default_factory=dict)
    sections: List[SectionHeaderSummary] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the standardized Module 03 output contract dictionary."""
        return {
            "type": self.type,
            "architecture": self.architecture,
            "file_kind": self.file_kind,
            "entry_point": self.entry_point,
            "image_base": self.image_base,
            "number_of_sections": self.number_of_sections,
            "subsystem": self.subsystem,
            "characteristics": self.characteristics,
            "dll_characteristics": self.dll_characteristics,
        }


class PEStaticAnalyzer:
    """
    PE Static Structure Analyzer.
    Safely inspects headers and binary layout without code execution.
    """

    @staticmethod
    def _parse_flags(value: int, flag_map: Dict[int, str]) -> List[str]:
        """Extracts human-readable flag names from bitmask value."""
        flags: List[str] = []
        for bitmask, name in flag_map.items():
            if value & bitmask:
                flags.append(name)
        return flags

    def analyze_bytes(self, data: bytes) -> PEAnalysisResult:
        """
        Parses raw binary bytes through pefile static inspection.

        Args:
            data: Raw binary byte stream.

        Returns:
            PEAnalysisResult object.
        """
        if not data or len(data) < 64:
            return PEAnalysisResult(
                is_valid=False,
                error_message="File is smaller than minimum required DOS header size (64 bytes)."
            )

        if data[:2] != b"MZ":
            return PEAnalysisResult(
                is_valid=False,
                error_message="Missing DOS 'MZ' signature at byte offset 0."
            )

        try:
            pe = pefile.PE(data=data, fast_load=False)
        except pefile.PEFormatError as err:
            logger.warning(f"PE structure parsing error: {err}")
            return PEAnalysisResult(
                is_valid=False,
                error_message=f"Corrupt or malformed PE format: {str(err)}"
            )
        except Exception as err:
            logger.error(f"Unexpected error during static PE parsing: {err}")
            return PEAnalysisResult(
                is_valid=False,
                error_message=f"Internal parsing exception: {str(err)}"
            )

        try:
            # 1. DOS Header Extraction
            dos_hdr = pe.DOS_HEADER
            dos_info = {
                "e_magic": hex(dos_hdr.e_magic),
                "e_lfanew": hex(dos_hdr.e_lfanew),
                "e_cblp": dos_hdr.e_cblp,
                "e_cp": dos_hdr.e_cp,
            }

            # 2. File / COFF Header Extraction
            file_hdr = pe.FILE_HEADER
            machine_val = file_hdr.Machine
            num_sections = file_hdr.NumberOfSections
            timestamp_val = file_hdr.TimeDateStamp
            char_val = file_hdr.Characteristics

            architecture = MACHINE_TYPE_MAP.get(machine_val, f"UNKNOWN (0x{machine_val:04X})")
            characteristics_list = self._parse_flags(char_val, FILE_CHARACTERISTICS_FLAGS)

            # Determine File Kind (EXE vs DLL vs SYS)
            if char_val & 0x2000:
                file_kind = "DLL"
            elif char_val & 0x1000:
                file_kind = "SYS"
            elif char_val & 0x0002:
                file_kind = "EXE"
            else:
                file_kind = "UNKNOWN"

            # Parse Compilation Timestamp safely
            try:
                dt = datetime.fromtimestamp(timestamp_val, tz=timezone.utc)
                timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except (ValueError, OSError):
                timestamp_str = f"Invalid Timestamp ({timestamp_val})"

            file_info = {
                "machine": hex(machine_val),
                "machine_name": architecture,
                "number_of_sections": num_sections,
                "time_date_stamp": timestamp_val,
                "timestamp_utc": timestamp_str,
                "characteristics_raw": hex(char_val),
                "characteristics": characteristics_list,
            }

            # 3. Optional Header Extraction
            opt_hdr = getattr(pe, "OPTIONAL_HEADER", None)
            pe_type = "UNKNOWN"
            entry_point_str = "0x0"
            image_base_str = "0x0"
            subsystem_str = "UNKNOWN"
            dll_characteristics_list: List[str] = []
            opt_info: Dict[str, Any] = {}

            if opt_hdr is not None:
                magic_val = getattr(opt_hdr, "Magic", 0)
                pe_type = OPTIONAL_MAGIC_MAP.get(magic_val, f"UNKNOWN (0x{magic_val:04X})")

                entry_point_val = getattr(opt_hdr, "AddressOfEntryPoint", 0)
                entry_point_str = hex(entry_point_val)

                image_base_val = getattr(opt_hdr, "ImageBase", 0)
                image_base_str = hex(image_base_val)

                subsystem_val = getattr(opt_hdr, "Subsystem", 0)
                subsystem_str = SUBSYSTEM_MAP.get(subsystem_val, f"Unknown Subsystem ({subsystem_val})")

                dll_char_val = getattr(opt_hdr, "DllCharacteristics", 0)
                dll_characteristics_list = self._parse_flags(dll_char_val, DLL_CHARACTERISTICS_FLAGS)

                opt_info = {
                    "magic": hex(magic_val),
                    "type": pe_type,
                    "address_of_entry_point": entry_point_str,
                    "image_base": image_base_str,
                    "section_alignment": getattr(opt_hdr, "SectionAlignment", 0),
                    "file_alignment": getattr(opt_hdr, "FileAlignment", 0),
                    "size_of_image": getattr(opt_hdr, "SizeOfImage", 0),
                    "size_of_headers": getattr(opt_hdr, "SizeOfHeaders", 0),
                    "subsystem_raw": subsystem_val,
                    "subsystem_name": subsystem_str,
                    "dll_characteristics_raw": hex(dll_char_val),
                    "dll_characteristics": dll_characteristics_list,
                }

            # 4. Section Headers Summary
            sections_list: List[SectionHeaderSummary] = []
            for sec in pe.sections:
                try:
                    sec_name = sec.Name.decode("latin-1", errors="replace").strip("\x00")
                except Exception:
                    sec_name = "unknown"

                sec_summary = SectionHeaderSummary(
                    name=sec_name,
                    virtual_address=hex(sec.VirtualAddress),
                    virtual_size=sec.Misc_VirtualSize,
                    raw_size=sec.SizeOfRawData,
                    characteristics=[hex(sec.Characteristics)],
                )
                sections_list.append(sec_summary)

            pe.close()

            return PEAnalysisResult(
                type=pe_type,
                architecture=architecture,
                file_kind=file_kind,
                entry_point=entry_point_str,
                image_base=image_base_str,
                number_of_sections=num_sections,
                subsystem=subsystem_str,
                characteristics=characteristics_list,
                dll_characteristics=dll_characteristics_list,
                is_valid=True,
                error_message=None,
                compile_timestamp_epoch=timestamp_val,
                compile_timestamp_utc=timestamp_str,
                dos_header=dos_info,
                file_header=file_info,
                optional_header=opt_info,
                sections=sections_list,
            )

        except Exception as err:
            logger.error(f"Error while parsing PE structure fields: {err}")
            return PEAnalysisResult(
                is_valid=False,
                error_message=f"Malformed header structure during field extraction: {str(err)}"
            )

    def analyze_file(self, file_path: Union[str, Path]) -> PEAnalysisResult:
        """
        Loads a file from disk and parses its static PE structure safely.

        Args:
            file_path: Path to the target binary.

        Returns:
            PEAnalysisResult object.
        """
        target = Path(file_path)
        if not target.exists() or not target.is_file():
            return PEAnalysisResult(
                is_valid=False,
                error_message=f"Target file not found at path: {file_path}"
            )

        try:
            with open(target, "rb") as f:
                content = f.read()
            return self.analyze_bytes(content)
        except PermissionError as pe:
            return PEAnalysisResult(
                is_valid=False,
                error_message=f"Permission denied reading file '{file_path}': {pe}"
            )
        except Exception as e:
            return PEAnalysisResult(
                is_valid=False,
                error_message=f"Failed to read file '{file_path}': {str(e)}"
            )


# Global singleton instance
pe_static_analyzer_service = PEStaticAnalyzer()


if __name__ == "__main__":
    import json
    import struct

    print("=" * 65)
    print("  ETHIO-AI Defender - Module 03: PE Static Analyzer Demo")
    print("=" * 65)

    analyzer = PEStaticAnalyzer()

    # Create a safe synthetic 64-bit PE binary
    def build_demo_pe(is_64bit=True, is_dll=False):
        buf = bytearray(1024)
        # DOS Header
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, 0x3C, 0x80)  # e_lfanew = 128
        # PE Signature
        buf[0x80:0x84] = b"PE\x00\x00"
        
        # COFF File Header
        machine = 0x8664 if is_64bit else 0x014C
        chars = 0x2002 if is_dll else 0x0022  # DLL vs EXE
        struct.pack_into("<HHIIIHH", buf, 0x84, machine, 3, 1723849200, 0, 0, 0x00F0, chars)
        
        # Optional Header (PE32+ 64-bit vs PE32 32-bit)
        magic = 0x020B if is_64bit else 0x010B
        subsystem = 2  # Windows GUI
        dll_chars = 0x8160  # NX, Dynamic Base, Terminal Server Aware
        
        if is_64bit:
            struct.pack_into("<HBBIIIIII", buf, 0x98, magic, 14, 0, 0x1000, 0x1000, 0, 0x1000, 0x1000, 0x200)
            struct.pack_into("<QIIHHHHII", buf, 0x98 + 24, 0x140000000, 0x1000, 0x200, 6, 0, 0, 0, 4, 0)
            struct.pack_into("<IIHH", buf, 0x98 + 56, 0x5000, 0x400, subsystem, dll_chars)
        else:
            struct.pack_into("<HBBIIIIII", buf, 0x98, magic, 14, 0, 0x1000, 0x1000, 0, 0x1000, 0x1000, 0x200)
            struct.pack_into("<IIIHHHHII", buf, 0x98 + 24, 0x400000, 0x1000, 0x200, 6, 0, 0, 0, 4, 0)
            struct.pack_into("<IIHH", buf, 0x98 + 52, 0x5000, 0x400, subsystem, dll_chars)
        
        return bytes(buf)

    print("\n[+] Test 1: Analyzing Synthetic 64-bit PE Executable...")
    res_x64 = analyzer.analyze_bytes(build_demo_pe(is_64bit=True, is_dll=False))
    print(json.dumps(res_x64.to_dict(), indent=2))

    print("\n[+] Test 2: Analyzing Synthetic 32-bit PE Dynamic Link Library (DLL)...")
    res_dll = analyzer.analyze_bytes(build_demo_pe(is_64bit=False, is_dll=True))
    print(json.dumps(res_dll.to_dict(), indent=2))

    print("\n[+] Test 3: Analyzing Malformed / Truncated Binary...")
    res_malformed = analyzer.analyze_bytes(b"MZ" + b"\x00" * 30)
    print(f"Is Valid     : {res_malformed.is_valid}")
    print(f"Error Detail : {res_malformed.error_message}")

    print("\n" + "=" * 65)
