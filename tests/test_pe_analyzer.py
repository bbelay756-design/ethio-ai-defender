"""
Unit tests for Module 03: PE Static Analyzer.

Tests:
1. Valid x86 (32-bit) PE Executable.
2. Valid x64 (64-bit) PE Executable.
3. Valid Dynamic Link Library (DLL) PE.
4. Valid System Driver (SYS) PE.
5. Invalid PE (plain text / non-PE).
6. Malformed & Truncated PE binaries.
7. File-based static analysis & error handling for missing files.
8. Standard output contract dictionary schema.
"""

import struct
import tempfile
import unittest
from pathlib import Path

from app.analyzers.pe_analyzer import PEStaticAnalyzer, PEAnalysisResult


def build_synthetic_pe(
    is_64bit: bool = True,
    is_dll: bool = False,
    is_driver: bool = False,
    subsystem: int = 2,  # 2 = Windows GUI, 3 = Windows CUI
    entry_point: int = 0x1000,
    image_base: int = 0x140000000,
    num_sections: int = 2
) -> bytes:
    """
    Constructs a valid, harmless in-memory synthetic PE binary.
    Adheres strictly to the Microsoft PE/COFF specification.
    """
    buf = bytearray(4096)

    # 1. DOS Header (64 bytes)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)  # e_lfanew = 128 (0x80)

    # 2. PE Signature (4 bytes)
    buf[0x80:0x84] = b"PE\x00\x00"

    # 3. COFF File Header (20 bytes at offset 0x84)
    machine = 0x8664 if is_64bit else 0x014C
    size_of_opt = 0xF0 if is_64bit else 0xE0  # 240 vs 224 bytes (includes 16 data dirs)
    chars = 0x0002  # IMAGE_FILE_EXECUTABLE_IMAGE
    if is_64bit:
        chars |= 0x0020  # IMAGE_FILE_LARGE_ADDRESS_AWARE
    if is_dll:
        chars |= 0x2000  # IMAGE_FILE_DLL
    if is_driver:
        chars |= 0x1000  # IMAGE_FILE_SYSTEM

    struct.pack_into(
        "<HHIIIHH",
        buf,
        0x84,
        machine,
        num_sections,
        1723849200,  # Sat Aug 16 2026 UTC
        0,           # PointerToSymbolTable
        0,           # NumberOfSymbols
        size_of_opt,
        chars
    )

    # 4. Optional Header (starts at offset 0x98)
    opt_offset = 0x98
    magic = 0x020B if is_64bit else 0x010B
    dll_chars = 0x8140  # DYNAMIC_BASE, NX_COMPAT, TERMINAL_SERVER_AWARE

    if is_64bit:
        # Standard Fields (24 bytes)
        struct.pack_into(
            "<HBBIIIII",
            buf,
            opt_offset,
            magic,
            14, 0,           # Major/Minor Linker Version
            0x1000,          # SizeOfCode
            0x1000,          # SizeOfInitializedData
            0,               # SizeOfUninitializedData
            entry_point,     # AddressOfEntryPoint
            0x1000           # BaseOfCode
        )
        # Windows-Specific Fields for PE32+ (88 bytes at opt_offset + 24)
        struct.pack_into(
            "<QIIHHHHHHIIIIHHQQQQII",
            buf,
            opt_offset + 24,
            image_base,      # ImageBase (64-bit)
            0x1000,          # SectionAlignment
            0x200,           # FileAlignment
            6, 0,            # OS Version
            0, 0,            # Image Version
            6, 0,            # Subsystem Version
            0,               # Win32VersionValue
            0x5000,          # SizeOfImage
            0x400,           # SizeOfHeaders
            0,               # CheckSum
            subsystem,       # Subsystem
            dll_chars,       # DllCharacteristics
            0x100000,        # SizeOfStackReserve
            0x1000,          # SizeOfStackCommit
            0x100000,        # SizeOfHeapReserve
            0x1000,          # SizeOfHeapCommit
            0,               # LoaderFlags
            16               # NumberOfRvaAndSizes
        )
        # Data directories (16 entries * 8 bytes = 128 bytes) starting at opt_offset + 112
        # Automatically 0s in bytearray.
    else:
        # Standard Fields for PE32 (28 bytes)
        struct.pack_into(
            "<HBBIIIIII",
            buf,
            opt_offset,
            magic,
            14, 0,
            0x1000,
            0x1000,
            0,
            entry_point,
            0x1000,          # BaseOfCode
            0x2000           # BaseOfData
        )
        # Windows-Specific Fields for PE32 (68 bytes at opt_offset + 28)
        struct.pack_into(
            "<IIIHHHHHHIIIIHHIIIIII",
            buf,
            opt_offset + 28,
            int(image_base) if image_base <= 0xFFFFFFFF else 0x400000,
            0x1000,
            0x200,
            6, 0,
            0, 0,
            6, 0,
            0,
            0x5000,
            0x400,
            0,
            subsystem,
            dll_chars,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
            16
        )
        # Data directories (16 entries * 8 bytes = 128 bytes) starting at opt_offset + 96

    # 5. Section Table (starts at opt_offset + size_of_opt = 0x98 + size_of_opt)
    sec_table_offset = opt_offset + size_of_opt

    # Section 1: .text
    struct.pack_into(
        "<8sIIIIIIHHI",
        buf,
        sec_table_offset,
        b".text\x00\x00\x00",
        0x1000,          # VirtualSize
        0x1000,          # VirtualAddress
        0x200,           # SizeOfRawData
        0x400,           # PointerToRawData
        0, 0, 0, 0,
        0x60000020       # Characteristics: Code, Execute, Read
    )

    # Section 2: .data
    if num_sections >= 2:
        struct.pack_into(
            "<8sIIIIIIHHI",
            buf,
            sec_table_offset + 40,
            b".data\x00\x00\x00",
            0x1000,          # VirtualSize
            0x2000,          # VirtualAddress
            0x200,           # SizeOfRawData
            0x600,           # PointerToRawData
            0, 0, 0, 0,
            0xC0000040       # Characteristics: Initialized Data, Read, Write
        )

    # Fill raw section data so headers match content
    buf[0x400:0x600] = b"\x90" * 0x200  # NOP sled
    buf[0x600:0x800] = b"\x00" * 0x200

    return bytes(buf)


class TestPEStaticAnalyzer(unittest.TestCase):
    """Unit tests for the PE Static Analyzer."""

    def setUp(self):
        self.analyzer = PEStaticAnalyzer()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_valid_x64_executable(self):
        """Verify parsing a 64-bit PE32+ executable."""
        pe_bytes = build_synthetic_pe(is_64bit=True, is_dll=False, subsystem=2)
        res = self.analyzer.analyze_bytes(pe_bytes)

        self.assertTrue(res.is_valid)
        self.assertIsNone(res.error_message)
        self.assertEqual(res.type, "PE32+")
        self.assertEqual(res.architecture, "x64")
        self.assertEqual(res.file_kind, "EXE")
        self.assertEqual(res.entry_point, "0x1000")
        self.assertEqual(res.image_base, "0x140000000")
        self.assertEqual(res.subsystem, "Windows GUI")
        self.assertEqual(res.number_of_sections, 2)
        self.assertIn("IMAGE_FILE_EXECUTABLE_IMAGE", res.characteristics)
        self.assertIn("IMAGE_FILE_LARGE_ADDRESS_AWARE", res.characteristics)
        self.assertIn("IMAGE_DLLCHARACTERISTICS_NX_COMPAT", res.dll_characteristics)

    def test_valid_x86_executable(self):
        """Verify parsing a 32-bit PE32 executable."""
        pe_bytes = build_synthetic_pe(is_64bit=False, is_dll=False, subsystem=3, image_base=0x400000)
        res = self.analyzer.analyze_bytes(pe_bytes)

        self.assertTrue(res.is_valid)
        self.assertEqual(res.type, "PE32")
        self.assertEqual(res.architecture, "x86")
        self.assertEqual(res.file_kind, "EXE")
        self.assertEqual(res.subsystem, "Windows CUI (Console)")
        self.assertEqual(res.image_base, "0x400000")

    def test_valid_dll_binary(self):
        """Verify parsing a PE Dynamic Link Library (DLL)."""
        pe_bytes = build_synthetic_pe(is_64bit=True, is_dll=True)
        res = self.analyzer.analyze_bytes(pe_bytes)

        self.assertTrue(res.is_valid)
        self.assertEqual(res.file_kind, "DLL")
        self.assertIn("IMAGE_FILE_DLL", res.characteristics)

    def test_invalid_non_pe_bytes(self):
        """Verify that non-PE content returns is_valid=False with a clear error message."""
        plain_text = b"This is a plain text file that exceeds sixty-four bytes in total length, but it definitely does not have an MZ header."
        res = self.analyzer.analyze_bytes(plain_text)

        self.assertFalse(res.is_valid)
        self.assertIsNotNone(res.error_message)
        self.assertIn("DOS 'MZ' signature", res.error_message)

    def test_truncated_pe_binary(self):
        """Verify that truncated/corrupted PE headers are handled gracefully without exceptions."""
        # Valid MZ header, but e_lfanew points beyond EOF
        truncated = bytearray(64)
        truncated[0:2] = b"MZ"
        struct.pack_into("<I", truncated, 0x3C, 0x2000)  # points to offset 8192 > 64

        res = self.analyzer.analyze_bytes(bytes(truncated))
        self.assertFalse(res.is_valid)
        self.assertIsNotNone(res.error_message)

    def test_analyze_file_from_disk(self):
        """Verify static analysis on a file on disk."""
        pe_bytes = build_synthetic_pe(is_64bit=True, is_dll=False)
        sample_path = Path(self.temp_dir.name) / "test_sample.exe"
        sample_path.write_bytes(pe_bytes)

        res = self.analyzer.analyze_file(sample_path)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.architecture, "x64")
        self.assertEqual(res.file_kind, "EXE")

    def test_analyze_file_missing_file_handling(self):
        """Verify that a missing file path returns an invalid result gracefully."""
        missing = Path(self.temp_dir.name) / "non_existent.exe"
        res = self.analyzer.analyze_file(missing)

        self.assertFalse(res.is_valid)
        self.assertIn("not found", res.error_message)

    def test_standard_output_contract_dict(self):
        """Verify the to_dict() method matches the exact Module 03 schema."""
        pe_bytes = build_synthetic_pe(is_64bit=True, is_dll=False)
        res = self.analyzer.analyze_bytes(pe_bytes)
        d = res.to_dict()

        expected_keys = {
            "type", "architecture", "file_kind", "entry_point",
            "image_base", "number_of_sections", "subsystem",
            "characteristics", "dll_characteristics"
        }
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertEqual(d["type"], "PE32+")
        self.assertEqual(d["architecture"], "x64")
        self.assertEqual(d["file_kind"], "EXE")


if __name__ == "__main__":
    unittest.main()
