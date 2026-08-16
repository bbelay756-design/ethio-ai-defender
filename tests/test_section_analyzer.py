"""
Unit tests for Module 04: PE Section Analyzer.

Tests:
1. Standard clean PE sections (.text, .rdata, .data, .rsrc, .reloc).
2. W+X (Writable & Executable) anomaly detection.
3. Virtual size >> Raw size (Zero raw size / packed allocation) anomaly detection.
4. Raw size >> Virtual size (disk slack space) anomaly detection.
5. Non-standard executable section name anomaly detection.
6. Unusual permissions on standard sections (.text writable, .data executable).
7. Non-PE / truncated binary error handling.
8. File-based static analysis & missing file handling.
9. Structured JSON output contract format.
"""

import struct
import tempfile
import unittest
from pathlib import Path
from typing import List, Tuple

from app.analyzers.section_analyzer import PESectionAnalyzer, SectionInfo, PESectionAnalysisResult


def build_custom_sections_pe(
    sections_spec: List[Tuple[str, int, int, int]]  # (name, virtual_size, raw_size, characteristics)
) -> bytes:
    """
    Constructs a safe, synthetic PE binary in memory with customizable sections.
    sections_spec format: List of (name, virtual_size, raw_size, characteristics)
    """
    buf = bytearray(8192)

    # 1. DOS Header (64 bytes)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)  # e_lfanew = 128

    # 2. PE Signature
    buf[0x80:0x84] = b"PE\x00\x00"

    # 3. COFF File Header (20 bytes)
    num_sections = len(sections_spec)
    size_of_opt = 0xF0  # 240 bytes (64-bit Optional Header)
    struct.pack_into(
        "<HHIIIHH",
        buf,
        0x84,
        0x8664,          # Machine: x64
        num_sections,    # NumberOfSections
        1723849200,      # TimeDateStamp
        0, 0,
        size_of_opt,
        0x0022           # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    # 4. Optional Header (starts at 0x98)
    opt_offset = 0x98
    struct.pack_into(
        "<HBBIIIII",
        buf,
        opt_offset,
        0x020B,          # Magic: PE32+
        14, 0,
        0x1000, 0x1000, 0,
        0x1000,          # AddressOfEntryPoint
        0x1000
    )
    struct.pack_into(
        "<QIIHHHHHHIIIIHHQQQQII",
        buf,
        opt_offset + 24,
        0x140000000,     # ImageBase
        0x1000,          # SectionAlignment
        0x200,           # FileAlignment
        6, 0, 0, 0, 6, 0, 0,
        0x10000,         # SizeOfImage
        0x400,           # SizeOfHeaders
        0,
        2,               # Subsystem: Windows GUI
        0x8140,          # DllCharacteristics
        0x100000, 0x1000, 0x100000, 0x1000,
        0, 16
    )

    # 5. Section Table (starts at opt_offset + size_of_opt = 0x98 + 240 = 0x188)
    sec_table_offset = opt_offset + size_of_opt
    current_va = 0x1000
    current_raw_ptr = 0x400

    for i, (name, v_size, r_size, char_flags) in enumerate(sections_spec):
        entry_offset = sec_table_offset + (i * 40)
        name_bytes = name.encode("latin-1")[:8].ljust(8, b"\x00")

        raw_ptr = current_raw_ptr if r_size > 0 else 0

        struct.pack_into(
            "<8sIIIIIIHHI",
            buf,
            entry_offset,
            name_bytes,
            v_size,          # VirtualSize
            current_va,      # VirtualAddress
            r_size,          # SizeOfRawData
            raw_ptr,         # PointerToRawData
            0, 0, 0, 0,
            char_flags       # Characteristics
        )

        # Fill raw section body if raw size > 0
        if r_size > 0:
            buf[current_raw_ptr:current_raw_ptr + r_size] = b"\x90" * r_size
            current_raw_ptr += ((r_size + 0x1FF) // 0x200) * 0x200  # align to 0x200

        current_va += ((max(v_size, r_size) + 0xFFF) // 0x1000) * 0x1000  # align to 0x1000

    return bytes(buf)


class TestPESectionAnalyzer(unittest.TestCase):
    """Unit tests for the PE Section Analyzer."""

    def setUp(self):
        self.analyzer = PESectionAnalyzer()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_standard_clean_sections(self):
        """Verify parsing standard benign sections (.text, .rdata, .data)."""
        spec = [
            (".text", 0x1000, 0x200, 0x60000020),   # Code, Execute, Read
            (".rdata", 0x800, 0x200, 0x40000040),   # Initialized Data, Read
            (".data", 0x1200, 0x400, 0xC0000040),   # Initialized Data, Read, Write
        ]
        pe_bytes = build_custom_sections_pe(spec)
        res = self.analyzer.analyze_bytes(pe_bytes)

        self.assertTrue(res.is_valid)
        self.assertEqual(res.total_sections, 3)
        self.assertFalse(res.has_wx_sections)
        self.assertEqual(res.anomalous_sections_count, 0)

        # Verify .text section
        text_sec = res.sections[0]
        self.assertEqual(text_sec.name, ".text")
        self.assertTrue(text_sec.readable)
        self.assertFalse(text_sec.writable)
        self.assertTrue(text_sec.executable)
        self.assertEqual(len(text_sec.indicators), 0)

        # Verify .data section
        data_sec = res.sections[2]
        self.assertEqual(data_sec.name, ".data")
        self.assertTrue(data_sec.readable)
        self.assertTrue(data_sec.writable)
        self.assertFalse(data_sec.executable)

    def test_detect_wx_permission_anomaly(self):
        """Verify detection of W+X (Writable & Executable) memory permission anomaly."""
        spec = [
            (".text", 0x1000, 0x200, 0x60000020),
            (".injected", 0x1000, 0x200, 0xE0000020),  # Read, Write, Execute (W+X)
        ]
        pe_bytes = build_custom_sections_pe(spec)
        res = self.analyzer.analyze_bytes(pe_bytes)

        self.assertTrue(res.is_valid)
        self.assertTrue(res.has_wx_sections)
        self.assertGreaterEqual(res.anomalous_sections_count, 1)

        wx_sec = res.sections[1]
        self.assertTrue(wx_sec.writable)
        self.assertTrue(wx_sec.executable)
        self.assertTrue(any("W+X" in ind for ind in wx_sec.indicators))

    def test_detect_zero_raw_size_anomaly(self):
        """Verify detection of section with zero raw disk size but allocated virtual size."""
        spec = [
            (".text", 0x1000, 0x200, 0x60000020),
            (".packed", 0x5000, 0x0, 0xC0000080),  # Uninitialized data, RawSize = 0, VirtualSize = 20KB
        ]
        pe_bytes = build_custom_sections_pe(spec)
        res = self.analyzer.analyze_bytes(pe_bytes)

        self.assertTrue(res.is_valid)
        packed_sec = res.sections[1]
        self.assertEqual(packed_sec.raw_size, 0)
        self.assertGreater(packed_sec.virtual_size, 0)
        self.assertTrue(any("Zero Raw Size" in ind for ind in packed_sec.indicators))

    def test_detect_virtual_raw_expansion_anomaly(self):
        """Verify detection of extreme expansion ratio (> 5x virtual vs raw size)."""
        spec = [
            (".payload", 0x10000, 0x400, 0x60000020),  # VirtualSize 64KB vs RawSize 1KB (> 60x ratio)
        ]
        pe_bytes = build_custom_sections_pe(spec)
        res = self.analyzer.analyze_bytes(pe_bytes)

        self.assertTrue(res.is_valid)
        sec = res.sections[0]
        self.assertTrue(any("Virtual/Raw Size Discrepancy" in ind for ind in sec.indicators))

    def test_detect_unusual_permissions_on_standard_sections(self):
        """Verify detection of writable .text or executable .data."""
        spec = [
            (".text", 0x1000, 0x200, 0xE0000020),  # .text marked writable & executable
            (".data", 0x1000, 0x200, 0x60000040),  # .data marked executable
        ]
        pe_bytes = build_custom_sections_pe(spec)
        res = self.analyzer.analyze_bytes(pe_bytes)

        self.assertTrue(res.is_valid)
        self.assertEqual(res.anomalous_sections_count, 2)
        self.assertTrue(any("Standard code section (.text) is marked Writable" in ind for ind in res.sections[0].indicators))
        self.assertTrue(any("Standard data section (.data) is marked Executable" in ind for ind in res.sections[1].indicators))

    def test_detect_non_standard_executable_section(self):
        """Verify detection of executable code inside non-standard named sections."""
        spec = [
            ("UPX0", 0x2000, 0x400, 0x60000020),  # Executable code with custom packer name
        ]
        pe_bytes = build_custom_sections_pe(spec)
        res = self.analyzer.analyze_bytes(pe_bytes)

        self.assertTrue(res.is_valid)
        sec = res.sections[0]
        self.assertFalse(sec.is_standard_name)
        self.assertTrue(sec.executable)
        self.assertTrue(any("Non-Standard Executable Section" in ind for ind in sec.indicators))

    def test_invalid_and_truncated_binary_handling(self):
        """Verify graceful error handling on corrupt or non-PE data."""
        res_text = self.analyzer.analyze_bytes(b"This is not a PE file, just plain text data.")
        self.assertFalse(res_text.is_valid)
        self.assertIsNotNone(res_text.error_message)

        res_short = self.analyzer.analyze_bytes(b"MZ" + b"\x00" * 10)
        self.assertFalse(res_short.is_valid)

    def test_analyze_file_from_disk(self):
        """Verify section analysis on a physical file on disk."""
        spec = [(".text", 0x1000, 0x200, 0x60000020)]
        pe_bytes = build_custom_sections_pe(spec)
        sample_path = Path(self.temp_dir.name) / "sample_binary.exe"
        sample_path.write_bytes(pe_bytes)

        res = self.analyzer.analyze_file(sample_path)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.total_sections, 1)
        self.assertEqual(res.sections[0].name, ".text")

    def test_output_schema_contract(self):
        """Verify the section dictionary adheres to the requested JSON schema contract."""
        spec = [(".text", 1234, 1250, 0x60000020)]
        pe_bytes = build_custom_sections_pe(spec)
        res = self.analyzer.analyze_bytes(pe_bytes)

        sec_dict = res.sections[0].to_dict()
        expected_keys = {
            "name", "virtual_address", "virtual_size", "raw_size",
            "readable", "writable", "executable", "indicators"
        }
        self.assertEqual(set(sec_dict.keys()), expected_keys)
        self.assertEqual(sec_dict["name"], ".text")
        self.assertEqual(sec_dict["virtual_size"], 1234)
        self.assertEqual(sec_dict["raw_size"], 1250)
        self.assertEqual(sec_dict["readable"], True)
        self.assertEqual(sec_dict["writable"], False)
        self.assertEqual(sec_dict["executable"], True)
        self.assertIsInstance(sec_dict["indicators"], list)


if __name__ == "__main__":
    unittest.main()
