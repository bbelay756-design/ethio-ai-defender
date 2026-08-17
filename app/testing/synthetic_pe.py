"""
Safe In-Memory Synthetic PE Generator for Module 18 Security Testing Framework.

CRITICAL SAFETY INVARIANT:
- This module creates ONLY harmless synthetic binary bytes in-memory for static analysis testing.
- No executable code is ever executed on the host system.
- Designed specifically for automated CI/CD and offline testing.
"""

import struct
from typing import Dict, List, Optional, Tuple


class SyntheticPEBuilder:
    """
    Builder for constructing valid, packed, suspicious, Ethiopian-targeted,
    or malformed Windows Portable Executable (PE) binaries in-memory.
    """

    @staticmethod
    def create_minimal_pe(
        sections: Optional[List[Tuple[str, bytes, int]]] = None,
        machine: int = 0x014C,  # IMAGE_FILE_MACHINE_I386
        characteristics: int = 0x0102,  # EXECUTABLE_IMAGE | 32BIT_MACHINE
        timestamp: int = 1700000000,
        subsystem: int = 2,  # IMAGE_SUBSYSTEM_WINDOWS_GUI
        custom_strings: Optional[List[str]] = None,
    ) -> bytes:
        """
        Constructs a minimal, structurally valid PE32 binary with optional custom sections and strings.
        """
        # Default sections if none provided
        if sections is None:
            # Format: (name, raw_data, characteristics)
            # Default characteristics: 0x60000020 (.text - EXECUTE, READ, CODE), 0xC0000040 (.data - READ, WRITE, INITIALIZED_DATA)
            text_bytes = b"\x90\x90\x90\x90\x90\x90\x90\x90\xC3\x00\x00\x00"
            if custom_strings:
                for s in custom_strings:
                    text_bytes += s.encode("utf-8") + b"\x00"
            # Pad to 512-byte alignment
            text_padded = text_bytes.ljust(512, b"\x00")
            data_padded = b"\x00" * 512

            sections = [
                (".text", text_padded, 0x60000020),
                (".data", data_padded, 0xC0000040),
            ]

        dos_header_size = 64
        dos_stub_size = 64
        pe_offset = dos_header_size + dos_stub_size  # 128 (0x80)

        # 1. DOS Header (64 bytes)
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 60, pe_offset)  # e_lfanew at offset 0x3C

        # 2. DOS Stub (64 bytes)
        dos_stub = b"This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        dos_stub = dos_stub.ljust(64, b"\x00")

        # 3. PE Signature
        pe_sig = b"PE\x00\x00"

        # 4. COFF File Header (20 bytes)
        num_sections = len(sections)
        size_of_optional_header = 224  # Standard PE32 Optional Header
        coff_header = struct.pack(
            "<HHIIIHH",
            machine,
            num_sections,
            timestamp,
            0,  # PointerToSymbolTable
            0,  # NumberOfSymbols
            size_of_optional_header,
            characteristics,
        )

        # 5. Optional Header Standard Fields (28 bytes)
        magic = 0x010B  # PE32
        major_linker_version = 14
        minor_linker_version = 0
        size_of_code = sum(len(raw) for name, raw, char in sections if name == ".text")
        size_of_init_data = sum(len(raw) for name, raw, char in sections if name != ".text")
        size_of_uninit_data = 0
        entry_point_rva = 0x1000
        base_of_code = 0x1000
        base_of_data = 0x2000

        opt_standard = struct.pack(
            "<HBBIIIIII",
            magic,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_init_data,
            size_of_uninit_data,
            entry_point_rva,
            base_of_code,
            base_of_data,
        )

        # 6. Optional Header Windows-Specific Fields (68 bytes)
        image_base = 0x00400000
        section_alignment = 0x1000  # 4096
        file_alignment = 0x200      # 512
        major_os = 6
        minor_os = 0
        major_image = 0
        minor_image = 0
        major_subsys = 6
        minor_subsys = 0
        win32_version = 0
        size_of_headers = 512
        checksum = 0
        dll_characteristics = 0x8140  # DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
        size_of_stack_reserve = 0x100000
        size_of_stack_commit = 0x1000
        size_of_heap_reserve = 0x100000
        size_of_heap_commit = 0x1000
        loader_flags = 0
        num_rva_and_sizes = 16

        # Calculate SizeOfImage
        size_of_image = section_alignment + (num_sections * section_alignment)

        opt_windows = struct.pack(
            "<IIIHHHHHHIIIIHHIIIIII",
            image_base,
            section_alignment,
            file_alignment,
            major_os,
            minor_os,
            major_image,
            minor_image,
            major_subsys,
            minor_subsys,
            win32_version,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            loader_flags,
            num_rva_and_sizes,
        )

        # 7. Data Directories (16 * 8 = 128 bytes, all zero for minimal binary)
        data_dirs = b"\x00" * (16 * 8)

        optional_header = opt_standard + opt_windows + data_dirs

        # 8. Section Headers (40 bytes each)
        headers_end = pe_offset + len(pe_sig) + len(coff_header) + len(optional_header) + (num_sections * 40)
        # File offset alignment
        current_raw_offset = 512
        current_virtual_address = 0x1000

        section_headers = bytearray()
        section_raw_data = bytearray()

        for name, raw_data, chars in sections:
            # 8-byte ASCII name
            name_bytes = name.encode("utf-8")[:8].ljust(8, b"\x00")
            virtual_size = len(raw_data)
            raw_size = (len(raw_data) + file_alignment - 1) & ~(file_alignment - 1)
            raw_data_padded = raw_data.ljust(raw_size, b"\x00")

            sec_header = struct.pack(
                "<8sIIIIIIHHI",
                name_bytes,
                virtual_size,
                current_virtual_address,
                raw_size,
                current_raw_offset,
                0,  # PointerToRelocations
                0,  # PointerToLinenumbers
                0,  # NumberOfRelocations
                0,  # NumberOfLinenumbers
                chars,
            )
            section_headers.extend(sec_header)
            section_raw_data.extend(raw_data_padded)

            current_virtual_address += section_alignment
            current_raw_offset += raw_size

        # Combine all parts
        headers = dos_header + dos_stub + pe_sig + coff_header + optional_header + section_headers
        headers_padded = headers.ljust(512, b"\x00")

        return bytes(headers_padded + section_raw_data)

    @classmethod
    def create_packed_pe(cls) -> bytes:
        """
        Creates a synthetic PE exhibiting indicators of UPX packing and high entropy.
        """
        # High entropy pseudo-random payload for .upx0 and .upx1
        high_entropy_bytes = bytes([((i * 137 + 73) ^ (i >> 3)) & 0xFF for i in range(1024)])
        strings_payload = b"UPX!UPX0UPX1\x00VirtualProtect\x00LoadLibraryA\x00GetProcAddress\x00"
        high_entropy_bytes = high_entropy_bytes + strings_payload

        sections = [
            ("UPX0", b"\x00" * 512, 0xE0000080),  # MEM_EXECUTE | MEM_READ | MEM_WRITE
            ("UPX1", high_entropy_bytes, 0xE0000040),
            (".rsrc", b"\x00" * 512, 0xC0000040),
        ]
        return cls.create_minimal_pe(sections=sections)

    @classmethod
    def create_suspicious_import_pe(cls) -> bytes:
        """
        Creates a synthetic PE containing suspicious API strings and persistence markers.
        """
        suspicious_strings = [
            "VirtualAlloc",
            "VirtualProtect",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "SetWindowsHookExA",
            "InternetOpenA",
            "InternetConnectA",
            "HttpSendRequestA",
            "RegSetValueExA",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "powershell.exe -ExecutionPolicy Bypass -NoProfile",
            "cmd.exe /c whoami",
            "http://c2-control-panel.com/beacon",
            "185.220.101.5",
        ]
        return cls.create_minimal_pe(custom_strings=suspicious_strings)

    @classmethod
    def create_ethiopian_targeted_pe(cls) -> bytes:
        """
        Creates a synthetic PE containing Ethiopian national infrastructure keywords,
        domains, and Amharic strings.
        """
        ethio_strings = [
            "https://ebank.cbe.com.et/retail/login",
            "telebirr://api/v1/payment/transfer",
            "inss.gov.et",
            "insa.gov.et",
            "ethionet.et",
            "196.188.1.10",
            "197.156.64.1",
            "የይለፍ ቃል",
            "የንግድ ባንክ",
            "ቴሌብር ክፍያ",
        ]
        return cls.create_minimal_pe(custom_strings=ethio_strings)

    @classmethod
    def create_malformed_pe(cls, variant: str = "bad_dos_magic") -> bytes:
        """
        Generates various malformed binary variants for perimeter & parser fuzzing.
        """
        valid_pe = bytearray(cls.create_minimal_pe())

        if variant == "bad_dos_magic":
            valid_pe[0:2] = b"XX"  # Invalid MZ
            return bytes(valid_pe)

        elif variant == "truncated_dos":
            return bytes(valid_pe[:32])  # Smaller than minimum 64-byte DOS header

        elif variant == "invalid_pe_offset":
            struct.pack_into("<I", valid_pe, 0x3C, 0xFFFFFF00)  # Pointer beyond file length
            return bytes(valid_pe)

        elif variant == "bad_pe_magic":
            # Overwrite PE\0\0 signature
            pe_offset = struct.unpack_from("<I", valid_pe, 0x3C)[0]
            valid_pe[pe_offset:pe_offset + 4] = b"DEAD"
            return bytes(valid_pe)

        elif variant == "zero_sections":
            pe_offset = struct.unpack_from("<I", valid_pe, 0x3C)[0]
            struct.pack_into("<H", valid_pe, pe_offset + 6, 0)  # NumberOfSections = 0
            return bytes(valid_pe)

        elif variant == "excessive_sections":
            pe_offset = struct.unpack_from("<I", valid_pe, 0x3C)[0]
            struct.pack_into("<H", valid_pe, pe_offset + 6, 9999)  # 9999 sections
            return bytes(valid_pe)

        elif variant == "corrupt_optional_magic":
            pe_offset = struct.unpack_from("<I", valid_pe, 0x3C)[0]
            struct.pack_into("<H", valid_pe, pe_offset + 24, 0x9999)  # Invalid magic
            return bytes(valid_pe)

        elif variant == "all_zero_bytes":
            return b"\x00" * 1024

        elif variant == "random_garbage":
            return bytes([((i * 47) ^ 0xA5) & 0xFF for i in range(1024)])

        else:
            return bytes(valid_pe)
