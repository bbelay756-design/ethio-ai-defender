"""
Live Demonstration Script for Module 03: PE Static Analyzer.
"""

import json
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.pe_analyzer import PEStaticAnalyzer
from tests.test_pe_analyzer import build_synthetic_pe


def main():
    print("=" * 70)
    print("  ETHIO-AI DEFENDER - MODULE 03: PE STATIC ANALYZER LIVE DEMO")
    print("=" * 70)

    analyzer = PEStaticAnalyzer()

    # Scenario 1: 64-bit Windows PE Executable
    print("\n[Scenario 1] Analyzing 64-bit Windows PE Executable (x64 / PE32+)...")
    pe64_bytes = build_synthetic_pe(
        is_64bit=True,
        is_dll=False,
        subsystem=2,
        entry_point=0x1000,
        image_base=0x140000000,
        num_sections=2
    )
    result_64 = analyzer.analyze_bytes(pe64_bytes)
    print("Analysis Contract Output:")
    print(json.dumps(result_64.to_dict(), indent=2))
    print(f"Compilation Timestamp (UTC): {result_64.compile_timestamp_utc}")
    print(f"Section Count: {result_64.number_of_sections}")
    for idx, sec in enumerate(result_64.sections, 1):
        print(f"  - Section {idx}: {sec.name:<8} VA: {sec.virtual_address} | VirtualSize: {sec.virtual_size} bytes")

    # Scenario 2: 32-bit Dynamic Link Library (DLL)
    print("\n[Scenario 2] Analyzing 32-bit Dynamic Link Library (x86 / PE32 DLL)...")
    pe32_dll_bytes = build_synthetic_pe(
        is_64bit=False,
        is_dll=True,
        subsystem=3,
        entry_point=0x1000,
        image_base=0x10000000,
        num_sections=2
    )
    result_dll = analyzer.analyze_bytes(pe32_dll_bytes)
    print("Analysis Contract Output:")
    print(json.dumps(result_dll.to_dict(), indent=2))

    # Scenario 3: Malformed & Truncated Binary Error Handling
    print("\n[Scenario 3] Safe Handling of Corrupted Binary (Zero Execution)...")
    corrupt_bytes = b"MZ" + b"\x00" * 40
    result_corrupt = analyzer.analyze_bytes(corrupt_bytes)
    print(f"Is Valid      : {result_corrupt.is_valid}")
    print(f"Error Message : {result_corrupt.error_message}")
    print(f"Defensive Note: Malformed structure is handled safely without calling it malware.")

    print("\n" + "=" * 70)
    print("  DEMONSTRATION COMPLETE - ZERO FILES EXECUTED")
    print("=" * 70)


if __name__ == "__main__":
    main()
