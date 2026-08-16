"""
Live Demonstration Script for Module 04: PE Section Analyzer.
"""

import json
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.section_analyzer import PESectionAnalyzer
from tests.test_section_analyzer import build_custom_sections_pe


def main():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 04: PE SECTION ANALYZER LIVE DEMO")
    print("=" * 72)

    analyzer = PESectionAnalyzer()

    # Scenario 1: Clean Standard PE with .text, .rdata, .data
    print("\n[Scenario 1] Analyzing Standard Benign PE Sections (.text, .rdata, .data)...")
    clean_spec = [
        (".text", 0x1200, 0x1200, 0x60000020),  # Code, Read, Execute
        (".rdata", 0x800, 0x800, 0x40000040),   # Initialized Data, Read
        (".data", 0x600, 0x600, 0xC0000040),    # Initialized Data, Read, Write
    ]
    pe_clean = build_custom_sections_pe(clean_spec)
    result_clean = analyzer.analyze_bytes(pe_clean)

    print(f"Total Sections      : {result_clean.total_sections}")
    print(f"Has W+X Violations : {result_clean.has_wx_sections}")
    print(f"Anomalous Sections  : {result_clean.anomalous_sections_count}")
    print("Structured Sections Output:")
    print(json.dumps(result_clean.to_dict(), indent=2))

    # Scenario 2: PE with W+X (Writable & Executable) and Packed Section Anomalies
    print("\n[Scenario 2] Analyzing PE with Section Anomalies (W+X & Packed Allocation)...")
    anomalous_spec = [
        (".text", 0x1000, 0x1000, 0x60000020),   # Standard code
        (".packed", 0x8000, 0x0, 0xC0000080),    # Uninitialized data / 0 raw size
        (".shell", 0x2000, 0x2000, 0xE0000020),  # Writable & Executable (W+X)
    ]
    pe_anom = build_custom_sections_pe(anomalous_spec)
    result_anom = analyzer.analyze_bytes(pe_anom)

    print(f"Total Sections      : {result_anom.total_sections}")
    print(f"Has W+X Violations : {result_anom.has_wx_sections}")
    print(f"Anomalous Sections  : {result_anom.anomalous_sections_count}")
    print("\nDetected Anomalies Per Section:")
    for sec in result_anom.sections:
        status_tag = f"[ANOMALOUS - {len(sec.indicators)} Indicator(s)]" if sec.indicators else "[BENIGN]"
        print(f"\n  Section '{sec.name}': {status_tag}")
        print(f"    - Virtual Size : {sec.virtual_size} bytes | Raw Size: {sec.raw_size} bytes")
        print(f"    - Permissions  : Readable={sec.readable}, Writable={sec.writable}, Executable={sec.executable}")
        if sec.indicators:
            for ind in sec.indicators:
                print(f"    - Indicator   : {ind}")

    print("\n" + "=" * 72)
    print("  DEMONSTRATION COMPLETE - ZERO FILES EXECUTED (STATIC IN-MEMORY ONLY)")
    print("=" * 72)


if __name__ == "__main__":
    main()
