"""
Live Demonstration Script for Module 05: Entropy Analyzer.
"""

import json
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.entropy_analyzer import EntropyAnalyzer
from tests.test_section_analyzer import build_custom_sections_pe


def main():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 05: ENTROPY ANALYZER LIVE DEMO")
    print("=" * 72)

    analyzer = EntropyAnalyzer()

    # 1. Mathematical Test Vectors
    print("\n[Scenario 1] Mathematical Shannon Entropy on Controlled Byte Sequences:")
    all_zeros = b"\x00" * 1024
    two_state = b"AB" * 512
    four_state = b"ABCD" * 256
    uniform_256 = bytes(range(256)) * 4

    print(f"  - All Zeros (1 unique byte)     : {analyzer.compute_entropy(all_zeros):.4f} -> [{analyzer.classify(analyzer.compute_entropy(all_zeros))}]")
    print(f"  - Two-State ('AB' alternating)   : {analyzer.compute_entropy(two_state):.4f} -> [{analyzer.classify(analyzer.compute_entropy(two_state))}]")
    print(f"  - Four-State ('ABCD' equal)      : {analyzer.compute_entropy(four_state):.4f} -> [{analyzer.classify(analyzer.compute_entropy(four_state))}]")
    print(f"  - Uniform 256 Byte Distribution  : {analyzer.compute_entropy(uniform_256):.4f} -> [{analyzer.classify(analyzer.compute_entropy(uniform_256))}]")

    # 2. Section Breakdown on a Synthetic PE Binary
    print("\n[Scenario 2] Full File & PE Section Entropy Breakdown:")
    spec = [
        (".text", 0x1000, 0x400, 0x60000020),
        (".rdata", 0x800, 0x200, 0x40000040),
        (".data", 0x600, 0x200, 0xC0000040),
    ]
    pe_bytes = build_custom_sections_pe(spec)
    result = analyzer.analyze_bytes(pe_bytes)

    print(f"File Overall Entropy: {result.file_entropy:.2f} [{result.file_classification}]")
    print("\nStructured Output Contract:")
    print(json.dumps(result.to_dict(), indent=2))

    print("\n" + "=" * 72)
    print("  DEMONSTRATION COMPLETE - ZERO FILES EXECUTED (STATIC IN-MEMORY ONLY)")
    print("=" * 72)


if __name__ == "__main__":
    main()
