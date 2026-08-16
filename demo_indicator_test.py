"""
Live Demonstration Script for Module 08: Suspicious Indicator Engine.
"""

import json
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.indicator_engine import SuspiciousIndicatorEngine
from app.analyzers.section_analyzer import PESectionAnalysisResult, SectionInfo
from app.analyzers.entropy_analyzer import EntropyAnalysisResult, SectionEntropyResult
from app.analyzers.string_analyzer import StringAnalysisResult
from app.analyzers.import_analyzer import ImportAnalysisResult, ImportInfo


def main():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 08: SUSPICIOUS INDICATOR ENGINE DEMO")
    print("=" * 72)

    engine = SuspiciousIndicatorEngine()

    # Synthetic multi-analyzer findings representing a complex sample
    mock_sections = PESectionAnalysisResult(
        total_sections=2,
        has_wx_sections=True,
        sections=[
            SectionInfo(
                name=".text", virtual_address="0x1000", virtual_size=4096,
                raw_size=4096, raw_offset=512, characteristics=0x60000020,
                readable=True, writable=False, executable=True
            ),
            SectionInfo(
                name=".packed", virtual_address="0x2000", virtual_size=16384,
                raw_size=0, raw_offset=0, characteristics=0xE0000020,
                readable=True, writable=True, executable=True, is_standard_name=False
            )
        ]
    )

    mock_entropy = EntropyAnalysisResult(
        file_entropy=7.4,
        sections=[
            SectionEntropyResult(name=".text", entropy=6.1, classification="NORMAL"),
            SectionEntropyResult(name=".packed", entropy=7.8, classification="VERY_HIGH")
        ]
    )

    mock_strings = StringAnalysisResult(
        urls=["https://threat-actor-c2.net/stage2.dll"],
        ip_addresses=["103.45.67.89"],
        registry_paths=["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        commands=["cmd.exe /c whoami >> C:\\Windows\\Temp\\debug.log"],
        powershell_references=["powershell -ExecutionPolicy Bypass -enc SQBFAFgA"]
    )

    mock_imports = ImportAnalysisResult(
        imports=[
            ImportInfo(dll="KERNEL32.dll", api="VirtualAlloc", category="MEMORY", risk_relevance="MEDIUM", explanation=""),
            ImportInfo(dll="KERNEL32.dll", api="VirtualProtect", category="MEMORY", risk_relevance="MEDIUM", explanation=""),
            ImportInfo(dll="KERNEL32.dll", api="OpenProcess", category="PROCESS", risk_relevance="MEDIUM", explanation=""),
            ImportInfo(dll="KERNEL32.dll", api="CreateRemoteThread", category="THREAD", risk_relevance="HIGH", explanation=""),
            ImportInfo(dll="ADVAPI32.dll", api="RegSetValueExA", category="REGISTRY", risk_relevance="MEDIUM", explanation=""),
            ImportInfo(dll="URLMON.dll", api="URLDownloadToFileA", category="NETWORK", risk_relevance="HIGH", explanation=""),
            ImportInfo(dll="KERNEL32.dll", api="WinExec", category="PROCESS", risk_relevance="MEDIUM", explanation=""),
            ImportInfo(dll="KERNEL32.dll", api="IsDebuggerPresent", category="SYSTEM_INFORMATION", risk_relevance="MEDIUM", explanation=""),
        ]
    )

    print("\n[+] Evaluating Correlated Static Indicators across all Analyzers...")
    result = engine.evaluate(
        sections=mock_sections,
        entropy=mock_entropy,
        strings=mock_strings,
        imports=mock_imports
    )

    print(f"\nTotal Indicators Identified : {result.total_indicators}")
    print(f"High Severity Indicators   : {result.high_severity_count}")
    print(f"Categories Present         : {result.categories_present}")

    print("\nExplainable Indicators Contract (JSON):")
    for ind in result.indicators:
        print(json.dumps(ind.to_dict(), indent=2))

    print("\n" + "=" * 72)
    print("  DEMONSTRATION COMPLETE - ZERO RUNTIME EXECUTION ASSUMPTIONS")
    print("=" * 72)


if __name__ == "__main__":
    main()
