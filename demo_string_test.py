"""
Live Demonstration Script for Module 06: String Analyzer.
"""

import json
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.string_analyzer import StringAnalyzer


def main():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 06: STRING ANALYZER LIVE DEMO")
    print("=" * 72)

    analyzer = StringAnalyzer()

    # Synthetic binary payload with diverse forensic string categories
    payload = (
        b"Welcome to ETHIO-AI Defender static analysis engine.\x00"
        b"https://cybersecurity.gov.et/alerts/threat-feed.json\x00"
        b"http://192.168.1.105:4444/download/beacon.bin\x00"
        b"c2-telecom.ethio.et\x00"
        b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        b"C:\\Windows\\System32\\drivers\\etc\\hosts\x00"
        b"powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgA\x00"
        b"cmd.exe /c whoami >> C:\\Windows\\Temp\\triage.log\x00"
        b"net user localadmin /add\x00"
        b"kernel32.dll\x00user32.dll\x00ws2_32.dll\x00"
        b"soc-analyst@telecom.et\x00"
        b"VirtualAlloc\x00CreateRemoteThread\x00WriteProcessMemory\x00"
    )

    result = analyzer.analyze_bytes(payload)

    print(f"\n[+] Total Strings Extracted: {result.total_strings}")
    print("\nCategorized Forensic Output Contract (JSON):")
    print(json.dumps(result.to_dict(), indent=2))

    print("\nExtended Artifacts Breakdown:")
    print(f"  - DLL Dependencies    : {result.dlls}")
    print(f"  - Email Contacts      : {result.emails}")
    print(f"  - File Paths          : {result.file_paths}")
    print(f"  - Windows System APIs : {result.apis}")

    print("\n" + "=" * 72)
    print("  DEMONSTRATION COMPLETE - ZERO COMMANDS EXECUTED (STATIC ONLY)")
    print("=" * 72)


if __name__ == "__main__":
    main()
