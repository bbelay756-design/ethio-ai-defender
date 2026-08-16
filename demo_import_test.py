"""
Live Demonstration Script for Module 07: Windows API Import Analyzer.
"""

import json
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.analyzers.import_analyzer import WindowsAPIImportAnalyzer, ImportInfo


def main():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 07: IMPORT/API ANALYZER LIVE DEMO")
    print("=" * 72)

    analyzer = WindowsAPIImportAnalyzer()

    # Demonstration of the 11 Required Categories
    sample_apis = [
        ("KERNEL32.dll", "CreateFileA"),
        ("KERNEL32.dll", "CreateProcessA"),
        ("KERNEL32.dll", "VirtualAlloc"),
        ("KERNEL32.dll", "VirtualProtect"),
        ("WININET.dll",  "InternetOpenA"),
        ("ADVAPI32.dll", "RegOpenKeyExA"),
        ("ADVAPI32.dll", "CreateServiceA"),
        ("ADVAPI32.dll", "CryptEncrypt"),
        ("KERNEL32.dll", "GetSystemInfo"),
        ("USER32.dll",   "MessageBoxA"),
        ("KERNEL32.dll", "CreateRemoteThread"),
        ("ADVAPI32.dll", "AdjustTokenPrivileges"),
    ]

    print("\n[+] API Categorization & Risk Relevance Analysis:")
    for dll, api in sample_apis:
        cat, risk, exp = analyzer.classify_api(api)
        info = ImportInfo(
            dll=dll,
            api=api,
            category=cat,
            risk_relevance=risk,
            explanation=exp
        )
        print(f"\nAPI: {api} ({dll})")
        print(json.dumps(info.to_dict(), indent=2))

    print("\n" + "=" * 72)
    print("  DEMONSTRATION COMPLETE - ZERO FILES EXECUTED (STATIC ONLY)")
    print("=" * 72)


if __name__ == "__main__":
    main()
