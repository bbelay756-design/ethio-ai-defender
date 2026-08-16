"""
Live Demonstration Script for Module 15: Defensive Security Dashboard.
"""

import sys
import json
import warnings
from fastapi.testclient import TestClient

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

warnings.filterwarnings("ignore", category=DeprecationWarning)

from app.main import app
from app.db.session import init_db


def main():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 15: DEFENSIVE SECURITY DASHBOARD DEMO")
    print("=" * 72)

    init_db()
    client = TestClient(app)

    # 1. Verify HTML Dashboard Delivery
    print("\n[1] Testing Dashboard Web Route (GET /)...")
    res_html = client.get("/", headers={"accept": "text/html"})
    print(f"    - HTTP Status Code : {res_html.status_code}")
    print(f"    - Content-Type     : {res_html.headers.get('content-type')}")
    print(f"    - Brand Title Found: {'ETHIO-AI Defender' in res_html.text}")

    # 2. Synthetic PE Binary Upload to /api/dashboard/analyze
    print("\n[2] Executing Full Analysis Pipeline via POST /api/dashboard/analyze...")
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    dos_header[0x3C:0x40] = (64).to_bytes(4, byteorder='little')
    pe_sig = b'PE\x00\x00'
    coff_header = b'\x64\x86\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01'
    synthetic_pe = bytes(dos_header) + pe_sig + coff_header + (b'\x00' * 512)

    files = {"file": ("demo_banking_sample.exe", synthetic_pe, "application/octet-stream")}
    res_api = client.post("/api/dashboard/analyze?language=en", files=files)
    
    print(f"    - HTTP Status Code : {res_api.status_code}")
    if res_api.status_code == 200:
        data = res_api.json()
        print(f"    - Analysis ID      : {data.get('analysis_id')}")
        print(f"    - Filename         : {data.get('filename')}")
        print(f"    - Threat Score     : {data.get('threat_score', {}).get('score')} [{data.get('threat_score', {}).get('risk_level')}]")
        print(f"    - Ethiopian Context: {data.get('ethiopian_context', {}).get('environment')} ({data.get('ethiopian_context', {}).get('relevance')})")
        print(f"    - AI Confidence    : {data.get('ai_assessment', {}).get('confidence')}")

    # 3. Test Amharic Localized Output
    print("\n[3] Testing Amharic Localized Analysis (language=am)...")
    res_am = client.post("/api/dashboard/analyze?language=am", files={"file": ("ethio_payload.dll", synthetic_pe, "application/octet-stream")})
    if res_am.status_code == 200:
        data_am = res_am.json()
        print(f"    - Language Code    : {data_am.get('language')}")
        print(f"    - Context Reason   : {data_am.get('ethiopian_context', {}).get('reason')}")

    # 4. List Samples API
    print("\n[4] Querying Analyzed Samples Catalog (GET /api/dashboard/samples)...")
    res_samples = client.get("/api/dashboard/samples")
    print(f"    - Samples Count    : {len(res_samples.json())}")

    print("\n" + "=" * 72)
    print("  DEMONSTRATION COMPLETE - DEFENSIVE SECURITY DASHBOARD")
    print("=" * 72)


if __name__ == "__main__":
    main()
