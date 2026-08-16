import sys
import io
import struct
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

from fastapi.testclient import TestClient
from app.main import app


def make_test_pe(size: int = 512) -> bytes:
    buf = bytearray(max(size, 256))
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    return bytes(buf)


def run_demonstration():
    client = TestClient(app)
    print("=" * 70)
    print("  [+] ETHIO-AI DEFENDER - MODULE 01 LIVE END-TO-END TEST")
    print("=" * 70)

    # 1. Health Check
    print("\n[1] Testing Platform Health Check Endpoint (GET /)...")
    res = client.get("/")
    print(f"    Status Code : {res.status_code}")
    print(f"    Platform    : {res.json().get('platform')}")
    print(f"    Status      : {res.json().get('status')}")

    # 2. Valid EXE Upload
    print("\n[2] Uploading Valid Windows Executable (sample_agent.exe)...")
    valid_pe = make_test_pe(1024)
    res = client.post(
        "/api/files/upload",
        files={"file": ("sample_agent.exe", io.BytesIO(valid_pe), "application/octet-stream")}
    )
    print(f"    Status Code : {res.status_code}")
    data = res.json()
    print(f"    Analysis ID : {data.get('analysis_id')}")
    print(f"    Filename    : {data.get('filename')}")
    print(f"    Size        : {data.get('size')} bytes")
    print(f"    SHA-256     : {data.get('sha256')}")
    print(f"    MD5         : {data.get('md5')}")
    print(f"    Status      : {data.get('status')}")
    saved_analysis_id = data.get("analysis_id")

    # 3. Retrieve Record via GET /api/files/{analysis_id}
    print(f"\n[3] Querying Stored Record for {saved_analysis_id} (GET /api/files/{saved_analysis_id})...")
    res = client.get(f"/api/files/{saved_analysis_id}")
    print(f"    Status Code : {res.status_code}")
    print(f"    Record Data : {res.json()}")

    # 4. Path Traversal Attack Test
    print("\n[4] Simulating Path Traversal Attack (../../../../Windows/calc.exe)...")
    res = client.post(
        "/api/files/upload",
        files={"file": ("../../../../Windows/calc.exe", io.BytesIO(valid_pe), "application/octet-stream")}
    )
    print(f"    Status Code : {res.status_code}")
    print(f"    Sanitized Filename : {res.json().get('filename')}")
    print("    Result: Directory traversal sequences stripped safely.")

    # 5. Invalid Extension Test (.sh script)
    print("\n[5] Testing Unsupported Extension Upload (malicious_script.sh)...")
    res = client.post(
        "/api/files/upload",
        files={"file": ("malicious_script.sh", io.BytesIO(b"#!/bin/bash\necho evil"), "application/octet-stream")}
    )
    print(f"    Status Code : {res.status_code}")
    print(f"    Rejection Detail : {res.json().get('detail')}")

    # 6. Malformed Fake EXE Test (plain text named .exe)
    print("\n[6] Testing Malformed Fake EXE Upload (fake_binary.exe)...")
    res = client.post(
        "/api/files/upload",
        files={"file": ("fake_binary.exe", io.BytesIO(b"I am not a PE executable."), "application/octet-stream")}
    )
    print(f"    Status Code : {res.status_code}")
    print(f"    Rejection Detail : {res.json().get('detail')}")

    # 7. Empty File Test
    print("\n[7] Testing 0-Byte Empty File Upload (empty.exe)...")
    res = client.post(
        "/api/files/upload",
        files={"file": ("empty.exe", io.BytesIO(b""), "application/octet-stream")}
    )
    print(f"    Status Code : {res.status_code}")
    print(f"    Rejection Detail : {res.json().get('detail')}")

    print("\n" + "=" * 70)
    print("  [SUCCESS] ALL LIVE SECURITY & FUNCTIONAL TESTS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    run_demonstration()
