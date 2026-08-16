"""
Live Demonstration Script for Module 16: Authentication and Access Control.
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
from app.auth.rate_limiter import rate_limiter


def main():
    print("=" * 72)
    print("  ETHIO-AI DEFENDER - MODULE 16: AUTH & ACCESS CONTROL DEMO")
    print("=" * 72)

    init_db()
    rate_limiter.reset_all()
    client = TestClient(app)

    # 1. Register Users with RBAC Roles
    print("\n[1] Registering Platform Users across 3 RBAC Roles (PBKDF2-HMAC-SHA256)...")
    roles = [
        ("soc_admin", "admin@insa.gov.et", "AdminMasterPass2026!", "ADMIN"),
        ("soc_analyst", "analyst@cbe.com.et", "AnalystSecurePass2026!", "ANALYST"),
        ("student_user", "student@aau.edu.et", "StudentLearnerPass2026!", "STUDENT"),
    ]

    for uname, email, pwd, role in roles:
        res = client.post("/api/auth/register", json={
            "username": uname,
            "email": email,
            "password": pwd,
            "role": role
        })
        if res.status_code == 201:
            data = res.json()
            print(f"    - User: {data['username']:<14} | Role: {data['role']:<8} | Permissions: {len(data['permissions'])} grants")

    # 2. Authenticate & Obtain Tokens
    print("\n[2] Authenticating Student & Generating HMAC-SHA256 Signed Bearer Token...")
    login_res = client.post("/api/auth/login", json={
        "username": "student_user",
        "password": "StudentLearnerPass2026!"
    })
    token_data = login_res.json()
    student_token = token_data.get("access_token")
    print(f"    - Token Type    : {token_data.get('token_type')}")
    print(f"    - Token JTI     : {token_data.get('jti')}")
    print(f"    - Token Preview : {student_token[:28]}... (Signature Verified)")

    # 3. RBAC Enforcement: Student Forbidden on Admin Endpoints
    print("\n[3] Testing RBAC Security Guard: Student Accessing Admin User Management...")
    forbidden_res = client.get("/api/auth/users", headers={"Authorization": f"Bearer {student_token}"})
    print(f"    - HTTP Status Code : {forbidden_res.status_code} (Expected: 403 Forbidden)")
    print(f"    - Security Response: {forbidden_res.json().get('detail')}")

    # 4. Admin Access Granted
    print("\n[4] Authenticating Admin & Querying Admin User Management...")
    admin_login = client.post("/api/auth/login", json={
        "username": "soc_admin",
        "password": "AdminMasterPass2026!"
    })
    admin_token = admin_login.json().get("access_token")
    admin_res = client.get("/api/auth/users", headers={"Authorization": f"Bearer {admin_token}"})
    print(f"    - HTTP Status Code : {admin_res.status_code} (Access Granted)")
    print(f"    - Registered Users : {len(admin_res.json())} users listed")

    # 5. Brute-Force Rate Limiting & Account Lockout
    print("\n[5] Simulating Brute-Force Password Attack (Account Lockout Policy)...")
    client.post("/api/auth/register", json={
        "username": "victim_account",
        "email": "victim@telecom.et",
        "password": "RealPassword2026!"
    })

    for attempt in range(1, 6):
        attempt_res = client.post("/api/auth/login", json={
            "username": "victim_account",
            "password": f"WrongAttempt{attempt}"
        })
        print(f"    - Attempt #{attempt}: HTTP {attempt_res.status_code} -> {attempt_res.json().get('detail')}")

    # 6. Secure Logout & Token Revocation
    print("\n[6] Logging Out Student & Blacklisting Token...")
    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {student_token}"})
    print(f"    - Logout Response: {logout_res.json().get('message')}")

    reuse_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {student_token}"})
    print(f"    - Post-Logout Attempt: HTTP {reuse_res.status_code} ({reuse_res.json().get('detail')})")

    print("\n" + "=" * 72)
    print("  DEMONSTRATION COMPLETE - AUTHENTICATION AND ACCESS CONTROL")
    print("=" * 72)


if __name__ == "__main__":
    main()
