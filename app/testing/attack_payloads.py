"""
Security Attack Test Vectors and Payloads for Module 18 Security Testing Framework.
"""

from typing import Dict, List


# 1. Path Traversal & Directory Traversal Vectors
PATH_TRAVERSAL_FILENAMES: List[str] = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\system32\\cmd.exe",
    "....//....//....//etc/shadow",
    "%2e%2e%2f%2e%2e%2fsample.exe",
    "..%252f..%252fsample.exe",
    "/root/.ssh/id_rsa.exe",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\app\\core\\config.py",
]

# 2. Dangerous Filenames (Null Bytes, Control Characters, Reserved Device Names)
DANGEROUS_FILENAMES: List[str] = [
    "sample\x00malicious.exe",
    "CON.exe",
    "PRN.dll",
    "AUX.sys",
    "NUL.exe",
    "COM1.exe",
    "LPT1.exe",
    "sample;rm -rf /.exe",
    "sample$(whoami).exe",
    "sample`calc.exe`.exe",
    "sample|cat /etc/passwd.exe",
    "  spaced_sample.exe  ",
    ".hidden_sample.exe",
    "very_long_filename_" + ("A" * 300) + ".exe",
]

# 3. SQL Injection Attack Payloads
SQL_INJECTION_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "admin' --",
    "admin' #",
    "' UNION SELECT 1, 'admin', 'admin@soc.et', 'ADMIN', 1 --",
    "'; DROP TABLE users; --",
    "'; DROP TABLE samples; --",
    "1' OR 1=1 ORDER BY 1--",
    "admin' AND 1=0 UNION ALL SELECT 1,2,3,4,5--",
]

# 4. Cross-Site Scripting (XSS) Payloads
XSS_PAYLOADS: List[str] = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert(document.cookie)",
    "'\"><script>alert(1)</script>",
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    "<body onload=alert('XSS')>",
]

# 5. Malformed API Requests & Invalid Headers
INVALID_AUTH_HEADERS: List[Dict[str, str]] = [
    {"Authorization": "Bearer "},
    {"Authorization": "Bearer invalid_token_format_123"},
    {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."},  # 'none' algorithm
    {"Authorization": "Basic YWRtaW46cGFzc3dvcmQ="},  # Unsupported Basic scheme
    {"Authorization": "Token 1234567890"},
    {"Authorization": "Bearer " + ("A" * 4096)},  # Oversized token header
]

# 6. Malformed JSON Payloads
MALFORMED_JSON_PAYLOADS: List[str] = [
    "{",
    "{'username': 'admin',}",  # Trailing comma
    '{"username": "admin", "password": }',  # Missing value
    '{"username": "\x00admin"}',  # Null byte in JSON string
    "",  # Empty body
    "NOT_JSON_AT_ALL",
]
