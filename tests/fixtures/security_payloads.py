"""
Curated Security Attack Payloads and Threat Vectors for ETHIO-AI Defender.
Covers Path Traversal, Dangerous Filenames, SQLi, XSS, Header Injections, and Malformed Data.
"""

from typing import List, Dict

# Path Traversal Payloads (Unix and Windows variants)
PATH_TRAVERSAL_FILENAMES: List[str] = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\system32\\cmd.exe",
    "....//....//....//etc/shadow",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%5c..%5c..%5cwindows%5csystem32%5cconfig%5cSAM",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "C:\\secret\\trojan.exe",
    "\\\\attacker.soc.et\\share\\payload.exe",
    "/root/.ssh/id_rsa.exe",
    "/tmp/../../../etc/hosts",
    "C:/Windows/System32/drivers/etc/hosts.dll",
]

# Dangerous & Malformed Filenames
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
    "very_long_filename_" + ("A" * 240) + ".exe",
]

# SQL Injection Attack Payloads
SQL_INJECTION_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "admin' --",
    "admin' /*",
    "' UNION SELECT 1, 'admin', 'password', 1 --",
    "'; DROP TABLE samples; --",
    "1' OR '1' = '1' /*",
    "' OR 1=1#",
    "1' ORDER BY 1--+",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT username FROM users LIMIT 0,1), FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a)--",
]

# Cross-Site Scripting (XSS) Payloads
XSS_PAYLOADS: List[str] = [
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "\"><script>alert('XSS')</script>",
    "<iframe src=\"javascript:alert('XSS')\"></iframe>",
    "<body onload=alert('XSS')>",
    "<a href=\"javascript:alert('XSS')\">Click Me</a>",
    "{{ 7*7 }}",
]

# Invalid / Forged / Corrupt Authentication Headers
INVALID_AUTH_HEADERS: List[Dict[str, str]] = [
    {},  # Missing Authorization header
    {"Authorization": ""},  # Empty header
    {"Authorization": "InvalidScheme token12345"},  # Non-Bearer scheme
    {"Authorization": "Bearer"},  # Missing token payload
    {"Authorization": "Bearer "},  # Trailing whitespace only
    {"Authorization": "Bearer abc.def.ghi.jkl"},  # Malformed JWT structure
    {"Authorization": "Bearer " + ("A" * 4096)},  # Oversized token buffer
    {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."},  # Alg: none forgery
    {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk5OSIsImV4cCI6MTYwMDAwMDAwMH0.invalid_signature"},  # Expired & forged
]

# Malformed & Boundary-Testing JSON Payloads
MALFORMED_JSON_PAYLOADS: List[str] = [
    "{",  # Truncated JSON
    "{'username': 'admin'}",  # Invalid single quotes
    '{"username": "admin",}',  # Trailing comma
    '{"username": ' + ("A" * 100000) + '}',  # Oversized string token
    '{"username": null, "password": null}',  # Null required fields
    '{"username": 12345, "password": true}',  # Invalid data types
    '{"username": {"nested": "object"}, "password": []}',  # Type mismatch
    "",  # Empty payload
    "NOT_A_JSON_STRING",  # Plain text
]
