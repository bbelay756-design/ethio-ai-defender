"""
Unit test suite for ETHIO-AI Defender.

Security bootstrap (SEC-02): the platform refuses to start without a strong
SECRET_KEY. When the suite is imported as a package (for example via
`python -m unittest discover -s tests -t .`) this module executes before any
test imports the application, so we inject an ephemeral, high-entropy signing
key. This keeps the test suite deterministic without ever committing a real
secret to the repository.
"""

import os
import secrets

os.environ.setdefault("SECRET_KEY", secrets.token_hex(32))
