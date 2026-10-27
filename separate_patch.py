#!/usr/bin/env python3
"""
Separate SEC-07 (XSS remediation) from SEC-06 (cookie auth) changes in app.js diff.
"""

import re
import sys

def read_diff(path):
    # Try different encodings
    for encoding in ['utf-8', 'utf-8-sig', 'utf-16', 'latin-1']:
        try:
            with open(path, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    # Fallback: read as binary and decode with replace
    with open(path, 'rb') as f:
        return f.read().decode('utf-8', errors='replace')

def write_diff(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

def is_sec06_hunk(hunk):
    """Check if a hunk is SEC-06 (cookie auth) related."""
    sec06_keywords = [
        'useCookieAuth',
        'csrfToken',
        'fetchCsrfToken',
        'getAuthHeaders',
        'fetchWithAuth',
        'handleLoginForm',
        'handleRegisterForm',
        'logoutUser',
        'initAuth',
        'renderUserAuthWidget',
        'renderLayoutForAuth',
        'credentials: \'include\'',
        'state.useCookieAuth',
        'state.token && !state.useCookieAuth',
        'state.useCookieAuth && csrfToken',
        'X-CSRF-Token',
        'state.authStatus',
        'localStorage.removeItem',
        'renderUserAuthWidget',
        'renderLayoutForAuth',
    ]
    for kw in sec06_keywords:
        if kw in hunk:
            return True
    return False

def is_sec07_hunk(hunk):
    """Check if a hunk is SEC-07 (XSS remediation) related."""
    sec07_keywords = [
        'data-type="api"',
        'data-type="string"',
        'data-action="copy-ioc"',
        'data-action="delete-note"',
        'data-action="copy-sha256"',
        'data-action="open-analysis"',
        'data-action="view-report"',
        'data-global-idx',
        'data-action="copy-string"',
        'data-action="inspect-string"',
        'data-action="goto-page"',
        'handleImportsTableClick',
        'handleTopStringsTableClick',
        'handleIocsTableClick',
        'handleAnalystNotesClick',
        'handleHistoryTableClick',
        'handleStringsTableClick',
        'handleStringsPaginationClick',
        'handleAdminUsersTableClick',
        'handleAuditLogsTableClick',
        'setupSampleDataTableDelegation',
        'data-action="role-modal"',
        'data-action="reset-pass"',
        'data-action="unlock-user"',
        'data-action="toggle-status"',
        'data-action="delete-user"',
        'data-action="audit-detail"',
        'data-action="copy-sha256"',
        'data-action="open-analysis"',
        'data-action="view-report"',
        'data-action="copy-string"',
        'data-action="inspect-string"',
    ]
    for kw in sec07_keywords:
        if kw in hunk:
            return True
    return False

def separate_diff(input_path, sec06_path, sec07_path):
    diff = read_diff(input_path)
    
    # Split diff into hunks
    lines = diff.split('\n')
    
    sec06_lines = []
    sec07_lines = []
    other_lines = []
    
    current_hunk = []
    in_hunk = False
    
    for line in lines:
        if line.startswith('@@'):
            # Process previous hunk
            if current_hunk:
                hunk_text = '\n'.join(current_hunk)
                if is_sec06_hunk(hunk_text):
                    sec06_lines.extend(current_hunk)
                elif is_sec07_hunk(hunk_text):
                    sec07_lines.extend(current_hunk)
                else:
                    other_lines.extend(current_hunk)
            current_hunk = [line]
            in_hunk = True
        else:
            current_hunk.append(line)
    
    # Process last hunk
    if current_hunk:
        hunk_text = '\n'.join(current_hunk)
        if is_sec06_hunk(hunk_text):
            sec06_lines.extend(current_hunk)
        elif is_sec07_hunk(hunk_text):
            sec07_lines.extend(current_hunk)
        else:
            other_lines.extend(current_hunk)
    
    # Ensure we have proper diff headers
    sec06_content = '\n'.join(sec06_lines)
    sec07_content = '\n'.join(sec07_lines)
    
    write_diff(sec06_path, sec06_content)
    write_diff(sec07_path, sec07_content)
    
    print(f"SEC-06 diff written to {sec06_path}")
    print(f"SEC-07 diff written to {sec07_path}")
    print(f"Other lines: {len(other_lines)}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 4:
        input_path = sys.argv[1]
        sec06_path = sys.argv[2]
        sec07_path = sys.argv[3]
    else:
        input_path = r'C:\app_full.diff'
        sec06_path = r'C:\sec06.diff'
        sec07_path = r'C:\sec07.diff'
    
    separate_diff(input_path, sec06_path, sec07_path)