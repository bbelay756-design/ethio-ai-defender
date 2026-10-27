#!/usr/bin/env python3
"""
Apply SEC-07 XSS remediation changes to app.js
"""

import re

def apply_sec07_changes(content):
    """Apply SEC-07 XSS remediation changes to the file content."""
    
    # 1. renderSampleData: imports table - replace onclick with data attributes
    old_imports = r'<tr style="cursor: pointer;" onclick="openStringOrApiDrawer\(\'${escapeJsString\(i\.api\}\)\', \'API\', \'${escapeJsString\(i\.risk_relevance \|\| \'LOW\'\)}\', \'${escapeJsString\(i\.category \|\| \'GENERAL\'\)}\', \'Imported API function from ${escapeJsString\(i\.dll\}\)\}')">'
    new_imports = r'<tr style="cursor: pointer;" data-type="api" data-api="${escapeHtml(i.api)}" data-dll="${escapeHtml(i.dll)}" data-category="${escapeHtml(i.category || \'GENERAL\')}" data-risk="${escapeHtml(i.risk_relevance || \'LOW\')}" data-description="Imported API function from ${escapeHtml(i.dll)}">'
    content = re.sub(old_imports, new_imports, content)
    
    # 2. renderSampleData: top strings table - replace onclick with data attributes
    old_strings = r'<tr style="cursor: pointer;" onclick="openStringOrApiDrawer\(\'${escapeJsString\(s\.value \|\| s\)}\', \'${escapeJsString\(s\.category \|\| s\.type \|\| \'STRING\'\)}\', \'${escapeJsString\(s\.severity \|\| \'LOW\'\)}\', \'${escapeJsString\(s\.encoding \|\| \'ASCII\'\)}\', \'${escapeJsString\(s\.reason \|\| \'Extracted ASCII / Unicode string artifact\'\)}\')">'
    new_strings = r'<tr style="cursor: pointer;" data-type="string" data-value="${escapeHtml(s.value || s)}" data-category="${escapeHtml(s.category || s.type || \'STRING\')}" data-severity="${escapeHtml(s.severity || \'LOW\')}" data-encoding="${escapeHtml(s.encoding || \'ASCII\')}" data-reason="${escapeHtml(s.reason || \'Extracted ASCII / Unicode string artifact\')}">'
    content = re.sub(old_strings, new_strings, content)
    
    # 3. renderSampleData: IOCs table - replace onclick with data-action
    old_iocs = r'<button class="btn-secondary" onclick="navigator\.clipboard\.writeText\(\'${escapeJsString\(ioc\.value}\)\'; showSocNotification\(\'Copied\', \'IOC copied to clipboard\', \'success\'\);" style="font-size: 9px; padding: 2px 6px;">'
    new_iocs = r'<button class="btn-secondary" data-action="copy-ioc" data-value="${escapeHtml(ioc.value)}" style="font-size: 9px; padding: 2px 6px;">'
    content = re.sub(old_iocs, new_iocs, content)
    
    # 4. renderSampleData: add setupSampleDataTableDelegation call
    content = content.replace(
        'renderAnalystNotesList(data.notes || []);\n}',
        'renderAnalystNotesList(data.notes || []);\n\n    // Set up event delegation for dynamic tables\n    setupSampleDataTableDelegation();\n}'
    )
    
    # 4b. Add setupSampleDataTableDelegation and handler functions before renderAnalystNotesList
    setup_delegation_code = '''

// Set up event delegation for dynamic tables
function setupSampleDataTableDelegation() {
    // Imports table delegation
    const impTbody = document.getElementById('imports-tbody');
    if (impTbody) {
        // Remove old listener if any
        impTbody.removeEventListener('click', handleImportsTableClick);
        impTbody.addEventListener('click', handleImportsTableClick);
    }

    // Top strings table delegation
    const topStrTbody = document.getElementById('ov-top-strings-tbody');
    if (topStrTbody) {
        topStrTbody.removeEventListener('click', handleTopStringsTableClick);
        topStrTbody.addEventListener('click', handleTopStringsTableClick);
    }

    // IOCs table delegation (copy buttons)
    const iocTbody = document.getElementById('ov-iocs-tbody');
    if (iocTbody) {
        iocTbody.removeEventListener('click', handleIocsTableClick);
        iocTbody.addEventListener('click', handleIocsTableClick);
    }
}

function handleImportsTableClick(event) {
    const row = event.target.closest('tr[data-type="api"]');
    if (!row) return;
    openStringOrApiDrawer(
        row.dataset.api,
        'API',
        row.dataset.risk,
        row.dataset.category,
        row.dataset.description
    );
}

function handleTopStringsTableClick(event) {
    const row = event.target.closest('tr[data-type="string"]');
    if (!row) return;
    openStringOrApiDrawer(
        row.dataset.value,
        row.dataset.category,
        row.dataset.severity,
        row.dataset.encoding,
        row.dataset.reason
    );
}

function handleIocsTableClick(event) {
    const btn = event.target.closest('button[data-action="copy-ioc"]');
    if (!btn) return;
    const value = btn.dataset.value;
    navigator.clipboard.writeText(value);
    showSocNotification('Copied', 'IOC copied to clipboard', 'success');
}
'''

    # Insert before renderAnalystNotesList
    content = content.replace(
        '/**\n * Jump to Specific Analysis Evidence Stage\n */',
        setup_delegation_code + '\n/**\n * Jump to Specific Analysis Evidence Stage\n */'
    )
    
    # 5. renderAnalystNotesList: replace onclick with data-action
    content = re.sub(
        r'<button class="btn-secondary" onclick="deleteAnalystNote\(\$\{n\.id\}\)" style="font-size: 8px; padding: 1px 4px; color: var\(--sev-crit\);">',
        r'<button class="btn-secondary" data-action="delete-note" data-note-id="${n.id}" style="font-size: 8px; padding: 1px 4px; color: var(--sev-crit);">',
        content
    )
    
    # 5b. Add handleAnalystNotesClick after deleteAnalystNotes
    content = content.replace(
        'async function deleteAnalystNote(noteId) {',
        'function handleAnalystNotesClick(event) {\n    const btn = event.target.closest(\'[data-action="delete-note"]\');\n    if (!btn) return;\n    const noteId = parseInt(btn.dataset.noteId, 10);\n    if (!isNaN(noteId)) {\n        deleteAnalystNote(noteId);\n    }\n}\n\nasync function deleteAnalystNote(noteId) {'
    )
    
    # 5c. Add event listener in renderAnalystNotesList
    content = content.replace(
        '`).join(\'\');\n}',
        '`).join(\'\');\n\n    // Event delegation for note deletion\n    container.removeEventListener(\'click\', handleAnalystNotesClick);\n    container.addEventListener(\'click\', handleAnalystNotesClick);\n}'
    )
    
    # 6. filterHistoryTable: replace onclick with data-action
    content = re.sub(
        r'<tr>',
        r'<tr data-analysis-id="${escapeHtml(item.analysis_id)}" data-sha256="${escapeHtml(item.sha256)}" data-url="/api/analyses/${encodeURIComponent(item.analysis_id)}/report?format=html&language=${state.currentLanguage}">',
        content
    )
    
    content = re.sub(
        r'<button class="btn-icon-copy" onclick="copyTextToClipboard\(\'${escapeJsString\(item\.sha256\)}\'\)" title="Copy full SHA-256">',
        r'<button class="btn-icon-copy" data-action="copy-sha256" data-value="${escapeHtml(item.sha256)}" title="Copy full SHA-256">',
        content
    )
    
    content = re.sub(
        r'<button class="btn-primary" style="padding: 4px 8px; font-size: 11px;" onclick="openAnalysisInWorkspace\(\'${escapeJsString\(item\.analysis_id\)}\'\)" title="Load into Workspace">',
        r'<button class="btn-primary" style="padding: 4px 8px; font-size: 11px;" data-action="open-analysis" title="Load into Workspace">',
        content
    )
    
    content = re.sub(
        r'<button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="window\.open\(\'/api/analyses/${encodeURIComponent\(item\.analysis_id\)\}/report\?format=html&language=${state\.currentLanguage}\', \'_blank\'\)" title="View Report">',
        r'<button class="btn-secondary" style="padding: 4px 8px; font-size: 11px;" data-action="view-report" title="View Report">',
        content
    )
    
    # 6b. Add handleHistoryTableClick and event listener
    history_handler = '''
function handleHistoryTableClick(event) {
    const row = event.target.closest('tr[data-analysis-id]');
    if (!row) return;

    const analysisId = row.dataset.analysisId;

    if (event.target.matches('[data-action="copy-sha256"]')) {
        const value = event.target.dataset.value;
        copyTextToClipboard(value);
        showSocNotification('Copied', 'SHA-256 copied to clipboard', 'success');
    } else if (event.target.matches('[data-action="open-analysis"]')) {
        openAnalysisInWorkspace(analysisId);
    } else if (event.target.matches('[data-action="view-report"]')) {
        const url = row.dataset.url;
        window.open(url, '_blank');
    }
}
'''
    content = content.replace(
        'function copyTextToClipboard(text) {',
        history_handler + '\nfunction copyTextToClipboard(text) {'
    )
    
    content = content.replace(
        '}).join(\'\');\n}',
        '}).join(\'\');\n\n    // Set up event delegation for history table\n    const historyTbody = document.getElementById(\'history-tbody\');\n    if (historyTbody) {\n        historyTbody.removeEventListener(\'click\', handleHistoryTableClick);\n        historyTbody.addEventListener(\'click\', handleHistoryTableClick);\n    }'
    )
    
    # 7. renderStringsTableSlice: replace onclick with data attributes
    content = re.sub(
        r'<tr>',
        r'<tr data-global-idx="${globalIdx}" data-value="${escapeHtml(item.value)}" data-offset="${escapeHtml(offsetStr)}" data-category="${escapeHtml(item.category || \'GENERAL\')}" data-encoding="${escapeHtml(item.encoding || \'ASCII\')}" data-severity="${escapeHtml(item.severity || \'LOW\')}" data-reason="${escapeHtml(item.reason || \'Standard string\')}" data-mitre="${escapeHtml(item.mitre_technique || \'\')}">',
        content
    )
    
    content = re.sub(
        r'<code style="font-family: var\(--font-mono\); font-size: 12px; color: \$\{isSusp \? \'var\(--accent-orange\'\) : \'var\(--text-primary\'\)\}; word-break: break-all; cursor: pointer;" onclick="openStringDetailModal\(\$\{globalIdx\}\)" title="${escapeHtml\(item\.value\)}">',
        r'<code style="font-family: var(--font-mono); font-size: 12px; color: ${isSusp ? \'var(--accent-orange)\' : \'var(--text-primary)\'}; word-break: break-all; cursor: pointer;" title="${escapeHtml(item.value)}">',
        content
    )
    
    content = re.sub(
        r'<button class="btn-secondary" onclick="copySingleString\(\$\{globalIdx\}, this\)" style="font-size: 10px; padding: 2px 6px;" title="Copy string text">',
        r'<button class="btn-secondary" data-action="copy-string" data-global-idx="${globalIdx}" style="font-size: 10px; padding: 2px 6px;" title="Copy string text">',
        content
    )
    
    content = re.sub(
        r'<button class="btn-primary" onclick="openStringDetailModal\(\$\{globalIdx\}\)" style="font-size: 10px; padding: 2px 7px;" title="Inspect forensic details">',
        r'<button class="btn-primary" data-action="inspect-string" data-global-idx="${globalIdx}" style="font-size: 10px; padding: 2px 7px;" title="Inspect forensic details">',
        content
    )
    
    # 7b. Add handleStringsTableClick and event listener
    strings_handler = '''
function handleStringsTableClick(event) {
    const row = event.target.closest('tr[data-global-idx]');
    if (!row) return;

    const globalIdx = parseInt(row.dataset.globalIdx, 10);

    if (event.target.matches('[data-action="copy-string"]')) {
        copySingleString(globalIdx, event.target);
    } else if (event.target.matches('[data-action="inspect-string"]')) {
        openStringDetailModal(globalIdx);
    }
}
'''
    content = content.replace(
        'function goToStringsPage(pageNum) {',
        strings_handler + '\nfunction goToStringsPage(pageNum) {'
    )
    
    content = re.sub(
        r'<button class="btn-secondary \$\{p === currentPage \? \'active\' : \'\'\}" onclick="goToStringsPage\(\$\{p\}\)"',
        r'<button class="btn-secondary ${p === currentPage ? \'active\' : \'\'}" data-action="goto-page" data-page="${p}"',
        content
    )
    
    content = content.replace(
        '}).join(\'\');',
        '}).join(\'\');\n\n    // Event delegation for pagination\n    numbersContainer.removeEventListener(\'click\', handleStringsPaginationClick);\n    numbersContainer.addEventListener(\'click\', handleStringsPaginationClick);'
    )
    
    # 7c. Add handleStringsPaginationClick
    pagination_handler = '''
function handleStringsPaginationClick(event) {
    const btn = event.target.closest('[data-action="goto-page"]');
    if (!btn) return;
    const page = parseInt(btn.dataset.page, 10);
    if (!isNaN(page)) {
        goToStringsPage(page);
    }
}
'''
    content = content.replace(
        'function goToStringsPage(pageNum) {',
        pagination_handler + '\nfunction goToStringsPage(pageNum) {'
    )
    
    # 8. filterUsersTable: replace onclick with data-action
    content = re.sub(
        r'<button class="btn-secondary" onclick="openAdminRoleModal\(\$\{u\.id\}, \'${escapeJsString\(u\.username\)}\', \'${escapeJsString\(u\.role\)}\'\)"',
        r'<button class="btn-secondary" data-action="role-modal" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}" data-role="${escapeHtml(u.role)}"',
        content
    )
    
    content = re.sub(
        r'<button class="btn-secondary" onclick="openAdminResetPassModal\(\$\{u\.id\}, \'${escapeJsString\(u\.username\)}\'\)"',
        r'<button class="btn-secondary" data-action="reset-pass" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}"',
        content
    )
    
    content = re.sub(
        r'<button class="btn-secondary" onclick="handleAdminUnlockUser\(\$\{u\.id\}, \'${escapeJsString\(u\.username\)}\'\)"',
        r'<button class="btn-secondary" data-action="unlock-user" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}"',
        content
    )
    
    content = re.sub(
        r'<button class="btn-secondary" onclick="toggleUserStatus\(\$\{u\.id\}\)"',
        r'<button class="btn-secondary" data-action="toggle-status" data-user-id="${u.id}"',
        content
    )
    
    content = re.sub(
        r'<button class="btn-secondary" onclick="deleteUserAccount\(\$\{u\.id\}, \'${escapeJsString\(u\.username\)}\'\)"',
        r'<button class="btn-secondary" data-action="delete-user" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}"',
        content
    )
    
    content = content.replace(
        '<tr>',
        '<tr data-user-id="${u.id}">'
    )
    
    # 8b. Add handleAdminUsersTableClick and event listener
    admin_handler = '''
function handleAdminUsersTableClick(event) {
    const btn = event.target.closest('[data-action]');
    if (!btn) return;

    const action = btn.dataset.action;
    const userId = parseInt(btn.dataset.userId, 10);
    const username = btn.dataset.username;
    const role = btn.dataset.role;

    if (isNaN(userId)) return;

    if (action === 'role-modal') {
        openAdminRoleModal(userId, username, role);
    } else if (action === 'reset-pass') {
        openAdminResetPassModal(userId, username);
    } else if (action === 'unlock-user') {
        handleAdminUnlockUser(userId, username);
    } else if (action === 'toggle-status') {
        toggleUserStatus(userId);
    } else if (action === 'delete-user') {
        deleteUserAccount(userId, username);
    }
}
'''
    content = content.replace(
        'function openAdminResetPassModal(userId, username) {',
        admin_handler + '\nfunction openAdminResetPassModal(userId, username) {'
    )
    
    content = content.replace(
        '}).join(\'\');\n}',
        '}).join(\'\');\n\n    // Event delegation for admin users table\n    const adminUsersTbody = document.getElementById(\'admin-users-tbody\');\n    if (adminUsersTbody) {\n        adminUsersTbody.removeEventListener(\'click\', handleAdminUsersTableClick);\n        adminUsersTbody.addEventListener(\'click\', handleAdminUsersTableClick);\n    }'
    )
    
    # 9. loadAuditLogs: replace onclick with data-action
    content = re.sub(
        r'<button class="btn-secondary" onclick="openAuditDetailModal\(\'${detailsEncoded}\'\)"',
        r'<button class="btn-secondary" data-action="audit-detail" data-details="${detailsEncoded}"',
        content
    )
    
    # 9b. Add handleAuditLogsTableClick and event listener
    audit_handler = '''
function handleAuditLogsTableClick(event) {
    const btn = event.target.closest('[data-action="audit-detail"]');
    if (!btn) return;
    const encodedDetails = btn.dataset.details;
    if (encodedDetails) {
        openAuditDetailModal(encodedDetails);
    }
}
'''
    content = content.replace(
        'function getAuditResultBadgeClass(result) {',
        audit_handler + '\nfunction getAuditResultBadgeClass(result) {'
    )
    
    content = content.replace(
        'if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="empty-state-cell">Error: ${escapeHtml(err.message)}</td></tr>`;\n    }\n}',
        'if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="empty-state-cell">Error: ${escapeHtml(err.message)}</td></tr>`;\n    }\n\n    // Event delegation for audit logs table\n    if (tbody) {\n        tbody.removeEventListener(\'click\', handleAuditLogsTableClick);\n        tbody.addEventListener(\'click\', handleAuditLogsTableClick);\n    }\n}'
    )
    
    return content

def main():
    input_path = r'C:\Users\MILKWAY\ethio-ai-defender\frontend\static\js\app.js'
    output_path = r'C:\Users\MILKWAY\ethio-ai-defender\frontend\static\js\app.js'
    
    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if already modified (has SEC-07 changes)
    if 'setupSampleDataTableDelegation' in content:
        print("File already has SEC-07 changes")
        return
    
    new_content = apply_sec07_changes(content)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print("SEC-07 changes applied successfully")

if __name__ == '__main__':
    main()