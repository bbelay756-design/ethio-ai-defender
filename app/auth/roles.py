"""
Role-Based Access Control (RBAC) Roles and Permissions Definition.
"""

from enum import Enum
from typing import Dict, Set


class UserRole(str, Enum):
    """Platform system access roles."""
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class Permission(str, Enum):
    """Granular platform operation permissions."""
    # Administrator Permissions
    MANAGE_USERS = "manage_users"
    MANAGE_SETTINGS = "manage_settings"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    MANAGE_ORGANIZATIONS = "manage_organizations"

    # Analyst Permissions
    UPLOAD_FILES = "upload_files"
    ANALYZE_FILES = "analyze_files"
    GENERATE_REPORTS = "generate_reports"
    VIEW_ANALYSES = "view_analyses"
    ADD_ANALYST_CONCLUSIONS = "add_analyst_conclusions"

    # Viewer Permissions
    VIEW_AUTHORIZED_REPORTS = "view_authorized_reports"
    VIEW_AUTHORIZED_ANALYSES = "view_authorized_analyses"
    VIEW_REPORTS = "view_authorized_reports"


# Exact Role-to-Permissions Matrix
ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.ADMIN: {
        Permission.MANAGE_USERS,
        Permission.MANAGE_SETTINGS,
        Permission.VIEW_AUDIT_LOGS,
        Permission.MANAGE_ORGANIZATIONS,
        Permission.VIEW_ANALYSES,
        Permission.UPLOAD_FILES,
        Permission.ANALYZE_FILES,
        Permission.GENERATE_REPORTS,
        Permission.ADD_ANALYST_CONCLUSIONS,
        Permission.VIEW_AUTHORIZED_REPORTS,
        Permission.VIEW_AUTHORIZED_ANALYSES,
    },
    UserRole.ANALYST: {
        Permission.UPLOAD_FILES,
        Permission.ANALYZE_FILES,
        Permission.GENERATE_REPORTS,
        Permission.VIEW_ANALYSES,
        Permission.ADD_ANALYST_CONCLUSIONS,
        Permission.VIEW_AUTHORIZED_REPORTS,
        Permission.VIEW_AUTHORIZED_ANALYSES,
    },
    UserRole.VIEWER: {
        Permission.VIEW_AUTHORIZED_REPORTS,
        Permission.VIEW_AUTHORIZED_ANALYSES,
    },
}


def has_permission(role: str, permission: Permission) -> bool:
    """
    Evaluates whether a given user role possesses the requested permission.
    """
    try:
        user_role = UserRole(role.upper())
    except ValueError:
        return False

    return permission in ROLE_PERMISSIONS.get(user_role, set())
