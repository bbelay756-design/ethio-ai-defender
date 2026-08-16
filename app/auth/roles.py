"""
Role-Based Access Control (RBAC) Roles and Permissions Definition.
"""

from enum import Enum
from typing import Dict, Set


class UserRole(str, Enum):
    """Platform system access roles."""
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    STUDENT = "STUDENT"


class Permission(str, Enum):
    """Granular platform operation permissions."""
    # Administrator Permissions
    MANAGE_USERS = "manage_users"
    MANAGE_SETTINGS = "manage_settings"
    VIEW_AUDIT_LOGS = "view_audit_logs"

    # Analyst Permissions
    UPLOAD_FILES = "upload_files"
    ANALYZE_FILES = "analyze_files"
    GENERATE_REPORTS = "generate_reports"
    VIEW_ANALYSES = "view_analyses"

    # Student Permissions
    ANALYZE_APPROVED_SAMPLES = "analyze_approved_samples"
    USE_LEARNING_MODE = "use_learning_mode"
    VIEW_OWN_REPORTS = "view_own_reports"


# Exact Role-to-Permissions Matrix
ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.ADMIN: {
        Permission.MANAGE_USERS,
        Permission.MANAGE_SETTINGS,
        Permission.VIEW_AUDIT_LOGS,
        Permission.VIEW_ANALYSES,
        Permission.UPLOAD_FILES,
        Permission.ANALYZE_FILES,
        Permission.GENERATE_REPORTS,
        Permission.USE_LEARNING_MODE,
    },
    UserRole.ANALYST: {
        Permission.UPLOAD_FILES,
        Permission.ANALYZE_FILES,
        Permission.GENERATE_REPORTS,
        Permission.VIEW_ANALYSES,
        Permission.USE_LEARNING_MODE,
    },
    UserRole.STUDENT: {
        Permission.ANALYZE_APPROVED_SAMPLES,
        Permission.USE_LEARNING_MODE,
        Permission.VIEW_OWN_REPORTS,
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
