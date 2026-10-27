"""
YARA Rule Management API (Phase 3C).

Provides REST endpoints for:
- Creating stable rule identities.
- Listing rules with bounded pagination and filtering.
- Retrieving individual rule status and ordered version history.
- Publishing immutable versions with YARA validation and SHA-256 digests.
- Lifecycle deactivation and reactivation with audit events.
- Strict RBAC: ADMIN required for mutations, ANALYST/ADMIN for read operations.
"""

import math
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import YaraRuleModel, UserModel
from app.db.schemas import (
    YaraRuleCreate,
    YaraRulePublish,
    YaraRuleRead,
    YaraRuleVersionRead,
    YaraRuleListResponse,
    YaraRuleVersionListResponse,
)
from app.auth.roles import UserRole
from app.auth.dependencies import require_roles
from app.services.yara_rule_publication_service import (
    create_rule_identity,
    validate_yara_source,
    publish_rule_version_safe,
    get_rule_by_id_or_name,
    get_rule_version_history,
    list_rules,
    deactivate_rule,
    reactivate_rule,
)

router = APIRouter(prefix="/api/yara/rules", tags=["YARA Rule Management"])


# ---------------------------------------------------------------------------
# 1. Create Rule Identity
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=YaraRuleRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new YARA rule identity (Admin only)",
    description="Creates a stable rule identity. If source is provided, validates and publishes version 1.",
)
def create_rule(
    payload: YaraRuleCreate,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_roles(UserRole.ADMIN)),
):
    # Validate source if provided
    if payload.source is not None and payload.source.strip():
        is_valid, err_msg = validate_yara_source(payload.source)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid YARA source: {err_msg}",
            )

    try:
        rule = create_rule_identity(
            db=db,
            name=payload.name,
            namespace=payload.namespace or "default",
            source=payload.source or "",
            description=payload.description,
            author=payload.author,
            tags=payload.tags,
            user_id=current_user.id,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # If source was provided, publish version 1
    if payload.source is not None and payload.source.strip():
        version, pub_err = publish_rule_version_safe(
            db=db,
            rule_name=rule.name,
            source=payload.source,
            author=payload.author,
            tags=payload.tags,
            user_id=current_user.id,
        )
        if pub_err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Rule identity created but initial publication failed: {pub_err}",
            )
        db.refresh(rule)

    return rule


# ---------------------------------------------------------------------------
# 2. List Rules
# ---------------------------------------------------------------------------


@router.get(
    "",
    response_model=YaraRuleListResponse,
    summary="List YARA rules with bounded pagination (Analyst/Admin)",
    description="Returns paginated list of stable rule identities with optional filters.",
)
def get_rules(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page (max 100)"),
    namespace: Optional[str] = Query(None, description="Filter by namespace"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    search: Optional[str] = Query(None, description="Search term for name, description, author"),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    items, total = list_rules(
        db=db,
        page=page,
        page_size=page_size,
        namespace=namespace,
        is_active=is_active,
        search=search,
    )
    pages = math.ceil(total / page_size) if total > 0 else 1
    return YaraRuleListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


# ---------------------------------------------------------------------------
# 3. Retrieve Individual Rule
# ---------------------------------------------------------------------------


@router.get(
    "/{rule_id_or_name}",
    response_model=YaraRuleRead,
    summary="Retrieve an individual YARA rule (Analyst/Admin)",
    description="Fetches a stable rule identity and its current version by ID or name.",
)
def get_rule(
    rule_id_or_name: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    rule = get_rule_by_id_or_name(db, rule_id_or_name)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id_or_name}' not found.",
        )
    return rule


# ---------------------------------------------------------------------------
# 4. Retrieve Rule Version History
# ---------------------------------------------------------------------------


@router.get(
    "/{rule_id_or_name}/versions",
    response_model=YaraRuleVersionListResponse,
    summary="Retrieve version history for a rule (Analyst/Admin)",
    description="Returns ordered, immutable version history for a YARA rule.",
)
def get_rule_versions(
    rule_id_or_name: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_roles(UserRole.ADMIN, UserRole.ANALYST)),
):
    result = get_rule_version_history(db, rule_id_or_name)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id_or_name}' not found.",
        )
    rule, versions = result
    return YaraRuleVersionListResponse(
        rule=rule,
        versions=versions,
        total_versions=len(versions),
    )


# ---------------------------------------------------------------------------
# 5. Publish New Rule Version
# ---------------------------------------------------------------------------


@router.post(
    "/{rule_id_or_name}/publish",
    response_model=YaraRuleVersionRead,
    status_code=status.HTTP_201_CREATED,
    summary="Publish a new immutable rule version (Admin only)",
    description="Validates YARA source, creates an immutable version row with SHA-256, and advances current pointer.",
)
def publish_version(
    rule_id_or_name: str,
    payload: YaraRulePublish,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_roles(UserRole.ADMIN)),
):
    rule = get_rule_by_id_or_name(db, rule_id_or_name)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id_or_name}' not found.",
        )

    # Validate YARA source syntax
    is_valid, err_msg = validate_yara_source(payload.source)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid YARA source: {err_msg}",
        )

    version, pub_err = publish_rule_version_safe(
        db=db,
        rule_name=rule.name,
        source=payload.source,
        author=payload.author,
        severity=payload.severity,
        category=payload.category,
        tags=payload.tags,
        user_id=current_user.id,
    )
    if pub_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Publication failed: {pub_err}",
        )

    return version


# ---------------------------------------------------------------------------
# 6. Deactivate Rule
# ---------------------------------------------------------------------------


@router.post(
    "/{rule_id_or_name}/deactivate",
    response_model=YaraRuleRead,
    summary="Deactivate a YARA rule (Admin only)",
    description="Sets is_active to False. Preserves all version history and match provenance.",
)
def deactivate_rule_endpoint(
    rule_id_or_name: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_roles(UserRole.ADMIN)),
):
    rule = get_rule_by_id_or_name(db, rule_id_or_name)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id_or_name}' not found.",
        )

    updated = deactivate_rule(db, rule.name, user_id=current_user.id)
    return updated


# ---------------------------------------------------------------------------
# 7. Reactivate Rule
# ---------------------------------------------------------------------------


@router.post(
    "/{rule_id_or_name}/reactivate",
    response_model=YaraRuleRead,
    summary="Reactivate a YARA rule (Admin only)",
    description="Sets is_active to True. Preserves all version history and match provenance.",
)
def reactivate_rule_endpoint(
    rule_id_or_name: str,
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(require_roles(UserRole.ADMIN)),
):
    rule = get_rule_by_id_or_name(db, rule_id_or_name)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Rule '{rule_id_or_name}' not found.",
        )

    updated = reactivate_rule(db, rule.name, user_id=current_user.id)
    return updated
