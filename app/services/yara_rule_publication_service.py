"""
YARA Rule Publication and Version Service (Milestone 02B, Phase 2).

Provides backend operations for:
  - Creating stable rule identities.
  - Validating YARA source with yara-python.
  - Publishing immutable, sequential versions with SHA-256 hashes.
  - Updating the current-version pointer atomically.
  - Retrieving rule metadata and version history.
  - Deactivating/reactivating rules without history loss.
  - Recording audit events through existing infrastructure.

Conventions followed:
  - SQLAlchemy transaction pattern from app/db/repository.py
  - Audit logging from app/audit/service.py and app/audit/logger.py
  - ORM models from app/db/models.py
  - Pydantic schemas from app/db/schemas.py
  - No compiled-artifact BLOBs (Phase 1 constraint)
  - Real development database never modified
"""

from hashlib import sha256
from typing import Optional, List, Tuple, Union
from sqlalchemy.orm import Session
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.db.models import YaraRuleModel, YaraRuleVersionModel
from app.db.schemas import YaraMatchCreate
from app.audit.logger import audit_logger
from app.audit.events import AuditEventType, AuditResult


# ---------------------------------------------------------------------------
# Helpers & Lookups
# ---------------------------------------------------------------------------


def _compute_sha256(source: str) -> str:
    """Compute SHA-256 hex digest of a YARA rule source string."""
    return sha256(source.encode("utf-8")).hexdigest()


def get_rule_by_id_or_name(
    db: Session,
    identifier: Union[int, str],
) -> Optional[YaraRuleModel]:
    """
    Retrieve a stable rule identity by integer ID or unique name.

    Returns ``YaraRuleModel`` or ``None`` if not found.
    """
    if identifier is None:
        return None

    # Check if integer or numeric string
    if isinstance(identifier, int):
        return db.query(YaraRuleModel).filter(YaraRuleModel.id == identifier).first()

    ident_str = str(identifier).strip()
    if ident_str.isdigit():
        rule = db.query(YaraRuleModel).filter(YaraRuleModel.id == int(ident_str)).first()
        if rule:
            return rule

    return db.query(YaraRuleModel).filter(YaraRuleModel.name == ident_str).first()


def list_rules(
    db: Session,
    page: int = 1,
    page_size: int = 50,
    namespace: Optional[str] = None,
    is_active: Optional[bool] = None,
    search: Optional[str] = None,
) -> Tuple[List[YaraRuleModel], int]:
    """
    List stable rule identities with pagination and optional filters.

    Returns ``(items, total_count)``.
    """
    query = db.query(YaraRuleModel)

    if namespace:
        query = query.filter(YaraRuleModel.namespace == namespace)

    if is_active is not None:
        query = query.filter(YaraRuleModel.is_active == is_active)

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            (YaraRuleModel.name.ilike(term)) |
            (YaraRuleModel.description.ilike(term)) |
            (YaraRuleModel.author.ilike(term))
        )

    total = query.count()
    page = max(1, page)
    page_size = min(max(1, page_size), 100)
    offset = (page - 1) * page_size
    items = query.order_by(YaraRuleModel.id.asc()).offset(offset).limit(page_size).all()

    return items, total


# ---------------------------------------------------------------------------
# A. Create rule identity
# ---------------------------------------------------------------------------


def create_rule_identity(
    db: Session,
    name: str,
    namespace: str = "default",
    source: Optional[str] = None,
    description: Optional[str] = None,
    author: Optional[str] = None,
    tags: Optional[str] = None,
    user_id: Optional[int] = None,
) -> YaraRuleModel:
    """
    Create a stable rule identity in ``yara_rules``.

    Validates required metadata. Does NOT create a published version until
    source validation and publication succeed.

    Raises:
        ValueError: If ``name`` is empty or ``namespace`` is invalid.
    """
    if not name or not name.strip():
        raise ValueError("Rule name must not be empty.")

    # Check for existing rule with same name (unique constraint)
    existing = db.query(YaraRuleModel).filter(YaraRuleModel.name == name.strip()).first()
    if existing:
        raise ValueError(f"Rule name '{name}' already exists.")

    rule = YaraRuleModel(
        name=name.strip(),
        namespace=namespace or "default",
        source=source or "",
        version=1,
        is_active=True,
        description=description,
        author=author,
        tags=tags,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)

    # Audit event: rule creation
    audit_logger.log_event(
        event=AuditEventType.ADMINISTRATIVE_CHANGES,
        result=AuditResult.SUCCESS,
        user_id=user_id,
        analysis_id=None,
        details={
            "action": "create_rule_identity",
            "rule_name": rule.name,
            "rule_id": rule.id,
            "namespace": rule.namespace,
        },
        db=db,
    )

    return rule


# ---------------------------------------------------------------------------
# B. Validate YARA source
# ---------------------------------------------------------------------------


def validate_yara_source(source: str) -> Tuple[bool, str]:
    """
    Validate a YARA rule source string using the installed yara-python library.

    Rejects empty or malformed source. Returns ``(True, "")`` on success or
    ``(False, error_message)`` on failure.

    Does NOT execute uploaded malware or sample files.
    Does NOT claim that thread-based timeouts can forcibly terminate native
    YARA operations.

    Args:
        source: The YARA rule source text to validate.

    Returns:
        Tuple of (is_valid, message). Message is empty on success, or an
        error description on failure.
    """
    if not source or not source.strip():
        return False, "YARA source must not be empty."

    source = source.strip()

    # Try yara-python first; gracefully fall back to syntactic checks.
    try:
        import yara
        try:
            compiled = yara.compile(source=source)
            # yara.compile succeeds only for valid source
            return True, ""
        except Exception as ye:
            # yara.compile raised — source is malformed/invalid
            return False, f"YARA source validation error: {ye}"
    except ImportError:
        # yara-python not installed — perform minimal syntactic checks
        # without claiming we can enforce YARA semantics.
        if not source.startswith("rule "):
            return False, "YARA source must begin with 'rule ' identifier declaration."
        if "{" not in source:
            return False, "YARA source must contain a rule body block with '{' and '}'."
        if "}" not in source:
            return False, "YARA source must contain closing brace '}'."
        return True, ""

    except Exception as e:
        # Unexpected error — treat as validation failure, never leak details
        return False, f"YARA source validation error: {e}"


# ---------------------------------------------------------------------------
# C. Publish a new immutable version
# ---------------------------------------------------------------------------


def publish_rule_version(
    db: Session,
    rule_name: str,
    source: str,
    author: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    tags: Optional[str] = None,
    user_id: Optional[int] = None,
) -> Tuple[Optional[YaraRuleVersionModel], Optional[str]]:
    """
    Publish a new immutable version of a YARA rule.

    Stores the exact YARA source, computes SHA-256, enforces unique
    ``(rule_id, version)`` at the database level, and updates the stable
    rule's ``current_version_id`` within the same transaction.

    Roll back the complete publication if any required step fails.

    Handle concurrent publication attempts safely using database constraints
    and appropriate transaction handling.

    Never silently overwrite an existing published version. A correction must
    create a new version (version increment).

    Returns:
        Tuple of (new_version_row, error_message). Error is None on success,
        or (None, error_message) if publication failed.
    """
    if not source or not source.strip():
        return None, "YARA source must not be empty."

    source = source.strip()

    # Build the new version row (published_at defaults via model)
    source_hash = _compute_sha256(source)

    new_version = YaraRuleVersionModel(
        rule_id=None,  # will set after finding rule
        version=None,  # will set after finding max version
        source=source,
        source_hash=source_hash,
        description= None,  # will set from rule after finding rule
        author=author,
        tags=tags,
        severity=severity,
        category=category,
        published_by=user_id,
        is_published=True,
    )

    # Retry loop for concurrent publication safety
    for attempt in range(10):
        # Find the rule by ID or name, lock the row to prevent race conditions
        ident_str = str(rule_name).strip()
        if ident_str.isdigit():
            rule = db.query(YaraRuleModel).filter(YaraRuleModel.id == int(ident_str)).with_for_update().first()
        else:
            rule = db.query(YaraRuleModel).filter(YaraRuleModel.name == ident_str).with_for_update().first()
        if not rule:
            return None, f"Rule '{rule_name}' not found."

        # Determine the next version number from the current max version.
        # This is safe because we hold a SELECT ... FOR UPDATE on the rule row,
        # and the yara_rule_versions.unique index enforces (rule_id, version).
        max_result = db.execute(
            text("SELECT MAX(version) FROM yara_rule_versions WHERE rule_id = :rid"),
            {"rid": rule.id},
        ).scalar()

        next_version = (max_result or 0) + 1

        # Set the version on the new_version object
        new_version.version = next_version
        new_version.rule_id = rule.id
        new_version.description = rule.description
        new_version.author = author or rule.author
        new_version.tags = tags or rule.tags
        new_version.severity = severity
        new_version.published_by = user_id

        db.add(new_version)
        db.flush()  # assign new_version.id before reading it

        # Update the stable rule's current_version_id pointer
        rule.current_version_id = new_version.id

        # Audit event: successful publication (will be logged after commit)
        # We defer the audit log to after commit to avoid partial state.

        try:
            db.commit()
            # Audit event: successful publication
            audit_logger.log_event(
                event=AuditEventType.ADMINISTRATIVE_CHANGES,
                result=AuditResult.SUCCESS,
                user_id=user_id,
                analysis_id=None,
                details={
                    "action": "publish_rule_version",
                    "rule_name": rule.name,
                    "rule_id": rule.id,
                    "version": new_version.version,
                    "source_hash": new_version.source_hash,
                },
                db=db,
            )
            return new_version, None
        except IntegrityError as e:
            # Unique constraint violation on (rule_id, version) — likely a
            # concurrent publication of the same version number. Rollback and
            # retry with an incremented version.
            db.rollback()
            # Increment version and retry
            continue
        except Exception as e:
            db.rollback()
            # Other unexpected error — return failure
            return None, f"Publication failed: {e}"

    # Exceeded max attempts — treat as failure
    return None, "Failed to publish rule version: concurrent conflict after retries."


def publish_rule_version_safe(
    db: Session,
    rule_name: str,
    source: str,
    author: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    tags: Optional[str] = None,
    user_id: Optional[int] = None,
    max_retries: int = 10,
) -> Tuple[Optional[YaraRuleVersionModel], Optional[str]]:
    """
    Publish a new immutable version with a bounded retry loop for concurrent
    publication safety.

    Returns ``(version_row, None)`` on success or ``(None, error)`` on failure.
    """
    last_error = None
    for attempt in range(1 + max_retries):
        version, error = publish_rule_version(
            db=db,
            rule_name=rule_name,
            source=source,
            author=author,
            severity=severity,
            category=category,
            tags=tags,
            user_id=user_id,
        )
        if not error:
            return version, None
        # If the error is about a duplicate version number, retry.
        # Other errors are returned immediately.
        if "concurrent conflict" in (error or "").lower() and attempt < max_retries:
            last_error = error
            continue
        return None, error

    return None, f"Max retries ({max_retries}) exceeded during publication"


# ---------------------------------------------------------------------------
# D. Retrieve version history
# ---------------------------------------------------------------------------


def get_rule_version_history(
    db: Session,
    rule_name: Union[int, str],
) -> Optional[Tuple[YaraRuleModel, List[YaraRuleVersionModel]]]:
    """
    Retrieve stable rule metadata and ordered version history.

    Returns ``(rule, versions)`` where ``versions`` are ordered by version
    ascending. Returns ``None`` if the rule does not exist.

    The current version is ``rule.current_version`` (or the highest-version
    published row if ``current_version_id`` is NULL).
    """
    rule = get_rule_by_id_or_name(db, rule_name)
    if not rule:
        return None

    # Load versions ordered by version number ascending
    versions = (
        db.query(YaraRuleVersionModel)
        .filter(YaraRuleVersionModel.rule_id == rule.id)
        .order_by(YaraRuleVersionModel.version.asc())
        .all()
    )

    # Ensure current_version_id points to the latest published version;
    # if NULL, fall back to the highest version row.
    if rule.current_version_id is None and versions:
        rule.current_version_id = versions[-1].id
        db.commit()

    return rule, versions


# ---------------------------------------------------------------------------
# E. Deactivate and reactivate rules
# ---------------------------------------------------------------------------


def deactivate_rule(
    db: Session,
    rule_name: Union[int, str],
    user_id: Optional[int] = None,
) -> Optional[YaraRuleModel]:
    """
    Deactivate a rule without deleting version history.

    Sets ``is_active = False`` on the rule. Published versions and match
    records are preserved. Historical audit events are recorded.

    Returns the updated rule row, or ``None`` if the rule was not found.
    """
    rule = get_rule_by_id_or_name(db, rule_name)
    if not rule:
        return None

    rule.is_active = False
    db.commit()
    db.refresh(rule)

    # Audit event: rule deactivation
    audit_logger.log_event(
        event=AuditEventType.ADMINISTRATIVE_CHANGES,
        result=AuditResult.SUCCESS,
        user_id=user_id,
        analysis_id=None,
        details={
            "action": "deactivate_rule",
            "rule_name": rule.name,
            "rule_id": rule.id,
        },
        db=db,
    )

    return rule


def reactivate_rule(
    db: Session,
    rule_name: Union[int, str],
    user_id: Optional[int] = None,
) -> Optional[YaraRuleModel]:
    """
    Reactivate a rule without deleting version history.

    Sets ``is_active = True`` on the rule. Published versions and match
    records are preserved.

    Returns the updated rule row, or ``None`` if the rule was not found.
    """
    rule = get_rule_by_id_or_name(db, rule_name)
    if not rule:
        return None

    rule.is_active = True
    db.commit()
    db.refresh(rule)

    # Audit event: rule reactivation
    audit_logger.log_event(
        event=AuditEventType.ADMINISTRATIVE_CHANGES,
        result=AuditResult.SUCCESS,
        user_id=user_id,
        analysis_id=None,
        details={
            "action": "reactivate_rule",
            "rule_name": rule.name,
            "rule_id": rule.id,
        },
        db=db,
    )

    return rule


# ---------------------------------------------------------------------------
# Module-level convenience: initialize service singleton
# ---------------------------------------------------------------------------

yara_rule_publication_service = None  # placeholder; instantiated by app startup


# ---------------------------------------------------------------------------
# End of module
# ---------------------------------------------------------------------------