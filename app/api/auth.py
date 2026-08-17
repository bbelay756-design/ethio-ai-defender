"""
Authentication and Access Control API Endpoints.
"""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Header, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.core.logger import logger
from app.db.session import get_db
from app.db.models import UserModel
from app.auth.roles import UserRole, Permission, ROLE_PERMISSIONS
from app.auth.service import (
    AuthService,
    AuthenticationError,
    AccountLockedError,
    RateLimitExceededError,
)
from app.auth.dependencies import (
    get_current_user,
    get_token_from_header,
    require_roles,
    require_permissions,
)
from app.audit.logger import audit_logger
from app.audit.events import AuditEventType, AuditResult

router = APIRouter(prefix="/api/auth", tags=["Authentication & Access Control"])


# --- Schemas ---
class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: str = Field(..., min_length=5, max_length=128, pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    password: str = Field(..., min_length=8, max_length=128)
    role: Optional[str] = Field("STUDENT", description="ADMIN, ANALYST, or STUDENT")


class UserLoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class AuthUserInfo(BaseModel):
    user_id: int
    username: str
    role: str
    dashboard_url: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    jti: str
    user_id: int
    username: str
    role: str
    dashboard_url: str
    user: Optional[AuthUserInfo] = None
    expires_at: str


class UserProfileResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: str
    email: str
    role: str
    dashboard_url: Optional[str] = None
    permissions: List[str]
    is_active: bool


class RoleUpdateRequest(BaseModel):
    role: str = Field(..., description="ADMIN, ANALYST, or STUDENT")


# --- Endpoints ---
@router.post("/register", response_model=UserProfileResponse, status_code=status.HTTP_201_CREATED)
def register(
    req: UserRegisterRequest,
    db: Session = Depends(get_db)
):
    """
    Registers a new platform user with salted PBKDF2-HMAC-SHA256 password hashing.
    """
    try:
        user = AuthService.register_user(
            db=db,
            username=req.username,
            email=req.email,
            password=req.password,
            role=req.role or "STUDENT"
        )
        user_role = UserRole(user.role)
        perms = [p.value for p in ROLE_PERMISSIONS.get(user_role, set())]
        
        # Log user registration as admin/user event
        audit_logger.log_event(
            event=AuditEventType.ADMINISTRATIVE_CHANGES,
            result=AuditResult.SUCCESS,
            user_id=user.id,
            details={"action": "USER_REGISTRATION", "registered_username": user.username, "assigned_role": user.role},
            db=db,
        )

        role_str = str(user.role).upper()
        return UserProfileResponse(
            id=user.id,
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=role_str,
            dashboard_url=f"/{role_str.lower()}/dashboard",
            permissions=perms,
            is_active=bool(user.is_active)
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


@router.post("/login", response_model=TokenResponse)
def login(
    req: UserLoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Authenticates user and returns an HMAC-SHA256 signed access token.
    Enforces brute-force rate limiting and account lockout.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        user = AuthService.authenticate_user(
            db=db,
            username=req.username,
            password=req.password,
            client_ip=client_ip
        )
        token_data = AuthService.create_token_for_user(user)

        # Log successful login (strictly without password or token)
        audit_logger.log_login(
            result=AuditResult.SUCCESS,
            username=user.username,
            user_id=user.id,
            ip_address=client_ip,
            db=db,
        )

        return TokenResponse(**token_data)
    except AccountLockedError as ale:
        audit_logger.log_login(
            result=AuditResult.LOCKED,
            username=req.username,
            ip_address=client_ip,
            details={"reason": "Account locked out"},
            db=db,
        )
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail=str(ale))
    except RateLimitExceededError as rle:
        audit_logger.log_login(
            result=AuditResult.DENIED,
            username=req.username,
            ip_address=client_ip,
            details={"reason": "Rate limit exceeded"},
            db=db,
        )
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(rle))
    except AuthenticationError as ae:
        audit_logger.log_login(
            result=AuditResult.FAILURE,
            username=req.username,
            ip_address=client_ip,
            details={"reason": "Invalid credentials"},
            db=db,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(ae))


@router.post("/logout", summary="Log out and invalidate access token")
def logout(
    request: Request,
    token: str = Depends(get_token_from_header),
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Revokes the current access token by adding its JTI to the revocation blacklist.
    """
    success = AuthService.revoke_token(db, token)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to revoke token.")

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_logger.log_logout(
        user_id=current_user.id,
        username=current_user.username,
        ip_address=client_ip,
        db=db,
    )
    return {"message": "Successfully logged out. Token revoked."}


@router.get("/me", response_model=UserProfileResponse)
def get_current_user_profile(
    current_user: UserModel = Depends(get_current_user)
):
    """
    Returns authenticated user profile, role, and permission grants.
    """
    user_role = UserRole(current_user.role)
    perms = [p.value for p in ROLE_PERMISSIONS.get(user_role, set())]
    role_str = str(current_user.role).upper()
    return UserProfileResponse(
        id=current_user.id,
        user_id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=role_str,
        dashboard_url=f"/{role_str.lower()}/dashboard",
        permissions=perms,
        is_active=bool(current_user.is_active)
    )


@router.get("/users", response_model=List[UserProfileResponse], dependencies=[Depends(require_roles(UserRole.ADMIN))])
def list_all_users(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """
    Admin Only: Lists all registered platform users.
    """
    users = AuthService.list_users(db, skip=skip, limit=limit)
    res = []
    for u in users:
        u_role = UserRole(u.role)
        perms = [p.value for p in ROLE_PERMISSIONS.get(u_role, set())]
        role_str = str(u.role).upper()
        res.append(UserProfileResponse(
            id=u.id,
            user_id=u.id,
            username=u.username,
            email=u.email,
            role=role_str,
            dashboard_url=f"/{role_str.lower()}/dashboard",
            permissions=perms,
            is_active=bool(u.is_active)
        ))
    return res


@router.put("/users/{user_id}/role", response_model=UserProfileResponse)
def update_user_role_admin(
    user_id: int,
    req: RoleUpdateRequest,
    admin_user: UserModel = Depends(require_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db)
):
    """
    Admin Only: Modifies a user's role and access level.
    """
    try:
        user = AuthService.update_user_role(db, user_id=user_id, new_role=req.role)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User ID {user_id} not found.")

        # Log administrative change in audit system
        audit_logger.log_admin_change(
            action="UPDATE_USER_ROLE",
            target_user_id=user.id,
            target_username=user.username,
            admin_user_id=admin_user.id,
            details={"new_role": req.role, "updated_by": admin_user.username},
            db=db,
        )

        u_role = UserRole(user.role)
        perms = [p.value for p in ROLE_PERMISSIONS.get(u_role, set())]
        role_str = str(user.role).upper()
        return UserProfileResponse(
            id=user.id,
            user_id=user.id,
            username=user.username,
            email=user.email,
            role=role_str,
            dashboard_url=f"/{role_str.lower()}/dashboard",
            permissions=perms,
            is_active=bool(user.is_active)
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


# --- Object-Level Authorization Endpoints ---
@router.get("/analyses/{analysis_id}")
def get_user_analysis_object(
    analysis_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Object-Level Authorization:
    - Admin: can view any analysis report.
    - Analyst: can view analyses.
    - Student: can view ONLY their own analysis reports.
    """
    from app.db.models import SampleModel

    sample = db.query(SampleModel).filter(SampleModel.analysis_id == analysis_id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Analysis '{analysis_id}' not found.")

    # Object-level authorization check:
    # If Student, must be the owner of the sample
    if current_user.role == UserRole.STUDENT.value:
        if sample.user_id is not None and sample.user_id != current_user.id:
            logger.warning(
                f"Object-Level Auth Violation: Student '{current_user.username}' (ID: {current_user.id}) "
                f"attempted to access analysis '{analysis_id}' owned by user ID {sample.user_id}."
            )
            audit_logger.log_security_alert(
                alert_type="OBJECT_AUTH_VIOLATION",
                description=f"Student '{current_user.username}' attempted unauthorized view of analysis '{analysis_id}'",
                user_id=current_user.id,
                analysis_id=analysis_id,
                details={"target_owner_id": sample.user_id},
                db=db,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You do not own this analysis report."
            )

    return {
        "analysis_id": sample.analysis_id,
        "filename": sample.filename,
        "owner_id": sample.user_id,
        "status": sample.status,
        "sha256": sample.sha256
    }


@router.delete("/analyses/{analysis_id}")
def delete_user_analysis_object(
    analysis_id: str,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Object-Level Authorization:
    - Admin: can delete any analysis.
    - Owner: can delete their own analysis.
    - Non-Owner: denied with 403 Forbidden.
    """
    from app.db.models import SampleModel

    sample = db.query(SampleModel).filter(SampleModel.analysis_id == analysis_id).first()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Analysis '{analysis_id}' not found.")

    # Only Admin or Owner can delete
    if current_user.role != UserRole.ADMIN.value and sample.user_id != current_user.id:
        logger.warning(
            f"Object-Level Modification Denied: User '{current_user.username}' (ID: {current_user.id}) "
            f"attempted to delete analysis '{analysis_id}' owned by user ID {sample.user_id}."
        )
        audit_logger.log_security_alert(
            alert_type="OBJECT_DELETE_VIOLATION",
            description=f"User '{current_user.username}' attempted unauthorized delete of analysis '{analysis_id}'",
            user_id=current_user.id,
            analysis_id=analysis_id,
            details={"target_owner_id": sample.user_id},
            db=db,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You cannot delete another user's analysis."
        )

    db.delete(sample)
    db.commit()
    logger.info(f"Analysis '{analysis_id}' successfully deleted by user '{current_user.username}' (Role: {current_user.role})")
    audit_logger.log_admin_change(
        action="DELETE_ANALYSIS",
        target_user_id=sample.user_id,
        admin_user_id=current_user.id,
        details={"deleted_analysis_id": analysis_id, "deleted_by_role": current_user.role},
        db=db,
    )
    return {"message": f"Analysis '{analysis_id}' deleted successfully."}
