"""Administration API router: user management, session control, system health."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db
from schemas import APIResponse, UserOut, UserCreateRequest, RoleUpdateRequest, SessionOut, SystemHealthOut
from auth.dependencies import require_role
from models import User, RoleEnum
from admin.service import (
    list_users, create_user, change_user_role, deactivate_user,
    force_password_reset, list_active_sessions, revoke_session, get_system_health,
)

router = APIRouter(prefix="/admin", tags=["Administration"])

_admin_dep = require_role(RoleEnum.admin)


@router.get("/users", response_model=APIResponse)
async def get_users(
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """List all users with role and last active info. Admin only."""
    users = list_users(db)
    return APIResponse(success=True, data=[UserOut.model_validate(u).model_dump() for u in users])


@router.post("/users", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def create_new_user(
    body: UserCreateRequest,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Create a new user account. Admin only."""
    try:
        user = create_user(db, body.email, body.password, body.role, current_user.id)
        return APIResponse(success=True, data=UserOut.model_validate(user).model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.put("/users/{user_id}/role", response_model=APIResponse)
async def update_role(
    user_id: int,
    body: RoleUpdateRequest,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Change a user's role. Admin only."""
    target: User | None = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    updated = change_user_role(db, target, body.role, current_user.id)
    return APIResponse(success=True, data=UserOut.model_validate(updated).model_dump())


@router.delete("/users/{user_id}", response_model=APIResponse)
async def delete_user(
    user_id: int,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Soft-delete (deactivate) a user. Admin only."""
    if user_id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate yourself")
    target: User | None = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    deactivate_user(db, target, current_user.id)
    return APIResponse(success=True, data={"message": f"User {user_id} deactivated"})


@router.post("/users/{user_id}/reset", response_model=APIResponse)
async def reset_password_flag(
    user_id: int,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Set force-password-reset flag on a user. Admin only."""
    target: User | None = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    force_password_reset(db, target, current_user.id)
    return APIResponse(success=True, data={"message": f"Password reset flagged for user {user_id}"})


@router.get("/sessions", response_model=APIResponse)
async def get_sessions(
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """List all active sessions. Admin only."""
    sessions = list_active_sessions(db)
    return APIResponse(success=True, data=[SessionOut.model_validate(s).model_dump() for s in sessions])


@router.delete("/sessions/{session_id}", response_model=APIResponse)
async def delete_session(
    session_id: int,
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Revoke a specific session. Admin only."""
    revoke_session(db, session_id, current_user.id)
    return APIResponse(success=True, data={"message": f"Session {session_id} revoked"})


@router.get("/system/health", response_model=APIResponse)
async def system_health(
    current_user: Annotated[User, Depends(_admin_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Return system health metrics. Admin only."""
    health = get_system_health(db)
    return APIResponse(success=True, data=health)
