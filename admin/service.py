"""Administration service: user management, session control, system health."""

import time
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from models import User, Session as UserSession, AuditLog, Alert, RiskSnapshot
from audit.service import write_audit_log
from threats.engine import get_current_risk

_START_TIME: float = time.time()


def list_users(db: Session) -> list[User]:
    """Return all users ordered by creation date."""
    return db.query(User).order_by(User.created_at).all()


def create_user(
    db: Session,
    email: str,
    password: str,
    role: str,
    actor_id: int,
) -> User:
    """Create a new user account. Returns the created User."""
    from auth.service import register_user
    user = register_user(db, email, password, role)
    write_audit_log(
        db,
        user_id=actor_id,
        action="create_user",
        resource="admin",
        status="safe",
        ip="0.0.0.0",
        details=f"Created user {email} with role {role}",
    )
    return user


def change_user_role(
    db: Session,
    target_user: User,
    new_role: str,
    actor_id: int,
) -> User:
    """Update the role of a user. Returns the modified User."""
    old_role = target_user.role
    target_user.role = new_role
    db.commit()
    db.refresh(target_user)
    write_audit_log(
        db,
        user_id=actor_id,
        action="role_change",
        resource="admin",
        status="safe",
        ip="0.0.0.0",
        details=f"Changed user {target_user.id} role from {old_role} to {new_role}",
    )
    return target_user


def deactivate_user(db: Session, target_user: User, actor_id: int) -> None:
    """Soft-delete a user by setting is_active=False and revoking all sessions."""
    target_user.is_active = False
    db.query(UserSession).filter(
        UserSession.user_id == target_user.id, UserSession.revoked == False
    ).update({"revoked": True})
    db.commit()
    write_audit_log(
        db,
        user_id=actor_id,
        action="deactivate_user",
        resource="admin",
        status="safe",
        ip="0.0.0.0",
        details=f"Deactivated user {target_user.id}",
    )


def force_password_reset(db: Session, target_user: User, actor_id: int) -> None:
    """Flag a user to require a password reset on next login."""
    target_user.force_password_reset = True
    db.commit()
    write_audit_log(
        db,
        user_id=actor_id,
        action="force_password_reset",
        resource="admin",
        status="safe",
        ip="0.0.0.0",
        details=f"Password reset flagged for user {target_user.id}",
    )


def list_active_sessions(db: Session) -> list[UserSession]:
    """Return all non-revoked, non-expired sessions."""
    return (
        db.query(UserSession)
        .filter(UserSession.revoked == False, UserSession.expires_at > datetime.utcnow())
        .order_by(UserSession.created_at.desc())
        .all()
    )


def revoke_session(db: Session, session_id: int, actor_id: int) -> None:
    """Revoke a specific session by ID."""
    session: Optional[UserSession] = db.query(UserSession).filter(UserSession.id == session_id).first()
    if session:
        session.revoked = True
        db.commit()
    write_audit_log(
        db,
        user_id=actor_id,
        action="revoke_session",
        resource="admin",
        status="safe",
        ip="0.0.0.0",
        details=f"Revoked session {session_id}",
    )


def get_system_health(db: Session) -> dict:
    """Return current system health metrics."""
    total_events = db.query(AuditLog).count()
    active_users = db.query(User).filter(User.is_active == True).count()
    active_sessions = (
        db.query(UserSession)
        .filter(UserSession.revoked == False, UserSession.expires_at > datetime.utcnow())
        .count()
    )
    uptime = time.time() - _START_TIME
    return {
        "uptime_seconds": round(uptime, 1),
        "total_events": total_events,
        "active_users": active_users,
        "active_sessions": active_sessions,
        "risk_score": get_current_risk(),
    }
