"""Authentication service: registration, login, token management, brute-force protection."""

from __future__ import annotations
import os
import hashlib
import random
import uuid
from datetime import datetime, timedelta
from typing import Optional

from jose import jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from models import User, Session as UserSession, RoleEnum
from audit.service import write_audit_log

SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-dev-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 60

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Simulated IP pool for demo purposes
_SIMULATED_IPS = [
    "10.0.0.1", "10.0.0.2", "192.168.1.50", "172.16.0.10",
    "203.0.113.5", "198.51.100.3", "192.0.2.7",
]


def _hash_token(token: str) -> str:
    """Return SHA-256 hex digest of a token string."""
    return hashlib.sha256(token.encode()).hexdigest()


def _random_ip() -> str:
    """Return a random simulated IP address."""
    return random.choice(_SIMULATED_IPS)


def _create_access_token(user_id: int, role: str) -> str:
    """Create a signed JWT access token with user id and role claims."""
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": str(user_id), "role": role, "exp": expire, "type": "access",
         "jti": uuid.uuid4().hex},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def _create_refresh_token(user_id: int) -> str:
    """Create a signed JWT refresh token."""
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return jwt.encode(
        {"sub": str(user_id), "exp": expire, "type": "refresh",
         "jti": uuid.uuid4().hex},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def register_user(
    db: Session,
    email: str,
    password: str,
    role: str = "normal_user",
    ip: str | None = None,
) -> User:
    """Register a new user with a bcrypt-hashed password. Raises ValueError on duplicate email."""
    if db.query(User).filter(User.email == email).first():
        raise ValueError("Email already registered")
    hashed = pwd_ctx.hash(password)
    user = User(email=email, password_hash=hashed, role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    write_audit_log(
        db,
        user_id=user.id,
        action="register",
        resource="auth",
        status="safe",
        ip=ip or _random_ip(),
        details=f"New {role} registered",
    )
    return user


def login_user(
    db: Session,
    email: str,
    password: str,
    ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, str]:
    """
    Verify credentials and issue access + refresh tokens.

    Returns (access_token, refresh_token).
    Raises ValueError for invalid credentials or locked accounts.
    """
    sim_ip = ip or _random_ip()
    user: Optional[User] = db.query(User).filter(User.email == email).first()

    if user is None:
        write_audit_log(db, user_id=None, action="login_failed", resource="auth",
                        status="suspicious", ip=sim_ip, details="Unknown email")
        raise ValueError("Invalid credentials")

    # Brute-force lockout check
    if user.locked_until and user.locked_until > datetime.utcnow():
        write_audit_log(db, user_id=user.id, action="login_blocked", resource="auth",
                        status="blocked", ip=sim_ip, details="Account locked")
        raise ValueError(f"Account locked until {user.locked_until.isoformat()}")

    if not pwd_ctx.verify(password, user.password_hash):
        user.failed_logins += 1
        if user.failed_logins >= MAX_FAILED_LOGINS:
            user.locked_until = datetime.utcnow() + timedelta(seconds=LOCKOUT_SECONDS)
            write_audit_log(db, user_id=user.id, action="account_locked", resource="auth",
                            status="blocked", ip=sim_ip, details="Too many failed attempts")
        else:
            write_audit_log(db, user_id=user.id, action="login_failed", resource="auth",
                            status="suspicious", ip=sim_ip,
                            details=f"Failed attempt {user.failed_logins}/{MAX_FAILED_LOGINS}")
        db.commit()
        raise ValueError("Invalid credentials")

    if not user.is_active:
        raise ValueError("Account deactivated")

    # Reset failure counter on successful auth
    user.failed_logins = 0
    user.locked_until = None
    user.last_active = datetime.utcnow()

    access_token = _create_access_token(user.id, user.role)
    refresh_token = _create_refresh_token(user.id)

    session = UserSession(
        user_id=user.id,
        token_hash=_hash_token(access_token),
        refresh_token_hash=_hash_token(refresh_token),
        expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        ip_address=sim_ip,
        user_agent=user_agent,
    )
    db.add(session)
    db.commit()

    write_audit_log(db, user_id=user.id, action="login", resource="auth",
                    status="safe", ip=sim_ip, session_id=session.id,
                    details=f"Login from {sim_ip}")
    return access_token, refresh_token


def refresh_tokens(db: Session, refresh_token: str) -> tuple[str, str]:
    """
    Rotate tokens: validate refresh JWT, revoke old session, issue new pair.

    Returns (new_access_token, new_refresh_token).
    """
    from jose import JWTError
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise ValueError("Not a refresh token")
        user_id: int = int(payload["sub"])
    except (JWTError, KeyError):
        raise ValueError("Invalid refresh token")

    token_hash = _hash_token(refresh_token)
    session: Optional[UserSession] = (
        db.query(UserSession)
        .filter(UserSession.refresh_token_hash == token_hash, UserSession.revoked == False)
        .first()
    )
    if session is None:
        raise ValueError("Refresh token not found or already revoked")

    user: Optional[User] = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise ValueError("User not found")

    session.revoked = True

    new_access = _create_access_token(user.id, user.role)
    new_refresh = _create_refresh_token(user.id)

    new_session = UserSession(
        user_id=user.id,
        token_hash=_hash_token(new_access),
        refresh_token_hash=_hash_token(new_refresh),
        expires_at=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        ip_address=session.ip_address,
    )
    db.add(new_session)
    db.commit()
    return new_access, new_refresh


def logout_user(db: Session, token_hash: str, user_id: int) -> None:
    """Revoke the session identified by token_hash."""
    session: Optional[UserSession] = (
        db.query(UserSession)
        .filter(UserSession.token_hash == token_hash, UserSession.user_id == user_id)
        .first()
    )
    if session:
        session.revoked = True
        db.commit()
    write_audit_log(db, user_id=user_id, action="logout", resource="auth",
                    status="safe", ip=_random_ip(), details="Session revoked")
