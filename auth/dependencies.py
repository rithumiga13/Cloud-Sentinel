"""FastAPI dependency functions for authentication and role enforcement."""

from __future__ import annotations
import os
import hashlib
from typing import Annotated, Optional
from datetime import datetime

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from database import get_db
from models import User, Session as UserSession, RoleEnum

SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-dev-key-change-in-production")
ALGORITHM = "HS256"

bearer_scheme = HTTPBearer(auto_error=False)


def _hash_token(token: str) -> str:
    """Return SHA-256 hex digest of a token string."""
    return hashlib.sha256(token.encode()).hexdigest()


def get_current_user(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Decode the JWT and return the authenticated User, raising 401 on failure."""
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int | None = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate token")

    # Verify session is still active and not revoked
    token_hash = _hash_token(token)
    session: UserSession | None = (
        db.query(UserSession)
        .filter(UserSession.token_hash == token_hash, UserSession.revoked == False)
        .first()
    )
    if session is None or session.expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or revoked")

    user: Optional[User] = db.query(User).filter(User.id == int(user_id), User.is_active == True).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or deactivated")

    # Update last_active timestamp
    user.last_active = datetime.utcnow()
    db.commit()

    return user


def get_current_session(
    credentials: Annotated[Optional[HTTPAuthorizationCredentials], Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> UserSession:
    """Return the current active session object for the bearer token."""
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    token_hash = _hash_token(credentials.credentials)
    session: UserSession | None = (
        db.query(UserSession)
        .filter(UserSession.token_hash == token_hash, UserSession.revoked == False)
        .first()
    )
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session not found")
    return session


def require_role(*roles: RoleEnum):
    """Return a dependency that enforces the caller has one of the given roles."""
    def _check(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        if current_user.role not in [r.value for r in roles]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {[r.value for r in roles]}",
            )
        return current_user
    return _check


def require_admin():
    """Convenience dependency that requires Admin role."""
    return require_role(RoleEnum.admin)
