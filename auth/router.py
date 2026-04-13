"""Authentication API router: register, login, refresh, logout."""

import hashlib
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from database import get_db
from schemas import APIResponse, RegisterRequest, LoginRequest, TokenResponse, RefreshRequest
from auth.service import register_user, login_user, refresh_tokens, logout_user
from auth.dependencies import get_current_user, get_current_session
from models import User, Session as UserSession

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@router.post("/register", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: Annotated[Session, Depends(get_db)]):
    """Register a new user account and return a JWT token pair."""
    try:
        user = register_user(db, body.email, body.password)
        access, refresh = login_user(db, body.email, body.password)
        return APIResponse(success=True, data=TokenResponse(
            access_token=access, refresh_token=refresh,
            user_email=user.email, user_role=user.role,
        ))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/login", response_model=APIResponse)
async def login(body: LoginRequest, request: Request, db: Annotated[Session, Depends(get_db)]):
    """Authenticate with email + password. Returns access + refresh tokens."""
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    try:
        access, refresh = login_user(db, body.email, body.password, ip=ip, user_agent=ua)
        from models import User as UserModel
        from jose import jwt as _jwt, JWTError
        try:
            payload = _jwt.decode(access, __import__("os").getenv("SECRET_KEY", "super-secret-dev-key-change-in-production"), algorithms=["HS256"])
            user = db.query(UserModel).filter(UserModel.id == int(payload["sub"])).first()
        except (JWTError, Exception):
            user = None
        return APIResponse(success=True, data=TokenResponse(
            access_token=access, refresh_token=refresh,
            user_email=user.email if user else "",
            user_role=user.role if user else "",
        ))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))


@router.post("/refresh", response_model=APIResponse)
async def refresh(body: RefreshRequest, db: Annotated[Session, Depends(get_db)]):
    """Rotate the access/refresh token pair using a valid refresh token."""
    try:
        access, refresh = refresh_tokens(db, body.refresh_token)
        return APIResponse(success=True, data=TokenResponse(access_token=access, refresh_token=refresh))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))


@router.post("/logout", response_model=APIResponse)
async def logout(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[UserSession, Depends(get_current_session)],
    db: Annotated[Session, Depends(get_db)],
):
    """Invalidate the current session token."""
    logout_user(db, session.token_hash, current_user.id)
    return APIResponse(success=True, data={"message": "Logged out successfully"})
