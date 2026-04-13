"""Pydantic request/response schemas for the Cloud IAM Platform."""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------

class APIResponse(BaseModel):
    """Consistent JSON envelope for all API responses."""
    success: bool
    data: Any = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Auth schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_email: str = ""
    user_role: str = ""


class RefreshRequest(BaseModel):
    refresh_token: str


# ---------------------------------------------------------------------------
# User schemas
# ---------------------------------------------------------------------------

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_active: Optional[datetime]
    force_password_reset: bool


class UserCreateRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    role: str = "normal_user"


class RoleUpdateRequest(BaseModel):
    role: str


# ---------------------------------------------------------------------------
# IAM / Permission schemas
# ---------------------------------------------------------------------------

class PermissionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    role: str
    resource: str
    action: str
    effect: str


class PolicyUpdateRequest(BaseModel):
    role: str
    permissions: list[dict[str, str]]  # [{resource, action, effect}]


# ---------------------------------------------------------------------------
# Simulate schemas
# ---------------------------------------------------------------------------

class SimulateActionRequest(BaseModel):
    user_id: int
    resource: str
    action: str


class SimulateActionResponse(BaseModel):
    allowed: bool
    reason: str
    risk_delta: float


# ---------------------------------------------------------------------------
# Audit schemas
# ---------------------------------------------------------------------------

class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int]
    action: str
    resource: str
    status: str
    ip_address: str
    timestamp: datetime
    session_id: Optional[int]
    risk_delta: float
    details: Optional[str]
    compliance_flags: Optional[str]


class AuditLogPage(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[AuditLogOut]


# ---------------------------------------------------------------------------
# Alert schemas
# ---------------------------------------------------------------------------

class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    user_id: Optional[int]
    severity: str
    message: str
    created_at: datetime
    resolved_at: Optional[datetime]
    resolved_by: Optional[int]


# ---------------------------------------------------------------------------
# Risk schemas
# ---------------------------------------------------------------------------

class RiskScoreOut(BaseModel):
    score: float
    timestamp: datetime


# ---------------------------------------------------------------------------
# Admin / Session schemas
# ---------------------------------------------------------------------------

class SessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: int
    created_at: datetime
    expires_at: datetime
    revoked: bool
    ip_address: Optional[str]


class SystemHealthOut(BaseModel):
    uptime_seconds: float
    total_events: int
    active_users: int
    active_sessions: int
    risk_score: float


# ---------------------------------------------------------------------------
# Group schemas
# ---------------------------------------------------------------------------

class GroupPermissionIn(BaseModel):
    resource: str
    action: str
    effect: str = "allow"


class GroupCreateRequest(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    description: Optional[str] = None


class GroupMemberRequest(BaseModel):
    user_id: int


class GroupPermissionRequest(BaseModel):
    resource: str
    action: str
    effect: str = "allow"


class GroupPermissionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    group_id: int
    resource: str
    action: str
    effect: str


class GroupMemberOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    user_id: int
    group_id: int
    assigned_by: Optional[int]
    assigned_at: datetime


class GroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: Optional[str]
    created_at: datetime
    created_by: Optional[int]


class GroupDetailOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    description: Optional[str]
    created_at: datetime
    members: list[GroupMemberOut] = []
    permissions: list[GroupPermissionOut] = []


# ---------------------------------------------------------------------------
# Permission boundary schemas
# ---------------------------------------------------------------------------

class BoundaryPair(BaseModel):
    resource: str
    action: str


class BoundarySetRequest(BaseModel):
    pairs: list[BoundaryPair]


class BoundaryOut(BaseModel):
    user_id: int
    boundary_pairs: list[BoundaryPair]
    updated_at: Optional[datetime]


# ---------------------------------------------------------------------------
# IAM evaluation / effective schemas
# ---------------------------------------------------------------------------

class ConditionOut(BaseModel):
    condition_type: str
    condition_value: str
    description: Optional[str] = None


class EvaluateRequest(BaseModel):
    user_id: int
    resource: str
    action: str
    mfa_verified: bool = False
    ip: str = "10.0.0.1"
    env_tag: str = "dev"


class EvaluationResult(BaseModel):
    allowed: bool
    decision: str
    matched_source: str
    role_checked: str
    inherited_roles: list[str]
    groups_checked: list[str]
    abac_trace: list[str]
    boundary_applied: bool
    deny_source: str


# ---------------------------------------------------------------------------
# Analyzer schemas
# ---------------------------------------------------------------------------

class AnalyzerFinding(BaseModel):
    role: str
    resource: str
    action: str
    effect: str
    suggestion: str


class AnalyzerResponse(BaseModel):
    findings: list[AnalyzerFinding]
    scanned_at: datetime
