"""SQLAlchemy ORM models for the Cloud IAM Security Simulation Platform."""

from datetime import datetime
from typing import List, Optional
from sqlalchemy import (
    Integer, String, Boolean, DateTime, Float, Text,
    ForeignKey, Enum as SAEnum, UniqueConstraint
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
import enum

from database import Base


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class RoleEnum(str, enum.Enum):
    admin          = "admin"
    power_user     = "power_user"
    normal_user    = "normal_user"
    read_only      = "read_only"
    service_account = "service_account"


class EffectEnum(str, enum.Enum):
    allow = "allow"
    deny  = "deny"


class StatusEnum(str, enum.Enum):
    safe       = "safe"
    suspicious = "suspicious"
    blocked    = "blocked"


class SeverityEnum(str, enum.Enum):
    low    = "LOW"
    medium = "MEDIUM"
    high   = "HIGH"


class CSPMScanStatusEnum(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class CSPMFindingStatusEnum(str, enum.Enum):
    open = "open"
    resolved = "resolved"
    ignored = "ignored"


class ConditionTypeEnum(str, enum.Enum):
    require_mfa  = "require_mfa"   # session must be MFA-verified
    ip_allowlist = "ip_allowlist"  # comma-separated CIDRs / exact IPs
    time_window  = "time_window"   # "HH:MM-HH:MM" UTC range
    env_tag      = "env_tag"       # resource env must match value (prod/dev/staging)


# ---------------------------------------------------------------------------
# Core identity models
# ---------------------------------------------------------------------------

class User(Base):
    """Registered user with role-based access control."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(SAEnum(RoleEnum), default=RoleEnum.normal_user, nullable=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    force_password_reset: Mapped[bool] = mapped_column(Boolean, default=False)
    last_active: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    sessions: Mapped[List["Session"]] = relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="user")
    alerts: Mapped[List["Alert"]] = relationship(
        "Alert", back_populates="user", foreign_keys="Alert.user_id"
    )
    group_memberships: Mapped[List["GroupMembership"]] = relationship(
        "GroupMembership", back_populates="user", foreign_keys="GroupMembership.user_id",
        cascade="all, delete-orphan"
    )
    permission_boundary: Mapped[Optional["UserPermissionBoundary"]] = relationship(
        "UserPermissionBoundary", back_populates="user", uselist=False,
        cascade="all, delete-orphan",
        foreign_keys="UserPermissionBoundary.user_id",
    )


class Session(Base):
    """Active JWT session record, used for revocation tracking."""
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    refresh_token_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped["User"] = relationship("User", back_populates="sessions")


# ---------------------------------------------------------------------------
# RBAC: Role permissions
# ---------------------------------------------------------------------------

class Permission(Base):
    """
    Role-level permission: (role, resource, action) → allow | deny.

    May carry an optional ABAC condition that is evaluated at access time.
    """
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    role: Mapped[str] = mapped_column(SAEnum(RoleEnum), nullable=False)
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    effect: Mapped[str] = mapped_column(SAEnum(EffectEnum), default=EffectEnum.allow, nullable=False)

    conditions: Mapped[List["PolicyCondition"]] = relationship(
        "PolicyCondition", back_populates="permission", cascade="all, delete-orphan"
    )


class PolicyCondition(Base):
    """
    ABAC condition attached to a role Permission.

    Evaluated at access time using the request context (IP, time, MFA status, env tag).
    All conditions on a permission must pass for the permission to apply.
    """
    __tablename__ = "policy_conditions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    permission_id: Mapped[int] = mapped_column(ForeignKey("permissions.id"), nullable=False)
    condition_type: Mapped[str] = mapped_column(SAEnum(ConditionTypeEnum), nullable=False)
    condition_value: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    permission: Mapped["Permission"] = relationship("Permission", back_populates="conditions")


# ---------------------------------------------------------------------------
# Groups: Group definitions, membership, group-level permissions
# ---------------------------------------------------------------------------

class Group(Base):
    """
    Named collection of users.  Groups carry their own permission grants
    that are merged (deny-wins) with the user's role permissions at
    evaluation time.
    """
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)

    members: Mapped[List["GroupMembership"]] = relationship(
        "GroupMembership", back_populates="group", cascade="all, delete-orphan"
    )
    permissions: Mapped[List["GroupPermission"]] = relationship(
        "GroupPermission", back_populates="group", cascade="all, delete-orphan"
    )


class GroupMembership(Base):
    """Associates a user with a group, with assignment provenance."""
    __tablename__ = "group_memberships"
    __table_args__ = (UniqueConstraint("user_id", "group_id", name="uq_user_group"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), nullable=False)
    assigned_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    assigned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped["User"] = relationship("User", back_populates="group_memberships", foreign_keys=[user_id])
    group: Mapped["Group"] = relationship("Group", back_populates="members")


class GroupPermission(Base):
    """
    Group-level permission grant: (group, resource, action) → allow | deny.

    Group permissions are merged with role permissions at evaluation time;
    deny always wins across both sources.
    """
    __tablename__ = "group_permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), nullable=False)
    resource: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    effect: Mapped[str] = mapped_column(SAEnum(EffectEnum), default=EffectEnum.allow, nullable=False)

    group: Mapped["Group"] = relationship("Group", back_populates="permissions")


# ---------------------------------------------------------------------------
# Permission boundary (per-user max-permissions cap)
# ---------------------------------------------------------------------------

class UserPermissionBoundary(Base):
    """
    Per-user permission boundary: a JSON-encoded list of allowed
    (resource, action) pairs that caps what the user can ever do,
    regardless of their role or group grants.

    Format of boundary_json:
        [{"resource": "s3", "action": "list"}, ...]
    An empty / null boundary means no cap is applied.
    """
    __tablename__ = "user_permission_boundaries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True, nullable=False)
    boundary_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="permission_boundary", foreign_keys="[UserPermissionBoundary.user_id]")


# ---------------------------------------------------------------------------
# Audit, alerts, risk
# ---------------------------------------------------------------------------

class AuditLog(Base):
    """Immutable append-only record of every action taken in the system."""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(SAEnum(StatusEnum), default=StatusEnum.safe, nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, default="0.0.0.0")
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    session_id: Mapped[Optional[int]] = mapped_column(ForeignKey("sessions.id"), nullable=True)
    risk_delta: Mapped[float] = mapped_column(Float, default=0.0)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    compliance_flags: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")


class Alert(Base):
    """Security alert raised by the threat detection rule engine."""
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(16), nullable=False)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    severity: Mapped[str] = mapped_column(SAEnum(SeverityEnum), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    resolved_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)

    user: Mapped[Optional["User"]] = relationship(
        "User", back_populates="alerts", foreign_keys=[user_id]
    )


class RiskSnapshot(Base):
    """Point-in-time risk score snapshot for trend analysis."""
    __tablename__ = "risk_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


# ---------------------------------------------------------------------------
# AWS CSPM models
# ---------------------------------------------------------------------------

class CloudAccount(Base):
    """Read-only AWS account identity validated through STS GetCallerIdentity."""
    __tablename__ = "cloud_accounts"
    __table_args__ = (UniqueConstraint("account_id", "region", name="uq_cloud_account_region"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    account_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    arn: Mapped[str] = mapped_column(String(512), nullable=False)
    region: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_validated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scans: Mapped[List["CSPMScan"]] = relationship("CSPMScan", back_populates="cloud_account")
    findings: Mapped[List["CSPMFinding"]] = relationship("CSPMFinding", back_populates="cloud_account")


class CSPMScan(Base):
    """One persisted AWS CSPM scan execution."""
    __tablename__ = "cspm_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    cloud_account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id"), nullable=False, index=True)
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(SAEnum(CSPMScanStatusEnum), default=CSPMScanStatusEnum.pending, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    cloud_account: Mapped["CloudAccount"] = relationship("CloudAccount", back_populates="scans")
    findings: Mapped[List["CSPMFinding"]] = relationship(
        "CSPMFinding", back_populates="scan", cascade="all, delete-orphan"
    )


class CSPMFinding(Base):
    """Normalized cloud security finding produced by an AWS CSPM scan."""
    __tablename__ = "cspm_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("cspm_scans.id"), nullable=False, index=True)
    cloud_account_id: Mapped[int] = mapped_column(ForeignKey("cloud_accounts.id"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), default="aws", nullable=False)
    service: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(512), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    compliance_tags_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    status: Mapped[str] = mapped_column(SAEnum(CSPMFindingStatusEnum), default=CSPMFindingStatusEnum.open, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    scan: Mapped["CSPMScan"] = relationship("CSPMScan", back_populates="findings")
    cloud_account: Mapped["CloudAccount"] = relationship("CloudAccount", back_populates="findings")
