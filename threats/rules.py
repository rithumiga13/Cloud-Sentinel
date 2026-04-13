"""Threat detection rule definitions R1–R8."""

from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional

from sqlalchemy.orm import Session

from models import AuditLog, Alert, User, Session as UserSession


@dataclass
class RuleResult:
    """Result from a single rule evaluation."""
    triggered: bool
    rule_id: str
    severity: str
    message: str
    user_id: Optional[int] = None


def _count_recent(db: Session, user_id: int, action: str, seconds: int) -> int:
    """Count audit log entries for a user matching an action within the last N seconds."""
    since = datetime.utcnow() - timedelta(seconds=seconds)
    return (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == user_id,
            AuditLog.action == action,
            AuditLog.timestamp >= since,
        )
        .count()
    )


def rule_r1_brute_force(db: Session, user_id: Optional[int], action: str) -> RuleResult:
    """R1 — Failed login > 5 in 60 s → HIGH alert, lock account."""
    if action != "login_failed" or user_id is None:
        return RuleResult(False, "R1", "HIGH", "")
    count = _count_recent(db, user_id, "login_failed", 60)
    if count >= 5:
        return RuleResult(True, "R1", "HIGH",
                          f"Brute-force detected: {count} failed logins in 60s for user {user_id}",
                          user_id=user_id)
    return RuleResult(False, "R1", "HIGH", "")


def rule_r2_iam_non_admin(db: Session, user_id: Optional[int], resource: str, role: str) -> RuleResult:
    """R2 — Non-Admin calls IAM endpoint → HIGH alert."""
    if "iam" in resource.lower() and role != "admin":
        return RuleResult(True, "R2", "HIGH",
                          f"Non-Admin user {user_id} accessed IAM resource '{resource}'",
                          user_id=user_id)
    return RuleResult(False, "R2", "HIGH", "")


def rule_r3_off_hours(db: Session, user_id: Optional[int], timestamp: datetime) -> RuleResult:
    """R3 — Any action between 00:00–05:00 UTC → MEDIUM alert."""
    if 0 <= timestamp.hour < 5:
        return RuleResult(True, "R3", "MEDIUM",
                          f"Off-hours activity at {timestamp.strftime('%H:%M')} UTC by user {user_id}",
                          user_id=user_id)
    return RuleResult(False, "R3", "MEDIUM", "")


def rule_r4_excessive_activity(db: Session, user_id: Optional[int]) -> RuleResult:
    """R4 — Same user > 50 actions / 5 min → MEDIUM alert."""
    if user_id is None:
        return RuleResult(False, "R4", "MEDIUM", "")
    since = datetime.utcnow() - timedelta(minutes=5)
    count = (
        db.query(AuditLog)
        .filter(AuditLog.user_id == user_id, AuditLog.timestamp >= since)
        .count()
    )
    if count > 50:
        return RuleResult(True, "R4", "MEDIUM",
                          f"Excessive activity: {count} actions in 5 min by user {user_id}",
                          user_id=user_id)
    return RuleResult(False, "R4", "MEDIUM", "")


def rule_r5_self_escalation(
    db: Session, actor_id: Optional[int], target_user_id: Optional[int], action: str
) -> RuleResult:
    """R5 — Role changed on own account → HIGH alert (self-escalation)."""
    if action in ("role_change", "self_role_change") and actor_id == target_user_id and actor_id is not None:
        return RuleResult(True, "R5", "HIGH",
                          f"Self-escalation detected: user {actor_id} changed their own role",
                          user_id=actor_id)
    return RuleResult(False, "R5", "HIGH", "")


def rule_r6_repeated_denial(db: Session, user_id: Optional[int], action: str, resource: str) -> RuleResult:
    """R6 — Denied action retried > 3× → MEDIUM alert."""
    if user_id is None:
        return RuleResult(False, "R6", "MEDIUM", "")
    since = datetime.utcnow() - timedelta(minutes=10)
    count = (
        db.query(AuditLog)
        .filter(
            AuditLog.user_id == user_id,
            AuditLog.action == action,
            AuditLog.resource == resource,
            AuditLog.status == "blocked",
            AuditLog.timestamp >= since,
        )
        .count()
    )
    if count > 3:
        return RuleResult(True, "R6", "MEDIUM",
                          f"Repeated denial: user {user_id} tried '{action}' on '{resource}' {count} times",
                          user_id=user_id)
    return RuleResult(False, "R6", "MEDIUM", "")


def rule_r7_service_account_compute(
    db: Session, user_id: Optional[int], resource: str, role: str
) -> RuleResult:
    """R7 — ServiceAccount calls EC2/RDS → LOW alert (unusual for service account)."""
    if role == "service_account" and any(r in resource.lower() for r in ("ec2", "rds")):
        return RuleResult(True, "R7", "LOW",
                          f"ServiceAccount user {user_id} accessed compute/DB resource '{resource}'",
                          user_id=user_id)
    return RuleResult(False, "R7", "LOW", "")


def rule_r8_sensitive_no_mfa(
    db: Session,
    user_id: Optional[int],
    resource: str,
    session_mfa_verified: bool,
) -> RuleResult:
    """R8 — MFA not verified but sensitive resource accessed → HIGH alert."""
    sensitive = ("iam", "rds", "s3", "lambda", "vpc")
    if not session_mfa_verified and any(s in resource.lower() for s in sensitive):
        return RuleResult(True, "R8", "HIGH",
                          f"Sensitive resource '{resource}' accessed without MFA by user {user_id}",
                          user_id=user_id)
    return RuleResult(False, "R8", "HIGH", "")
