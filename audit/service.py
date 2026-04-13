"""Audit logging service: write, query, export, and compliance flagging."""

import csv
import io
import json
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import desc

from models import AuditLog


# ---------------------------------------------------------------------------
# Compliance rule definitions
# ---------------------------------------------------------------------------

_COMPLIANCE_RULES: list[tuple[str, callable]] = [
    ("SOC2-CC6.1: Root/Admin login should use MFA", lambda e: e.action == "login" and e.details and "admin" in (e.details or "").lower()),
    ("SOC2-CC6.3: IAM policy change", lambda e: "policy" in e.action.lower()),
    ("ISO27001-A.9.4: Privileged action without MFA", lambda e: e.action in ("attach-policy", "delete") and "iam" in e.resource.lower()),
    ("SOC2-CC7.2: Off-hours access", lambda e: e.timestamp.hour < 5),
    ("SOC2-CC6.2: Cross-account simulation", lambda e: "cross" in (e.details or "").lower()),
]


def _evaluate_compliance(log: AuditLog) -> str:
    """Return a comma-separated string of triggered compliance flags for a log entry."""
    triggered = [label for label, fn in _COMPLIANCE_RULES if fn(log)]
    return "; ".join(triggered) if triggered else ""


def write_audit_log(
    db: Session,
    user_id: Optional[int],
    action: str,
    resource: str,
    status: str = "safe",
    ip: str = "0.0.0.0",
    session_id: Optional[int] = None,
    risk_delta: float = 0.0,
    details: Optional[str] = None,
) -> AuditLog:
    """
    Append a new immutable audit log entry and evaluate compliance flags.

    Returns the created AuditLog instance.
    """
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        status=status,
        ip_address=ip,
        session_id=session_id,
        risk_delta=risk_delta,
        details=details,
        timestamp=datetime.utcnow(),
    )
    db.add(entry)
    db.flush()  # Assign id before compliance check
    entry.compliance_flags = _evaluate_compliance(entry)
    db.commit()
    db.refresh(entry)
    return entry


def query_audit_logs(
    db: Session,
    user_id: Optional[int] = None,
    resource: Optional[str] = None,
    status: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[int, list[AuditLog]]:
    """
    Query audit logs with optional filters.

    Returns (total_count, page_items).
    """
    q = db.query(AuditLog)
    if user_id is not None:
        q = q.filter(AuditLog.user_id == user_id)
    if resource:
        q = q.filter(AuditLog.resource.ilike(f"%{resource}%"))
    if status:
        q = q.filter(AuditLog.status == status)
    if start_date:
        q = q.filter(AuditLog.timestamp >= start_date)
    if end_date:
        q = q.filter(AuditLog.timestamp <= end_date)

    total = q.count()
    items = q.order_by(desc(AuditLog.timestamp)).offset((page - 1) * page_size).limit(page_size).all()
    return total, items


def export_logs_csv(db: Session) -> str:
    """Export all audit logs as a CSV string."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "user_id", "action", "resource", "status",
                     "ip_address", "timestamp", "session_id", "risk_delta",
                     "details", "compliance_flags"])
    for log in logs:
        writer.writerow([
            log.id, log.user_id, log.action, log.resource, log.status,
            log.ip_address, log.timestamp.isoformat(), log.session_id,
            log.risk_delta, log.details, log.compliance_flags,
        ])
    return output.getvalue()


def export_logs_json(db: Session) -> list[dict]:
    """Export all audit logs as a list of dicts."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp).all()
    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "resource": log.resource,
            "status": log.status,
            "ip_address": log.ip_address,
            "timestamp": log.timestamp.isoformat(),
            "session_id": log.session_id,
            "risk_delta": log.risk_delta,
            "details": log.details,
            "compliance_flags": log.compliance_flags,
        }
        for log in logs
    ]
