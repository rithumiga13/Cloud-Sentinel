"""Threat detection engine: evaluate rules, persist alerts, update dynamic risk score."""

from __future__ import annotations
import asyncio
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from models import Alert, AuditLog, RiskSnapshot, SeverityEnum
from threats.rules import (
    RuleResult,
    rule_r1_brute_force,
    rule_r2_iam_non_admin,
    rule_r3_off_hours,
    rule_r4_excessive_activity,
    rule_r5_self_escalation,
    rule_r6_repeated_denial,
    rule_r7_service_account_compute,
    rule_r8_sensitive_no_mfa,
)

# Risk score state (in-memory for performance, snapshotted to DB)
_current_risk: float = 0.0
_last_alert_time: datetime = datetime.utcnow()


def get_current_risk() -> float:
    """Return the current dynamic risk score (0–100)."""
    return round(_current_risk, 2)


def _persist_alert(db: Session, result: RuleResult) -> Alert:
    """Save a triggered rule result as an Alert row."""
    alert = Alert(
        rule_id=result.rule_id,
        user_id=result.user_id,
        severity=result.severity,
        message=result.message,
        created_at=datetime.utcnow(),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def _update_risk(db: Session, results: list[RuleResult]) -> float:
    """
    Recalculate the global risk score based on active alerts.

    Formula:
        base = 0
        +20 per active HIGH
        +10 per active MEDIUM
        +3  per active LOW
        decays 5 pts / 5 min since last alert
    """
    global _current_risk, _last_alert_time

    # Count active (unresolved) alerts
    high = db.query(Alert).filter(Alert.severity == "HIGH", Alert.resolved_at == None).count()
    medium = db.query(Alert).filter(Alert.severity == "MEDIUM", Alert.resolved_at == None).count()
    low = db.query(Alert).filter(Alert.severity == "LOW", Alert.resolved_at == None).count()

    raw_score = (high * 20) + (medium * 10) + (low * 3)

    # Apply decay
    minutes_since_alert = (datetime.utcnow() - _last_alert_time).total_seconds() / 60
    decay = max(0.0, (minutes_since_alert / 5) * 5)
    score = max(0.0, min(100.0, raw_score - decay))

    if results:  # New alerts just fired → reset decay clock
        _last_alert_time = datetime.utcnow()

    _current_risk = score

    # Persist snapshot
    snapshot = RiskSnapshot(score=score, timestamp=datetime.utcnow())
    db.add(snapshot)
    db.commit()

    return score


async def _broadcast_alert(payload: dict) -> None:
    """Broadcast a new alert over the WebSocket event channel."""
    from websocket.manager import manager
    await manager.broadcast_alert(payload)


async def evaluate_and_alert(
    db: Session,
    user_id: Optional[int],
    action: str,
    resource: str,
    role: str,
    session_mfa_verified: bool = False,
    target_user_id: Optional[int] = None,
    timestamp: Optional[datetime] = None,
) -> list[Alert]:
    """
    Run all threat rules against the current event context.

    Persists alerts for triggered rules, updates the risk score, and
    broadcasts over WebSocket. Returns the list of created Alert objects.
    """
    ts = timestamp or datetime.utcnow()
    triggered: list[RuleResult] = []

    checks = [
        rule_r1_brute_force(db, user_id, action),
        rule_r2_iam_non_admin(db, user_id, resource, role),
        rule_r3_off_hours(db, user_id, ts),
        rule_r4_excessive_activity(db, user_id),
        rule_r5_self_escalation(db, user_id, target_user_id, action),
        rule_r6_repeated_denial(db, user_id, action, resource),
        rule_r7_service_account_compute(db, user_id, resource, role),
        rule_r8_sensitive_no_mfa(db, user_id, resource, session_mfa_verified),
    ]

    new_alerts: list[Alert] = []
    for result in checks:
        if result.triggered:
            triggered.append(result)
            alert = _persist_alert(db, result)
            new_alerts.append(alert)
            # Extract scalars before session may close (avoids DetachedInstanceError)
            alert_payload = {
                "id": alert.id,
                "rule_id": alert.rule_id,
                "severity": alert.severity,
                "message": alert.message,
                "user_id": alert.user_id,
                "created_at": alert.created_at.isoformat(),
            }
            asyncio.create_task(_broadcast_alert(alert_payload))

    score = _update_risk(db, triggered)

    from websocket.manager import manager
    asyncio.create_task(manager.broadcast_risk(score))

    return new_alerts
