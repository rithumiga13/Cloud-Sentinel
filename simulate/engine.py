"""Simulation engine: action handler and background random activity generator."""

import asyncio
import random
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from database import SessionLocal
from models import User, Session as UserSession
from iam.service import check_permission
from audit.service import write_audit_log
from threats.engine import evaluate_and_alert

# ---------------------------------------------------------------------------
# Simulated cloud resources and valid actions per resource
# ---------------------------------------------------------------------------

RESOURCE_ACTIONS: dict[str, list[str]] = {
    "s3":     ["list", "get", "put", "delete"],
    "ec2":    ["describe", "start", "stop", "terminate"],
    "lambda": ["list", "invoke"],
    "rds":    ["describe", "connect"],
    "iam":    ["list-users", "attach-policy"],
    "vpc":    ["describe", "modify"],
}

_SIMULATED_IPS = [
    "10.0.1.1", "10.0.1.2", "192.168.10.5",
    "172.16.5.20", "198.51.100.9",
]


async def handle_action(
    db: Session,
    user_id: int,
    resource: str,
    action: str,
    session_mfa_verified: bool = False,
    ip: Optional[str] = None,
    session_id: Optional[int] = None,
) -> dict:
    """
    Evaluate authorization for (user, resource, action) and persist an audit log entry.

    Returns a dict with keys: allowed, reason, risk_delta, alert_count.
    """
    user: Optional[User] = db.query(User).filter(User.id == user_id).first()
    if not user:
        return {"allowed": False, "reason": "User not found", "risk_delta": 0.0, "alert_count": 0}

    sim_ip = ip or random.choice(_SIMULATED_IPS)
    allowed, reason = check_permission(db, user.role, resource, action)
    audit_status = "safe" if allowed else "blocked"

    # Determine risk delta
    risk_delta = 0.0
    if not allowed:
        risk_delta = 5.0
    elif resource == "iam":
        risk_delta = 10.0

    log = write_audit_log(
        db,
        user_id=user_id,
        action=action,
        resource=resource,
        status=audit_status,
        ip=sim_ip,
        session_id=session_id,
        risk_delta=risk_delta,
        details=reason,
    )

    # Broadcast audit event over WebSocket
    from websocket.manager import manager
    asyncio.create_task(manager.broadcast_event({
        "id": log.id,
        "user_id": user_id,
        "user_email": user.email,
        "action": action,
        "resource": resource,
        "status": audit_status,
        "ip_address": sim_ip,
        "timestamp": log.timestamp.isoformat(),
        "risk_delta": risk_delta,
    }))

    # Run threat detection
    alerts = await evaluate_and_alert(
        db,
        user_id=user_id,
        action=action,
        resource=resource,
        role=user.role,
        session_mfa_verified=session_mfa_verified,
        timestamp=log.timestamp,
    )

    return {
        "allowed": allowed,
        "reason": reason,
        "risk_delta": risk_delta,
        "alert_count": len(alerts),
    }


# ---------------------------------------------------------------------------
# Background simulator — 3 virtual users generating random activity
# ---------------------------------------------------------------------------

_bg_running = False


async def _simulate_background_activity() -> None:
    """Continuously generate random IAM activity for background demo users."""
    global _bg_running
    _bg_running = True

    while _bg_running:
        await asyncio.sleep(10)
        try:
            db: Session = SessionLocal()
            try:
                # Pick background users (user_id 2, 3, 4 after seeding)
                bg_users = db.query(User).filter(User.id.in_([2, 3, 4])).all()
                if not bg_users:
                    continue
                user = random.choice(bg_users)
                resource = random.choice(list(RESOURCE_ACTIONS.keys()))
                action = random.choice(RESOURCE_ACTIONS[resource])
                await handle_action(
                    db, user.id, resource, action,
                    session_mfa_verified=bool(user.mfa_enabled),
                )
            finally:
                db.close()
        except Exception:
            pass  # Background task must not crash the server


def start_background_simulator() -> None:
    """Schedule the background activity simulator as an asyncio task."""
    asyncio.create_task(_simulate_background_activity())


def stop_background_simulator() -> None:
    """Signal the background simulator to stop."""
    global _bg_running
    _bg_running = False
