"""Threat and alert API router: list, resolve alerts; IAM analyzer; risk score."""

from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from database import get_db
from schemas import APIResponse, AlertOut, AnalyzerFinding, AnalyzerResponse
from auth.dependencies import get_current_user
from models import Alert, User, Permission, AuditLog, RoleEnum
from threats.engine import get_current_risk

router = APIRouter(tags=["Threats & Analysis"])


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@router.get("/alerts", response_model=APIResponse)
async def list_alerts(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    resolved: Optional[bool] = Query(None),
    severity: Optional[str] = Query(None),
):
    """Return all security alerts, optionally filtered by resolved status or severity."""
    q = db.query(Alert)
    if resolved is True:
        q = q.filter(Alert.resolved_at != None)
    elif resolved is False:
        q = q.filter(Alert.resolved_at == None)
    if severity:
        q = q.filter(Alert.severity == severity.upper())
    alerts = q.order_by(Alert.created_at.desc()).all()
    return APIResponse(success=True, data=[AlertOut.model_validate(a).model_dump() for a in alerts])


@router.post("/alerts/{alert_id}/resolve", response_model=APIResponse)
async def resolve_alert(
    alert_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """Mark an alert as resolved by the current user."""
    alert: Optional[Alert] = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    if alert.resolved_at:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Alert already resolved")
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = current_user.id
    db.commit()
    return APIResponse(success=True, data={"message": "Alert resolved", "alert_id": alert_id})


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------

@router.get("/risk", response_model=APIResponse)
async def get_risk(current_user: Annotated[User, Depends(get_current_user)]):
    """Return the current dynamic risk score."""
    return APIResponse(success=True, data={"score": get_current_risk(), "timestamp": datetime.utcnow().isoformat()})


# ---------------------------------------------------------------------------
# IAM Analyzer
# ---------------------------------------------------------------------------

# Baseline max-permission sets per role (used by over-permission scanner)
_ROLE_BASELINES: dict[str, set[tuple[str, str]]] = {
    "admin": set(),  # Admins have no restrictions in the baseline
    "power_user": {
        ("s3", "list"), ("s3", "get"), ("s3", "put"),
        ("ec2", "describe"), ("ec2", "start"), ("ec2", "stop"),
        ("lambda", "list"), ("lambda", "invoke"),
    },
    "normal_user": {
        ("s3", "list"), ("s3", "get"),
        ("ec2", "describe"),
        ("lambda", "list"),
    },
    "read_only": {
        ("s3", "list"), ("ec2", "describe"),
        ("lambda", "list"), ("rds", "describe"), ("vpc", "describe"),
    },
    "service_account": {
        ("s3", "list"), ("s3", "get"), ("s3", "put"),
        ("lambda", "list"), ("lambda", "invoke"),
    },
}


@router.get("/analyze/permissions", response_model=APIResponse)
async def analyze_permissions(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """
    Scan all role permissions and flag:
    - Permissions exceeding the role baseline (over-permission)
    - Permissions on resources unused in the last 30 min of simulation activity
    """
    findings: list[AnalyzerFinding] = []
    permissions = db.query(Permission).all()

    # Build set of recently used (resource, action) pairs
    from datetime import timedelta
    since = datetime.utcnow() - timedelta(minutes=30)
    recent_logs = db.query(AuditLog).filter(AuditLog.timestamp >= since).all()
    recently_used: set[tuple[str, str]] = {(log.resource.lower(), log.action.lower()) for log in recent_logs}

    for perm in permissions:
        role = perm.role
        resource = perm.resource.lower()
        action = perm.action.lower()
        baseline = _ROLE_BASELINES.get(role, set())

        # Over-permission: permission exists but not in baseline (skip admin)
        if role != "admin" and baseline and (resource, action) not in baseline and perm.effect == "allow":
            findings.append(AnalyzerFinding(
                role=role,
                resource=perm.resource,
                action=perm.action,
                effect=perm.effect,
                suggestion=f"Permission '{action}' on '{resource}' exceeds baseline for role '{role}'. Consider removing.",
            ))
        # Unused permission
        elif (resource, action) not in recently_used and perm.effect == "allow":
            findings.append(AnalyzerFinding(
                role=role,
                resource=perm.resource,
                action=perm.action,
                effect=perm.effect,
                suggestion=f"Permission '{action}' on '{resource}' for role '{role}' unused in last 30 min. Apply least-privilege.",
            ))

    return APIResponse(
        success=True,
        data=AnalyzerResponse(findings=findings, scanned_at=datetime.utcnow()).model_dump(),
    )
