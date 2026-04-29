"""AWS identity and CSPM API routes."""

from __future__ import annotations

import csv
import io
import json
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.orm import Session

from audit.service import write_audit_log
from auth.dependencies import get_current_user, require_role
from aws_integration.client import AWSIntegrationError, validate_identity
from aws_integration.scanner import calculate_risk_score, get_or_create_cloud_account, run_cspm_scan
from aws_integration.schemas import (
    AccountIdentity,
    CSPMFindingOut,
    CSPMScanOut,
    FindingStatusUpdate,
    ScanRequest,
)
from database import get_db
from models import CSPMFinding, CSPMScan, RoleEnum, User
from schemas import APIResponse
from websocket.manager import manager

router = APIRouter(tags=["AWS CSPM"])
scan_dep = require_role(RoleEnum.admin, RoleEnum.power_user)
status_dep = require_role(RoleEnum.admin, RoleEnum.power_user)


@router.get("/aws/identity", response_model=APIResponse)
async def aws_identity(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    region: Optional[str] = Query(None),
):
    """Validate AWS credentials with STS and return account metadata."""
    try:
        identity = validate_identity(region)
        get_or_create_cloud_account(db, identity)
        write_audit_log(db, current_user.id, "aws_identity_validation", "aws", "safe", details=f"account={identity.account_id}, region={identity.region}")
        return APIResponse(success=True, data=AccountIdentity(
            account_id=identity.account_id,
            arn=identity.arn,
            user_id=identity.user_id,
            region=identity.region,
        ).model_dump())
    except AWSIntegrationError as exc:
        write_audit_log(db, current_user.id, "aws_identity_validation", "aws", "blocked", details=str(exc))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/cspm/scan", response_model=APIResponse)
async def start_scan(
    body: ScanRequest,
    current_user: Annotated[User, Depends(scan_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Run a synchronous read-only AWS CSPM scan."""
    await manager.broadcast_cspm("cspm_scan_started", {"scan_type": body.scan_type.value, "region": body.region})
    write_audit_log(db, current_user.id, "cspm_scan_started", "cspm", "safe", details=f"scan_type={body.scan_type.value}, region={body.region or 'default'}")
    try:
        scan, findings, risk = run_cspm_scan(db, body.scan_type, body.region)
        for finding in findings:
            await manager.broadcast_cspm("cspm_finding_created", {"id": finding.id, "severity": finding.severity, "service": finding.service, "title": finding.title})
        await manager.broadcast_cspm("cspm_scan_completed", {"scan_id": scan.id, "finding_count": scan.finding_count})
        await manager.broadcast_cspm("cspm_risk_updated", risk)
        await manager.broadcast_risk(risk["normalized_score"])
        write_audit_log(db, current_user.id, "cspm_scan_completed", "cspm", "safe", risk_delta=risk["normalized_score"], details=f"scan_id={scan.id}, findings={scan.finding_count}")
        return APIResponse(success=True, data={
            "scan": CSPMScanOut.model_validate(scan).model_dump(),
            "risk_score": risk,
            "finding_count": len(findings),
        })
    except Exception as exc:
        write_audit_log(db, current_user.id, "cspm_scan_failed", "cspm", "blocked", details=str(exc))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get("/cspm/scans", response_model=APIResponse)
async def list_scans(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """List previous CSPM scans."""
    scans = db.query(CSPMScan).order_by(CSPMScan.started_at.desc()).limit(100).all()
    return APIResponse(success=True, data=[CSPMScanOut.model_validate(scan).model_dump() for scan in scans])


@router.get("/cspm/scans/{scan_id}", response_model=APIResponse)
async def get_scan(
    scan_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """Return scan metadata and findings."""
    scan = db.query(CSPMScan).filter(CSPMScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    findings = db.query(CSPMFinding).filter(CSPMFinding.scan_id == scan_id).order_by(CSPMFinding.created_at.desc()).all()
    return APIResponse(success=True, data={
        "scan": CSPMScanOut.model_validate(scan).model_dump(),
        "findings": [CSPMFindingOut.model_validate(f).model_dump() for f in findings],
    })


@router.get("/cspm/findings", response_model=APIResponse)
async def list_findings(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    severity: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    resource_type: Optional[str] = Query(None),
):
    """List CSPM findings with optional filters."""
    q = db.query(CSPMFinding)
    if severity:
        q = q.filter(CSPMFinding.severity == severity.upper())
    if service:
        q = q.filter(CSPMFinding.service == service.lower())
    if status_filter:
        q = q.filter(CSPMFinding.status == status_filter.lower())
    if resource_type:
        q = q.filter(CSPMFinding.resource_type == resource_type)
    findings = q.order_by(CSPMFinding.created_at.desc()).limit(500).all()
    return APIResponse(success=True, data=[CSPMFindingOut.model_validate(f).model_dump() for f in findings])


@router.post("/cspm/findings/{finding_id}/status", response_model=APIResponse)
async def update_finding_status(
    finding_id: int,
    body: FindingStatusUpdate,
    current_user: Annotated[User, Depends(status_dep)],
    db: Annotated[Session, Depends(get_db)],
):
    """Mark a finding open, resolved, or ignored."""
    finding = db.query(CSPMFinding).filter(CSPMFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    finding.status = body.status.value
    db.commit()
    db.refresh(finding)
    risk = calculate_risk_score(db.query(CSPMFinding).all())
    await manager.broadcast_cspm("cspm_risk_updated", risk)
    await manager.broadcast_risk(risk["normalized_score"])
    write_audit_log(db, current_user.id, "cspm_finding_status_changed", "cspm", "safe", details=f"finding_id={finding_id}, status={finding.status}")
    return APIResponse(success=True, data={"finding": CSPMFindingOut.model_validate(finding).model_dump(), "risk_score": risk})


@router.get("/cspm/risk", response_model=APIResponse)
async def get_cspm_risk(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """Return current CSPM risk score based on open findings."""
    return APIResponse(success=True, data=calculate_risk_score(db.query(CSPMFinding).all()))


@router.get("/cspm/report")
async def export_cspm_report(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    format: str = Query("json", pattern="^(csv|json)$"),
):
    """Export CSPM findings as JSON or CSV."""
    findings = db.query(CSPMFinding).order_by(CSPMFinding.created_at.desc()).all()
    write_audit_log(db, current_user.id, "cspm_report_exported", "cspm", "safe", details=f"format={format}, findings={len(findings)}")
    rows = [CSPMFindingOut.model_validate(f).model_dump() for f in findings]
    if format == "csv":
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=list(rows[0].keys()) if rows else ["id"])
        writer.writeheader()
        writer.writerows(rows)
        return PlainTextResponse(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=cspm_findings.csv"})
    return JSONResponse(content={"success": True, "data": json.loads(json.dumps(rows, default=str))}, headers={"Content-Disposition": "attachment; filename=cspm_findings.json"})
