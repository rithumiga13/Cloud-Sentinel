"""CSPM scan orchestration, persistence, and risk scoring."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from aws_integration.client import AWSIdentity, validate_identity
from aws_integration.cloudtrail_scanner import scan_cloudtrail
from aws_integration.ec2_scanner import scan_ec2
from aws_integration.iam_scanner import scan_iam
from aws_integration.s3_scanner import scan_s3
from aws_integration.schemas import NormalizedFinding, ScanType
from models import CloudAccount, CSPMFinding, CSPMScan

SEVERITY_POINTS = {"HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 1}


def get_or_create_cloud_account(db: Session, identity: AWSIdentity, name: str | None = None) -> CloudAccount:
    """Persist validated AWS account metadata without storing credentials."""
    account = (
        db.query(CloudAccount)
        .filter(CloudAccount.account_id == identity.account_id, CloudAccount.region == identity.region)
        .first()
    )
    if account is None:
        account = CloudAccount(account_id=identity.account_id, arn=identity.arn, region=identity.region, name=name)
        db.add(account)
    account.arn = identity.arn
    account.last_validated_at = datetime.utcnow()
    db.commit()
    db.refresh(account)
    return account


def calculate_risk_score(findings: list[Any]) -> dict[str, Any]:
    """Calculate CSPM risk score from open findings."""
    counts = Counter()
    service_points: defaultdict[str, int] = defaultdict(int)
    resource_points: defaultdict[str, int] = defaultdict(int)
    total = 0
    for finding in findings:
        status = getattr(finding, "status", "open")
        if status != "open":
            continue
        severity = str(getattr(finding, "severity", "")).upper()
        points = SEVERITY_POINTS.get(severity, 0)
        total += points
        counts[severity] += 1
        service_points[getattr(finding, "service", "unknown")] += points
        resource_points[getattr(finding, "resource_id", "unknown")] += points
    return {
        "total_score": total,
        "normalized_score": min(100, total),
        "counts_by_severity": {k: counts.get(k, 0) for k in ("HIGH", "MEDIUM", "LOW", "INFO")},
        "top_risky_services": sorted(
            [{"service": k, "score": v} for k, v in service_points.items()],
            key=lambda i: i["score"],
            reverse=True,
        )[:5],
        "top_risky_resources": sorted(
            [{"resource_id": k, "score": v} for k, v in resource_points.items()],
            key=lambda i: i["score"],
            reverse=True,
        )[:10],
    }


def _scan(scan_type: ScanType, region: str) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    if scan_type in {ScanType.full, ScanType.iam}:
        findings.extend(scan_iam(region))
    if scan_type in {ScanType.full, ScanType.s3}:
        findings.extend(scan_s3(region))
    if scan_type in {ScanType.full, ScanType.ec2}:
        findings.extend(scan_ec2(region))
    if scan_type in {ScanType.full, ScanType.cloudtrail}:
        findings.extend(scan_cloudtrail(region))
    return findings


def run_cspm_scan(db: Session, scan_type: ScanType, region: str | None = None) -> tuple[CSPMScan, list[CSPMFinding], dict[str, Any]]:
    """Run a synchronous read-only AWS scan, save findings, and return summary data."""
    identity = validate_identity(region)
    account = get_or_create_cloud_account(db, identity)
    scan = CSPMScan(cloud_account_id=account.id, scan_type=scan_type.value, status="running", started_at=datetime.utcnow())
    db.add(scan)
    db.commit()
    db.refresh(scan)
    try:
        normalized = _scan(scan_type, identity.region)
        persisted: list[CSPMFinding] = []
        for item in normalized:
            finding = CSPMFinding(
                scan_id=scan.id,
                cloud_account_id=account.id,
                provider=item.provider,
                service=item.service,
                resource_type=item.resource_type,
                resource_id=item.resource_id,
                title=item.title,
                description=item.description,
                severity=item.severity.value,
                recommendation=item.recommendation,
                evidence_json=json.dumps(item.evidence, default=str),
                compliance_tags_json=json.dumps(item.compliance_tags),
                status="open",
            )
            db.add(finding)
            persisted.append(finding)
        scan.finding_count = len(persisted)
        scan.high_count = sum(1 for f in persisted if f.severity == "HIGH")
        scan.medium_count = sum(1 for f in persisted if f.severity == "MEDIUM")
        scan.low_count = sum(1 for f in persisted if f.severity == "LOW")
        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()
        for finding in persisted:
            db.refresh(finding)
        risk = calculate_risk_score(db.query(CSPMFinding).filter(CSPMFinding.status == "open").all())
        return scan, persisted, risk
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.utcnow()
        scan.error_message = str(exc)
        db.commit()
        raise
