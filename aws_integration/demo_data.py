"""Demo CSPM data for portfolio-ready AWS dashboards without real credentials."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from aws_integration.scanner import calculate_risk_score
from models import CloudAccount, CSPMFinding, CSPMScan

DEMO_ACCOUNT_ID = "000000000000"
DEMO_ACCOUNT_ARN = "arn:aws:iam::000000000000:role/DemoCSPMReadOnlyRole"
DEMO_ACCOUNT_NAME = "Demo AWS Account"


def _evidence(payload: dict[str, Any]) -> str:
    payload = {"demo": True, **payload}
    return json.dumps(payload, default=str)


def _tags(*tags: str) -> str:
    return json.dumps(list(tags))


DEMO_FINDINGS: list[dict[str, Any]] = [
    {
        "service": "iam", "resource_type": "iam_policy", "resource_id": "arn:aws:iam::000000000000:policy/PortfolioAdminWildcard",
        "title": "IAM policy allows all actions on all resources", "severity": "HIGH",
        "description": "A demo IAM policy grants Action '*' on Resource '*', bypassing least-privilege boundaries.",
        "recommendation": "Replace wildcard permissions with scoped actions and resource ARNs.",
        "evidence": {"policy_name": "PortfolioAdminWildcard", "statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}},
        "tags": ["CIS AWS Foundations", "IAM Least Privilege", "NIST AC-6"],
    },
    {
        "service": "iam", "resource_type": "iam_user", "resource_id": "arn:aws:iam::000000000000:user/demo-analyst",
        "title": "IAM console user has no MFA", "severity": "HIGH",
        "description": "The demo IAM user has console access but no MFA device registered.",
        "recommendation": "Enable MFA for console users or remove console login access.",
        "evidence": {"user_name": "demo-analyst", "console_access": True, "mfa_devices": []},
        "tags": ["CIS AWS Foundations", "NIST IA-2"],
    },
    {
        "service": "iam", "resource_type": "iam_access_key", "resource_id": "AKIADEMOOLDKEY0001",
        "title": "IAM access key is older than 90 days", "severity": "MEDIUM",
        "description": "A demo access key is 143 days old and should be rotated or removed.",
        "recommendation": "Rotate old keys and prefer short-lived role credentials.",
        "evidence": {"access_key_id": "AKIADEMOOLDKEY0001", "age_days": 143, "status": "Active"},
        "tags": ["CIS AWS Foundations", "NIST AC-2"],
    },
    {
        "service": "s3", "resource_type": "s3_bucket", "resource_id": "demo-portfolio-logs-000000000000",
        "title": "S3 default encryption is not enabled", "severity": "MEDIUM",
        "description": "The demo bucket does not define a default server-side encryption rule.",
        "recommendation": "Enable SSE-S3 or SSE-KMS default encryption.",
        "evidence": {"bucket": "demo-portfolio-logs-000000000000", "encryption": None},
        "tags": ["S3 Data Protection", "NIST SC-28"],
    },
    {
        "service": "s3", "resource_type": "s3_bucket", "resource_id": "demo-portfolio-logs-000000000000",
        "title": "S3 bucket versioning is disabled", "severity": "LOW",
        "description": "The demo bucket has versioning disabled, reducing recovery options.",
        "recommendation": "Enable bucket versioning for recovery from accidental deletion or overwrite.",
        "evidence": {"bucket": "demo-portfolio-logs-000000000000", "versioning": {"Status": "Suspended"}},
        "tags": ["S3 Data Protection"],
    },
    {
        "service": "s3", "resource_type": "s3_bucket", "resource_id": "demo-public-policy-example",
        "title": "S3 bucket policy allows public object read", "severity": "HIGH",
        "description": "A demo bucket policy allows Principal '*' to call s3:GetObject.",
        "recommendation": "Remove public principals and use scoped identities or CloudFront Origin Access Control.",
        "evidence": {"bucket": "demo-public-policy-example", "statement": {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::demo-public-policy-example/*"}},
        "tags": ["CIS AWS Foundations", "S3 Public Access"],
    },
    {
        "service": "s3", "resource_type": "s3_bucket", "resource_id": "demo-portfolio-logs-000000000000",
        "title": "S3 server access logging is disabled", "severity": "LOW",
        "description": "The demo bucket does not write server access logs.",
        "recommendation": "Enable S3 server access logging or CloudTrail data events for sensitive buckets.",
        "evidence": {"bucket": "demo-portfolio-logs-000000000000", "logging": {}},
        "tags": ["CIS AWS Foundations", "NIST AU-2"],
    },
    {
        "service": "ec2", "resource_type": "security_group", "resource_id": "sg-demo-open-admin",
        "title": "Security group exposes SSH to the internet", "severity": "HIGH",
        "description": "A demo security group allows TCP/22 from 0.0.0.0/0.",
        "recommendation": "Restrict SSH to VPN, bastion, or approved administrative CIDRs.",
        "evidence": {"group_id": "sg-demo-open-admin", "rule": {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}},
        "tags": ["Network Least Privilege", "NIST SC-7"],
    },
    {
        "service": "ec2", "resource_type": "security_group", "resource_id": "sg-demo-open-admin",
        "title": "Security group exposes RDP to the internet", "severity": "HIGH",
        "description": "A demo security group allows TCP/3389 from 0.0.0.0/0.",
        "recommendation": "Restrict RDP to VPN, bastion, or approved administrative CIDRs.",
        "evidence": {"group_id": "sg-demo-open-admin", "rule": {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "CidrIp": "0.0.0.0/0"}},
        "tags": ["Network Least Privilege", "NIST SC-7"],
    },
    {
        "service": "ec2", "resource_type": "security_group", "resource_id": "sg-demo-open-db",
        "title": "Security group exposes PostgreSQL port 5432 to the internet", "severity": "HIGH",
        "description": "A demo security group allows PostgreSQL from 0.0.0.0/0.",
        "recommendation": "Restrict database access to private CIDRs or application security groups.",
        "evidence": {"group_id": "sg-demo-open-db", "rule": {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "CidrIp": "0.0.0.0/0"}},
        "tags": ["Network Least Privilege", "NIST SC-7"],
    },
    {
        "service": "cloudtrail", "resource_type": "cloudtrail_trail", "resource_id": "arn:aws:cloudtrail:us-east-1:000000000000:trail/demo-management-events",
        "title": "CloudTrail multi-region trail is not enabled", "severity": "HIGH",
        "description": "The demo trail records only one region, leaving other regions with reduced visibility.",
        "recommendation": "Enable multi-region management event logging.",
        "evidence": {"trail": "demo-management-events", "IsMultiRegionTrail": False},
        "tags": ["CIS AWS Foundations", "NIST AU-12"],
    },
    {
        "service": "cloudtrail", "resource_type": "cloudtrail_trail", "resource_id": "arn:aws:cloudtrail:us-east-1:000000000000:trail/demo-management-events",
        "title": "CloudTrail log file validation is disabled", "severity": "MEDIUM",
        "description": "The demo trail does not validate log file integrity.",
        "recommendation": "Enable CloudTrail log file integrity validation.",
        "evidence": {"trail": "demo-management-events", "LogFileValidationEnabled": False},
        "tags": ["CIS AWS Foundations", "NIST AU-9"],
    },
    {
        "service": "cloudtrail", "resource_type": "cloudtrail_event", "resource_id": "ConsoleLogin:demo-admin",
        "title": "ConsoleLogin failures above threshold", "severity": "MEDIUM",
        "description": "Recent demo CloudTrail events show repeated failed console logins.",
        "recommendation": "Investigate repeated login failures and enforce MFA.",
        "evidence": {"username": "demo-admin", "failure_count": 8, "event_name": "ConsoleLogin"},
        "tags": ["Threat Detection", "NIST AU-6"],
    },
    {
        "service": "cloudtrail", "resource_type": "cloudtrail_event", "resource_id": "event-demo-unauthorized",
        "title": "Recent unauthorized AWS API call", "severity": "MEDIUM",
        "description": "A demo CloudTrail event contains UnauthorizedOperation.",
        "recommendation": "Review denied API calls for compromised credentials or missing least-privilege permissions.",
        "evidence": {"event_name": "DescribeInstances", "error_code": "UnauthorizedOperation", "username": "demo-analyst"},
        "tags": ["Threat Detection", "NIST AU-6"],
    },
    {
        "service": "cloudtrail", "resource_type": "cloudtrail_event", "resource_id": "event-demo-root",
        "title": "Recent root account usage detected", "severity": "HIGH",
        "description": "A demo CloudTrail event shows root account activity.",
        "recommendation": "Avoid root account usage except break-glass tasks and ensure root MFA is enabled.",
        "evidence": {"event_name": "GetAccountSummary", "user_identity": {"type": "Root"}},
        "tags": ["CIS AWS Foundations", "NIST AC-2"],
    },
]


def load_demo_cspm_data(db: Session, region: str = "us-east-1") -> tuple[CSPMScan, list[CSPMFinding], dict[str, Any]]:
    """Insert a completed demo CSPM scan with realistic sample findings."""
    account = (
        db.query(CloudAccount)
        .filter(CloudAccount.account_id == DEMO_ACCOUNT_ID, CloudAccount.region == region)
        .first()
    )
    if account is None:
        account = CloudAccount(
            account_id=DEMO_ACCOUNT_ID,
            arn=DEMO_ACCOUNT_ARN,
            region=region,
            name=DEMO_ACCOUNT_NAME,
            created_at=datetime.utcnow(),
            last_validated_at=datetime.utcnow(),
        )
        db.add(account)
        db.flush()

    scan = CSPMScan(
        cloud_account_id=account.id,
        scan_type="demo",
        status="completed",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
    )
    db.add(scan)
    db.flush()

    findings: list[CSPMFinding] = []
    for item in DEMO_FINDINGS:
        finding = CSPMFinding(
            scan_id=scan.id,
            cloud_account_id=account.id,
            provider="aws",
            service=item["service"],
            resource_type=item["resource_type"],
            resource_id=item["resource_id"],
            title=item["title"],
            description=item["description"],
            severity=item["severity"],
            recommendation=item["recommendation"],
            evidence_json=_evidence(item["evidence"]),
            compliance_tags_json=_tags(*item["tags"]),
            status="open",
            created_at=datetime.utcnow(),
        )
        db.add(finding)
        findings.append(finding)

    scan.finding_count = len(findings)
    scan.high_count = sum(1 for f in findings if f.severity == "HIGH")
    scan.medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
    scan.low_count = sum(1 for f in findings if f.severity == "LOW")
    db.commit()
    db.refresh(scan)
    for finding in findings:
        db.refresh(finding)
    risk = calculate_risk_score(db.query(CSPMFinding).all())
    return scan, findings, risk


def clear_demo_cspm_data(db: Session) -> dict[str, int]:
    """Delete only demo CSPM rows identified by account metadata or evidence marker."""
    demo_findings = []
    for finding in db.query(CSPMFinding).all():
        try:
            if json.loads(finding.evidence_json or "{}").get("demo") is True:
                demo_findings.append(finding)
        except json.JSONDecodeError:
            continue

    scan_ids = {finding.scan_id for finding in demo_findings}
    finding_count = len(demo_findings)
    for finding in demo_findings:
        db.delete(finding)

    demo_scans = db.query(CSPMScan).filter(CSPMScan.scan_type == "demo").all()
    for scan in demo_scans:
        scan_ids.add(scan.id)
    scan_count = 0
    for scan in db.query(CSPMScan).filter(CSPMScan.id.in_(scan_ids)).all() if scan_ids else []:
        db.delete(scan)
        scan_count += 1

    demo_accounts = db.query(CloudAccount).filter(CloudAccount.account_id == DEMO_ACCOUNT_ID).all()
    account_count = 0
    for account in demo_accounts:
        remaining_scans = db.query(CSPMScan).filter(CSPMScan.cloud_account_id == account.id).count()
        remaining_findings = db.query(CSPMFinding).filter(CSPMFinding.cloud_account_id == account.id).count()
        if remaining_scans == 0 and remaining_findings == 0:
            db.delete(account)
            account_count += 1

    db.commit()
    return {"findings_deleted": finding_count, "scans_deleted": scan_count, "accounts_deleted": account_count}
