"""Read-only AWS CloudTrail configuration and event threat scanner."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from aws_integration.client import ClientError, get_client
from aws_integration.schemas import NormalizedFinding, Severity

CT_TAGS = ["CIS AWS Foundations", "CloudTrail Monitoring", "NIST AU"]
IAM_POLICY_EVENTS = {"CreatePolicy", "DeletePolicy", "CreatePolicyVersion", "DeletePolicyVersion", "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy"}
SG_CHANGE_EVENTS = {"AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupEgress", "CreateSecurityGroup", "DeleteSecurityGroup"}


def analyze_events(events: list[dict[str, Any]], console_failure_threshold: int = 5) -> list[NormalizedFinding]:
    """Detect recent suspicious CloudTrail events from LookupEvents output."""
    findings: list[NormalizedFinding] = []
    failures: Counter[str] = Counter()
    for event in events:
        name = event.get("EventName", "")
        username = event.get("Username") or "unknown"
        cloud_event = event.get("CloudTrailEvent")
        parsed = {}
        if isinstance(cloud_event, str):
            import json
            try:
                parsed = json.loads(cloud_event)
            except json.JSONDecodeError:
                parsed = {}
        error_code = event.get("ErrorCode") or parsed.get("errorCode")
        if name == "ConsoleLogin" and (parsed.get("responseElements", {}).get("ConsoleLogin") == "Failure" or error_code):
            failures[username] += 1
        if error_code in {"AccessDenied", "UnauthorizedOperation", "Client.UnauthorizedOperation"} or "Unauthorized" in str(error_code):
            findings.append(_finding("cloudtrail_event", event.get("EventId", name), "Recent unauthorized AWS API call", Severity.medium, "Investigate denied API calls for compromised credentials or missing least-privilege policies.", {"event": event}))
        if username == "root" or parsed.get("userIdentity", {}).get("type") == "Root":
            findings.append(_finding("cloudtrail_event", event.get("EventId", name), "Recent root account usage detected", Severity.high, "Avoid root account usage except for break-glass tasks and ensure MFA is enabled.", {"event": event}))
        if name in IAM_POLICY_EVENTS:
            findings.append(_finding("cloudtrail_event", event.get("EventId", name), "Recent IAM policy change detected", Severity.medium, "Review IAM policy changes for approval and least privilege.", {"event": event}))
        if name in SG_CHANGE_EVENTS:
            findings.append(_finding("cloudtrail_event", event.get("EventId", name), "Recent security group change detected", Severity.medium, "Review security group changes for exposed ingress or overly broad egress.", {"event": event}))
    for username, count in failures.items():
        if count >= console_failure_threshold:
            findings.append(_finding("cloudtrail_event", f"ConsoleLogin:{username}", "ConsoleLogin failures above threshold", Severity.medium, "Investigate repeated console login failures and enforce MFA.", {"username": username, "failure_count": count}))
    return findings


def _finding(resource_type: str, resource_id: str, title: str, severity: Severity, recommendation: str, evidence: dict[str, Any]) -> NormalizedFinding:
    return NormalizedFinding(
        service="cloudtrail", resource_type=resource_type, resource_id=resource_id,
        title=title, description=f"CloudTrail: {title}.", severity=severity,
        recommendation=recommendation, evidence=evidence, compliance_tags=CT_TAGS,
    )


def scan_cloudtrail(region: str | None = None, cloudtrail_client: Any = None, s3_client: Any = None) -> list[NormalizedFinding]:
    """Scan CloudTrail trails, status, and recent management events."""
    ct = cloudtrail_client or get_client("cloudtrail", region)
    findings: list[NormalizedFinding] = []
    trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    if not trails:
        findings.append(_finding("account", "cloudtrail", "No CloudTrail trail configured", Severity.high, "Create an organization or account trail that logs management events.", {}))
    for trail in trails:
        arn = trail.get("TrailARN") or trail.get("Name", "cloudtrail")
        if not trail.get("IsMultiRegionTrail"):
            findings.append(_finding("cloudtrail_trail", arn, "CloudTrail multi-region trail is not enabled", Severity.high, "Enable multi-region logging for management events.", {"trail": trail}))
        if not trail.get("LogFileValidationEnabled"):
            findings.append(_finding("cloudtrail_trail", arn, "CloudTrail log file validation is disabled", Severity.medium, "Enable log file integrity validation.", {"trail": trail}))
        try:
            status = ct.get_trail_status(Name=trail.get("TrailARN") or trail.get("Name"))
            if not status.get("IsLogging"):
                findings.append(_finding("cloudtrail_trail", arn, "CloudTrail trail is not logging", Severity.high, "Start logging for the trail and investigate why logging stopped.", {"trail": trail, "status": status}))
        except ClientError as exc:
            findings.append(_finding("cloudtrail_trail", arn, "CloudTrail trail status could not be read", Severity.low, "Verify permissions and trail configuration.", {"trail": trail, "error": str(exc)}))

    start = datetime.now(timezone.utc) - timedelta(days=7)
    try:
        paginator = ct.get_paginator("lookup_events")
        events: list[dict[str, Any]] = []
        for page in paginator.paginate(StartTime=start, EndTime=datetime.now(timezone.utc), PaginationConfig={"MaxItems": 200}):
            events.extend(page.get("Events", []))
        findings.extend(analyze_events(events))
    except ClientError as exc:
        findings.append(_finding("cloudtrail_event", "lookup-events", "CloudTrail recent events could not be queried", Severity.low, "Ensure cloudtrail:LookupEvents is allowed for the scanner role.", {"error": str(exc)}))
    return findings
