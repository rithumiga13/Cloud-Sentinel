from datetime import datetime, timezone

from aws_integration.cloudtrail_scanner import analyze_events
from aws_integration.ec2_scanner import analyze_security_group
from aws_integration.iam_scanner import analyze_policy_document
from aws_integration.s3_scanner import analyze_bucket_policy
from aws_integration.scanner import calculate_risk_score
from aws_integration.schemas import Severity


def test_iam_policy_wildcard_detection():
    findings = analyze_policy_document(
        {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        "arn:aws:iam::123:user/alice",
        "iam_user",
        "InlineAdmin",
    )
    assert any(f.severity == Severity.high and "all actions" in f.title for f in findings)


def test_s3_public_policy_detection():
    findings = analyze_bucket_policy(
        {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::demo/*"}]},
        "demo",
    )
    assert any(f.service == "s3" and f.severity == Severity.high for f in findings)


def test_ec2_public_ssh_and_rdp_detection():
    findings = analyze_security_group({
        "GroupId": "sg-123",
        "GroupName": "web",
        "Description": "web access",
        "IpPermissions": [{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [],
        }],
        "IpPermissionsEgress": [],
    })
    titles = {f.title for f in findings}
    assert "Security group exposes SSH to the internet" in titles
    assert "Security group exposes RDP to the internet" in titles


def test_cloudtrail_event_threat_detection():
    findings = analyze_events([
        {
            "EventId": "e1",
            "EventName": "AttachUserPolicy",
            "Username": "root",
            "EventTime": datetime.now(timezone.utc),
            "CloudTrailEvent": '{"userIdentity":{"type":"Root"}}',
        },
        {
            "EventId": "e2",
            "EventName": "DescribeInstances",
            "Username": "bob",
            "ErrorCode": "UnauthorizedOperation",
        },
    ])
    titles = {f.title for f in findings}
    assert "Recent root account usage detected" in titles
    assert "Recent IAM policy change detected" in titles
    assert "Recent unauthorized AWS API call" in titles


def test_risk_score_calculation():
    class Finding:
        def __init__(self, severity, service, resource_id, status="open"):
            self.severity = severity
            self.service = service
            self.resource_id = resource_id
            self.status = status

    risk = calculate_risk_score([
        Finding("HIGH", "iam", "u1"),
        Finding("MEDIUM", "s3", "b1"),
        Finding("LOW", "ec2", "sg1"),
        Finding("HIGH", "iam", "u2", "resolved"),
    ])
    assert risk["total_score"] == 33
    assert risk["normalized_score"] == 33
    assert risk["counts_by_severity"]["HIGH"] == 1
    assert risk["top_risky_services"][0]["service"] == "iam"
