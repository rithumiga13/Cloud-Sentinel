"""Read-only AWS EC2 security group scanner."""

from __future__ import annotations

from typing import Any

from aws_integration.client import get_client
from aws_integration.schemas import NormalizedFinding, Severity

EC2_TAGS = ["CIS AWS Foundations", "Network Least Privilege", "NIST SC"]
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 27017: "MongoDB"}


def _internet_ranges(rule: dict[str, Any]) -> list[str]:
    ranges = [r.get("CidrIp") for r in rule.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
    ranges.extend(r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0")
    return [r for r in ranges if r]


def _port_in_rule(rule: dict[str, Any], port: int) -> bool:
    if rule.get("IpProtocol") in {"-1", "all"}:
        return True
    if rule.get("IpProtocol") != "tcp":
        return False
    return int(rule.get("FromPort", -1)) <= port <= int(rule.get("ToPort", -1))


def analyze_security_group(group: dict[str, Any]) -> list[NormalizedFinding]:
    """Detect public ingress and broad egress in one EC2 security group."""
    findings: list[NormalizedFinding] = []
    group_id = group.get("GroupId", group.get("GroupName", "unknown"))
    for rule in group.get("IpPermissions", []):
        public = _internet_ranges(rule)
        if not public:
            continue
        evidence = {"group_id": group_id, "rule": rule, "public_ranges": public}
        if rule.get("IpProtocol") == "-1":
            findings.append(_finding(group_id, "Security group allows all inbound traffic from the internet", Severity.high, "Restrict inbound access to required ports and trusted CIDR ranges.", evidence))
        if rule.get("IpProtocol") == "tcp" and int(rule.get("FromPort", -1)) == 0 and int(rule.get("ToPort", -1)) == 65535:
            findings.append(_finding(group_id, "Security group allows all TCP ports from the internet", Severity.high, "Limit inbound TCP ports to explicit business requirements.", evidence))
        if _port_in_rule(rule, 22):
            findings.append(_finding(group_id, "Security group exposes SSH to the internet", Severity.high, "Restrict SSH to a VPN, bastion, or approved admin CIDR.", evidence))
        if _port_in_rule(rule, 3389):
            findings.append(_finding(group_id, "Security group exposes RDP to the internet", Severity.high, "Restrict RDP to a VPN, bastion, or approved admin CIDR.", evidence))
        for port, name in DB_PORTS.items():
            if _port_in_rule(rule, port):
                findings.append(_finding(group_id, f"Security group exposes {name} port {port} to the internet", Severity.high, "Restrict database access to application security groups or private CIDRs.", evidence))

    for rule in group.get("IpPermissionsEgress", []):
        public = _internet_ranges(rule)
        if public and rule.get("IpProtocol") == "-1":
            findings.append(_finding(group_id, "Security group allows all outbound traffic to the internet", Severity.medium, "Restrict outbound traffic to required destinations where feasible.", {"group_id": group_id, "rule": rule, "public_ranges": public}))

    description = (group.get("Description") or "").strip().lower()
    name = (group.get("GroupName") or "").strip().lower()
    if not description or description in {"default", "security group", "sg"} or name in {"default", "test", "temp"}:
        findings.append(_finding(group_id, "Security group metadata is weak or missing", Severity.low, "Use descriptive security group names and descriptions that identify owner and purpose.", {"group_id": group_id, "group_name": group.get("GroupName"), "description": group.get("Description")}))
    return findings


def _finding(group_id: str, title: str, severity: Severity, recommendation: str, evidence: dict[str, Any]) -> NormalizedFinding:
    return NormalizedFinding(
        service="ec2", resource_type="security_group", resource_id=group_id,
        title=title, description=f"{group_id}: {title}.", severity=severity,
        recommendation=recommendation, evidence=evidence, compliance_tags=EC2_TAGS,
    )


def scan_ec2(region: str | None = None, ec2_client: Any = None) -> list[NormalizedFinding]:
    """Scan EC2 security groups in the selected region."""
    ec2 = ec2_client or get_client("ec2", region)
    findings: list[NormalizedFinding] = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for group in page.get("SecurityGroups", []):
            findings.extend(analyze_security_group(group))
    return findings
