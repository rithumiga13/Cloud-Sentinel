"""Read-only AWS S3 bucket permission and configuration scanner."""

from __future__ import annotations

from typing import Any

from aws_integration.client import ClientError, get_client
from aws_integration.iam_scanner import _as_list, _matches_action
from aws_integration.schemas import NormalizedFinding, Severity

S3_TAGS = ["CIS AWS Foundations", "S3 Data Protection", "NIST AC"]
PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def _is_public_principal(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(v == "*" or "*" in _as_list(v) for v in principal.values())
    return False


def analyze_bucket_policy(policy: dict[str, Any], bucket_name: str) -> list[NormalizedFinding]:
    """Detect public S3 read/write access in a bucket policy document."""
    findings: list[NormalizedFinding] = []
    for stmt in _as_list(policy.get("Statement")):
        if str(stmt.get("Effect", "")).lower() != "allow" or not _is_public_principal(stmt.get("Principal")):
            continue
        evidence = {"bucket": bucket_name, "statement": stmt}
        if _matches_action(stmt.get("Action"), "s3:GetObject"):
            findings.append(_finding(bucket_name, "S3 bucket policy allows public object read", Severity.high, "Restrict Principal '*' object read access or use CloudFront Origin Access Control.", evidence))
        if _matches_action(stmt.get("Action"), "s3:PutObject"):
            findings.append(_finding(bucket_name, "S3 bucket policy allows public object write", Severity.high, "Remove public write grants and require authenticated, scoped principals.", evidence))
    return findings


def _finding(bucket_name: str, title: str, severity: Severity, recommendation: str, evidence: dict[str, Any]) -> NormalizedFinding:
    return NormalizedFinding(
        service="s3", resource_type="s3_bucket", resource_id=bucket_name,
        title=title, description=f"Bucket {bucket_name}: {title}.", severity=severity,
        recommendation=recommendation, evidence=evidence, compliance_tags=S3_TAGS,
    )


def _get_optional(callable_obj, missing_codes: set[str]) -> Any:
    try:
        return callable_obj()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in missing_codes:
            return None
        raise


def scan_s3(region: str | None = None, s3_client: Any = None) -> list[NormalizedFinding]:
    """Scan S3 buckets for public access and missing data protection controls."""
    s3 = s3_client or get_client("s3", region)
    findings: list[NormalizedFinding] = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        acl = s3.get_bucket_acl(Bucket=name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI")
            permission = grant.get("Permission")
            if uri in PUBLIC_GRANTEES and permission in {"READ", "FULL_CONTROL"}:
                findings.append(_finding(name, "S3 bucket is publicly readable through ACL", Severity.high, "Remove public ACL read grants and enable bucket-owner-enforced object ownership.", {"grant": grant}))
            if uri in PUBLIC_GRANTEES and permission in {"WRITE", "WRITE_ACP", "FULL_CONTROL"}:
                findings.append(_finding(name, "S3 bucket is publicly writable through ACL", Severity.high, "Remove public ACL write grants immediately.", {"grant": grant}))

        policy_resp = _get_optional(lambda: s3.get_bucket_policy(Bucket=name), {"NoSuchBucketPolicy", "NoSuchPolicy"})
        if policy_resp and policy_resp.get("Policy"):
            import json
            findings.extend(analyze_bucket_policy(json.loads(policy_resp["Policy"]), name))

        pab = _get_optional(lambda: s3.get_public_access_block(Bucket=name), {"NoSuchPublicAccessBlockConfiguration"})
        pab_config = (pab or {}).get("PublicAccessBlockConfiguration", {})
        required = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
        if not pab_config or not all(pab_config.get(k) for k in required):
            findings.append(_finding(name, "S3 public access block is missing or partially disabled", Severity.medium, "Enable all four S3 Block Public Access settings.", {"public_access_block": pab_config}))

        encryption = _get_optional(lambda: s3.get_bucket_encryption(Bucket=name), {"ServerSideEncryptionConfigurationNotFoundError"})
        if not encryption:
            findings.append(_finding(name, "S3 default encryption is not enabled", Severity.medium, "Enable default server-side encryption with SSE-S3 or SSE-KMS.", {}))

        versioning = s3.get_bucket_versioning(Bucket=name)
        if versioning.get("Status") != "Enabled":
            findings.append(_finding(name, "S3 bucket versioning is disabled", Severity.low, "Enable bucket versioning to improve recovery from deletion or overwrite events.", {"versioning": versioning}))

        logging = s3.get_bucket_logging(Bucket=name)
        if "LoggingEnabled" not in logging:
            findings.append(_finding(name, "S3 server access logging is disabled", Severity.low, "Enable S3 server access logging or CloudTrail data events for sensitive buckets.", {"logging": logging}))
    return findings
