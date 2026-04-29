"""Read-only AWS IAM policy and identity posture scanner."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable

from aws_integration.client import ClientError, get_client
from aws_integration.schemas import NormalizedFinding, Severity

IAM_TAGS = ["CIS AWS Foundations", "IAM Least Privilege", "NIST AC"]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _matches_action(actions: Any, wanted: str) -> bool:
    wanted = wanted.lower()
    for action in _as_list(actions):
        a = str(action).lower()
        if a == "*" or a == wanted or (a.endswith("*") and wanted.startswith(a[:-1])):
            return True
    return False


def _principal_is_public(principal: Any) -> bool:
    return principal == "*" or (isinstance(principal, dict) and any(v == "*" or "*" in _as_list(v) for v in principal.values()))


def analyze_policy_document(
    policy: dict[str, Any],
    resource_id: str,
    resource_type: str,
    policy_name: str,
) -> list[NormalizedFinding]:
    """Detect broad IAM permissions in an IAM policy document."""
    findings: list[NormalizedFinding] = []
    for statement in _as_list(policy.get("Statement")):
        if str(statement.get("Effect", "")).lower() != "allow":
            continue
        actions = statement.get("Action") or statement.get("NotAction")
        resources = statement.get("Resource", "*")
        resource_star = "*" in [str(r) for r in _as_list(resources)]
        evidence = {"policy_name": policy_name, "statement": statement}
        if _matches_action(actions, "*") and resource_star:
            findings.append(NormalizedFinding(
                service="iam", resource_type=resource_type, resource_id=resource_id,
                title="IAM policy allows all actions on all resources",
                description=f"{policy_name} grants Action '*' on Resource '*'.",
                severity=Severity.high,
                recommendation="Replace wildcard admin-style grants with least-privilege actions and scoped resources.",
                evidence=evidence, compliance_tags=IAM_TAGS,
            ))
        if _matches_action(actions, "iam:CreateUser") or _matches_action(actions, "iam:*"):
            findings.append(NormalizedFinding(
                service="iam", resource_type=resource_type, resource_id=resource_id,
                title="IAM policy grants broad IAM administration",
                description=f"{policy_name} allows broad IAM privileges.",
                severity=Severity.high,
                recommendation="Restrict IAM administrative permissions to dedicated break-glass roles with MFA.",
                evidence=evidence, compliance_tags=IAM_TAGS,
            ))
        if _matches_action(actions, "sts:AssumeRole") and resource_star:
            findings.append(NormalizedFinding(
                service="iam", resource_type=resource_type, resource_id=resource_id,
                title="IAM policy allows broad role assumption",
                description=f"{policy_name} allows sts:AssumeRole against Resource '*'.",
                severity=Severity.medium,
                recommendation="Scope sts:AssumeRole to approved role ARNs and add external ID or MFA conditions where appropriate.",
                evidence=evidence, compliance_tags=IAM_TAGS,
            ))
    return findings


def _finding(resource_type: str, resource_id: str, title: str, description: str, severity: Severity, recommendation: str, evidence: dict[str, Any]) -> NormalizedFinding:
    return NormalizedFinding(
        service="iam", resource_type=resource_type, resource_id=resource_id,
        title=title, description=description, severity=severity,
        recommendation=recommendation, evidence=evidence, compliance_tags=IAM_TAGS,
    )


def _paginate(client: Any, operation: str, result_key: str, **kwargs) -> Iterable[dict[str, Any]]:
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        yield from page.get(result_key, [])


def scan_iam(region: str | None = None, iam_client: Any = None) -> list[NormalizedFinding]:
    """Scan IAM users, roles, policies, password policy, MFA, and access keys."""
    iam = iam_client or get_client("iam", region)
    findings: list[NormalizedFinding] = []
    now = datetime.now(timezone.utc)

    try:
        password_policy = iam.get_account_password_policy()["PasswordPolicy"]
        checks = [
            ("RequireSymbols", "Password policy does not require symbols"),
            ("RequireNumbers", "Password policy does not require numbers"),
            ("RequireUppercaseCharacters", "Password policy does not require uppercase characters"),
        ]
        for key, title in checks:
            if not password_policy.get(key):
                findings.append(_finding("account", "account-password-policy", title, title, Severity.medium, "Strengthen the account password policy.", {"password_policy": password_policy}))
        if int(password_policy.get("MinimumPasswordLength", 0)) < 12:
            findings.append(_finding("account", "account-password-policy", "Password minimum length is under 12", "The AWS account password policy minimum length is below 12.", Severity.medium, "Set minimum password length to at least 12 characters.", {"password_policy": password_policy}))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            findings.append(_finding("account", "account-password-policy", "Missing account password policy", "The AWS account does not have an IAM account password policy.", Severity.high, "Create an account password policy requiring MFA-friendly strong passwords.", {"error_code": "NoSuchEntity"}))
        else:
            raise

    for user in _paginate(iam, "list_users", "Users"):
        user_name = user["UserName"]
        user_id = user.get("Arn", user_name)
        mfa_devices = iam.list_mfa_devices(UserName=user_name).get("MFADevices", [])
        try:
            iam.get_login_profile(UserName=user_name)
            has_console_password = True
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
            has_console_password = False
        if has_console_password and not mfa_devices:
            findings.append(_finding("iam_user", user_id, "IAM console user has no MFA", f"IAM user {user_name} has console access without MFA.", Severity.high, "Enable MFA or remove console access for this IAM user.", {"user_name": user_name, "mfa_devices": []}))

        for key in iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
            key_id = key["AccessKeyId"]
            age_days = (now - key["CreateDate"]).days
            usage = iam.get_access_key_last_used(AccessKeyId=key_id).get("AccessKeyLastUsed", {})
            if age_days > 90:
                findings.append(_finding("iam_access_key", key_id, "IAM access key is older than 90 days", f"Access key for {user_name} is {age_days} days old.", Severity.medium, "Rotate or remove long-lived access keys.", {"user_name": user_name, "age_days": age_days, "status": key.get("Status")}))
            if key.get("Status") == "Active" and "LastUsedDate" not in usage:
                findings.append(_finding("iam_access_key", key_id, "Active IAM access key has no recent usage", f"Active access key for {user_name} has no recorded last-used timestamp.", Severity.medium, "Disable unused access keys and prefer role-based access.", {"user_name": user_name, "last_used": usage}))

        for pol in iam.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", []):
            if pol.get("PolicyName") == "AdministratorAccess":
                findings.append(_finding("iam_user", user_id, "AdministratorAccess attached directly to IAM user", f"IAM user {user_name} has AdministratorAccess attached directly.", Severity.high, "Attach privileged policies to roles or groups instead of users.", {"user_name": user_name, "policy": pol}))
            policy = iam.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]
            version = iam.get_policy_version(PolicyArn=pol["PolicyArn"], VersionId=policy["DefaultVersionId"])["PolicyVersion"]
            findings.extend(analyze_policy_document(version["Document"], user_id, "iam_user", pol["PolicyName"]))
        for name in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
            doc = iam.get_user_policy(UserName=user_name, PolicyName=name)["PolicyDocument"]
            findings.extend(analyze_policy_document(doc, user_id, "iam_user", name))

    for role in _paginate(iam, "list_roles", "Roles"):
        role_name = role["RoleName"]
        role_id = role.get("Arn", role_name)
        for stmt in _as_list(role.get("AssumeRolePolicyDocument", {}).get("Statement")):
            if str(stmt.get("Effect", "")).lower() == "allow" and _principal_is_public(stmt.get("Principal")):
                findings.append(_finding("iam_role", role_id, "IAM role trust policy allows Principal '*'", f"Role {role_name} can be assumed by a public principal.", Severity.high, "Restrict trusted principals to specific AWS account, role, or service principals.", {"role_name": role_name, "statement": stmt}))
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            policy = iam.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]
            version = iam.get_policy_version(PolicyArn=pol["PolicyArn"], VersionId=policy["DefaultVersionId"])["PolicyVersion"]
            findings.extend(analyze_policy_document(version["Document"], role_id, "iam_role", pol["PolicyName"]))
        for name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"]
            findings.extend(analyze_policy_document(doc, role_id, "iam_role", name))

    return findings
