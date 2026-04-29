"""Safe boto3 session and identity helpers for read-only AWS CSPM scans."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, PartialCredentialsError
except ImportError:  # pragma: no cover - exercised only when dependencies are missing.
    boto3 = None
    BotoCoreError = ClientError = NoCredentialsError = PartialCredentialsError = Exception


DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION") or os.getenv("AWS_REGION") or "us-east-1"


class AWSIntegrationError(RuntimeError):
    """Raised when AWS credentials or read-only API calls cannot be used safely."""


@dataclass(frozen=True)
class AWSIdentity:
    account_id: str
    arn: str
    user_id: str
    region: str


def _region(region: Optional[str] = None) -> str:
    return region or os.getenv("AWS_DEFAULT_REGION") or os.getenv("AWS_REGION") or DEFAULT_REGION


def _next_steps() -> list[str]:
    return [
        "Set AWS_ACCESS_KEY_ID in the server environment.",
        "Set AWS_SECRET_ACCESS_KEY in the server environment.",
        "Set AWS_DEFAULT_REGION, for example ap-south-1 or us-east-1.",
        "Or configure AWS_ROLE_ARN, plus optional AWS_EXTERNAL_ID, for AssumeRole mode.",
    ]


def _source_from_credentials(credentials: Any) -> str:
    method = getattr(credentials, "method", "") or ""
    if method == "env":
        return "env"
    if "shared" in method or "config" in method:
        return "shared_credentials_file"
    if method in {"iam-role", "container-role", "metadata-service", "assume-role-with-web-identity"}:
        return "iam_role"
    return "unknown" if method else "missing"


def get_aws_session(region: Optional[str] = None):
    """Create a boto3 session, optionally assuming AWS_ROLE_ARN for cross-account scans."""
    if boto3 is None:
        raise AWSIntegrationError("boto3 is not installed. Install project requirements first.")
    active_region = _region(region)
    role_arn = os.getenv("AWS_ROLE_ARN")
    if not role_arn:
        return boto3.Session(region_name=active_region)

    base_session = boto3.Session(region_name=active_region)
    assume_kwargs: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": os.getenv("AWS_ROLE_SESSION_NAME", "CloudIAMCSPMReadOnlySession"),
    }
    external_id = os.getenv("AWS_EXTERNAL_ID")
    if external_id:
        assume_kwargs["ExternalId"] = external_id
    response = base_session.client("sts", region_name=active_region).assume_role(**assume_kwargs)
    credentials = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name=active_region,
    )


def get_session(region: Optional[str] = None):
    """Backward-compatible alias for the AWS session helper."""
    return get_aws_session(region)


def get_client(service_name: str, region: Optional[str] = None, session: Any = None):
    """Return a boto3 client for a read-only scanner."""
    session = session or get_aws_session(region)
    return session.client(service_name, region_name=_region(region or session.region_name))


def get_aws_credential_status(region: Optional[str] = None) -> dict[str, Any]:
    """Return safe AWS credential diagnostics without exposing secret material."""
    active_region = _region(region)
    status: dict[str, Any] = {
        "configured": False,
        "source": "missing",
        "region": active_region,
        "account_id": None,
        "arn": None,
        "user_id": None,
        "error_message": None,
        "next_steps": [],
    }
    if boto3 is None:
        status["source"] = "missing"
        status["error_message"] = "boto3 is not installed. Install project requirements first."
        status["next_steps"] = ["Install dependencies with pip install -r requirements.txt."]
        return status

    role_arn = os.getenv("AWS_ROLE_ARN")
    try:
        if role_arn:
            status["source"] = "assume_role"
            session = get_aws_session(active_region)
        else:
            session = boto3.Session(region_name=active_region)
            credentials = session.get_credentials()
            if credentials is None:
                status["source"] = "missing"
                status["error_message"] = "AWS credentials were not found in the default credential chain."
                status["next_steps"] = _next_steps()
                return status
            status["source"] = _source_from_credentials(credentials)

        identity = session.client("sts", region_name=active_region).get_caller_identity()
        status.update({
            "configured": True,
            "account_id": identity.get("Account"),
            "arn": identity.get("Arn"),
            "user_id": identity.get("UserId"),
            "next_steps": [],
        })
        return status
    except NoCredentialsError:
        status["source"] = "assume_role" if role_arn else "missing"
        status["error_message"] = "AWS credentials were not found in the default credential chain."
        status["next_steps"] = _next_steps()
    except PartialCredentialsError as exc:
        status["source"] = "assume_role" if role_arn else "unknown"
        status["error_message"] = f"AWS credentials are partially configured: {exc}."
        status["next_steps"] = _next_steps()
    except ClientError as exc:
        status["source"] = "assume_role" if role_arn else status.get("source", "unknown")
        status["error_message"] = exc.response.get("Error", {}).get("Message", str(exc))
        status["next_steps"] = _next_steps()
    except (BotoCoreError, Exception) as exc:
        status["source"] = "assume_role" if role_arn else status.get("source", "unknown")
        status["error_message"] = str(exc)
        status["next_steps"] = _next_steps()
    return status


def validate_identity(region: Optional[str] = None) -> AWSIdentity:
    """Validate credentials with STS GetCallerIdentity without exposing secret material."""
    active_region = _region(region)
    status = get_aws_credential_status(active_region)
    if not status["configured"]:
        raise AWSIntegrationError(status["error_message"] or "AWS credentials are not configured.")
    return AWSIdentity(
        account_id=status.get("account_id") or "",
        arn=status.get("arn") or "",
        user_id=status.get("user_id") or "",
        region=active_region,
    )
