"""Safe boto3 session and identity helpers for read-only AWS CSPM scans."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
except ImportError:  # pragma: no cover - exercised only when dependencies are missing.
    boto3 = None
    BotoCoreError = ClientError = NoCredentialsError = Exception


DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION") or os.getenv("AWS_REGION") or "us-east-1"


class AWSIntegrationError(RuntimeError):
    """Raised when AWS credentials or read-only API calls cannot be used safely."""


@dataclass(frozen=True)
class AWSIdentity:
    account_id: str
    arn: str
    user_id: str
    region: str


def get_session(region: Optional[str] = None):
    """Create a boto3 session using the default credential chain only."""
    if boto3 is None:
        raise AWSIntegrationError("boto3 is not installed. Install project requirements first.")
    return boto3.Session(region_name=region or DEFAULT_REGION)


def get_client(service_name: str, region: Optional[str] = None, session: Any = None):
    """Return a boto3 client for a read-only scanner."""
    session = session or get_session(region)
    return session.client(service_name, region_name=region or session.region_name or DEFAULT_REGION)


def validate_identity(region: Optional[str] = None) -> AWSIdentity:
    """Validate credentials with STS GetCallerIdentity without exposing secret material."""
    active_region = region or DEFAULT_REGION
    try:
        sts = get_client("sts", active_region)
        response = sts.get_caller_identity()
    except NoCredentialsError as exc:
        raise AWSIntegrationError("AWS credentials were not found in the default credential chain.") from exc
    except (ClientError, BotoCoreError) as exc:
        raise AWSIntegrationError(f"Unable to validate AWS identity: {exc}") from exc
    return AWSIdentity(
        account_id=response.get("Account", ""),
        arn=response.get("Arn", ""),
        user_id=response.get("UserId", ""),
        region=active_region,
    )
