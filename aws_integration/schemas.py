"""Pydantic schemas and enums for AWS CSPM APIs."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScanType(str, Enum):
    full = "full"
    iam = "iam"
    s3 = "s3"
    ec2 = "ec2"
    cloudtrail = "cloudtrail"


class Severity(str, Enum):
    high = "HIGH"
    medium = "MEDIUM"
    low = "LOW"
    info = "INFO"


class FindingStatus(str, Enum):
    open = "open"
    resolved = "resolved"
    ignored = "ignored"


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class AccountIdentity(BaseModel):
    account_id: str
    arn: str
    user_id: str
    region: str


class ScanRequest(BaseModel):
    scan_type: ScanType = ScanType.full
    region: Optional[str] = Field(default=None, max_length=64)


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


class NormalizedFinding(BaseModel):
    provider: str = "aws"
    service: str
    resource_type: str
    resource_id: str
    title: str
    description: str
    severity: Severity
    recommendation: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    compliance_tags: list[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    scan_id: int
    scan_type: str
    status: str
    account_id: str
    region: str
    finding_count: int
    high_count: int
    medium_count: int
    low_count: int
    risk_score: dict[str, Any]


class CSPMScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cloud_account_id: int
    scan_type: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    finding_count: int
    high_count: int
    medium_count: int
    low_count: int
    error_message: Optional[str]


class CSPMFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    cloud_account_id: int
    provider: str
    service: str
    resource_type: str
    resource_id: str
    title: str
    description: str
    severity: str
    recommendation: str
    evidence_json: str
    compliance_tags_json: str
    status: str
    created_at: datetime

