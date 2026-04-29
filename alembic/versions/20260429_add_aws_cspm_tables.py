"""add aws cspm tables

Revision ID: 20260429_add_aws_cspm
Revises:
Create Date: 2026-04-29
"""

from alembic import op
import sqlalchemy as sa


revision = "20260429_add_aws_cspm"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cloud_accounts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("account_id", sa.String(length=32), nullable=False),
        sa.Column("arn", sa.String(length=512), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_validated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("account_id", "region", name="uq_cloud_account_region"),
    )
    op.create_index(op.f("ix_cloud_accounts_id"), "cloud_accounts", ["id"])
    op.create_index(op.f("ix_cloud_accounts_account_id"), "cloud_accounts", ["account_id"])

    scan_status = sa.Enum("pending", "running", "completed", "failed", name="cspmscanstatusenum")
    finding_status = sa.Enum("open", "resolved", "ignored", name="cspmfindingstatusenum")
    scan_status.create(op.get_bind(), checkfirst=True)
    finding_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "cspm_scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cloud_account_id", sa.Integer(), nullable=False),
        sa.Column("scan_type", sa.String(length=32), nullable=False),
        sa.Column("status", scan_status, nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("high_count", sa.Integer(), nullable=False),
        sa.Column("medium_count", sa.Integer(), nullable=False),
        sa.Column("low_count", sa.Integer(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["cloud_account_id"], ["cloud_accounts.id"]),
    )
    op.create_index(op.f("ix_cspm_scans_id"), "cspm_scans", ["id"])
    op.create_index(op.f("ix_cspm_scans_cloud_account_id"), "cspm_scans", ["cloud_account_id"])

    op.create_table(
        "cspm_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("cloud_account_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("service", sa.String(length=32), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=512), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False),
        sa.Column("compliance_tags_json", sa.Text(), nullable=False),
        sa.Column("status", finding_status, nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["cspm_scans.id"]),
        sa.ForeignKeyConstraint(["cloud_account_id"], ["cloud_accounts.id"]),
    )
    op.create_index(op.f("ix_cspm_findings_id"), "cspm_findings", ["id"])
    op.create_index(op.f("ix_cspm_findings_scan_id"), "cspm_findings", ["scan_id"])
    op.create_index(op.f("ix_cspm_findings_cloud_account_id"), "cspm_findings", ["cloud_account_id"])
    op.create_index(op.f("ix_cspm_findings_service"), "cspm_findings", ["service"])
    op.create_index(op.f("ix_cspm_findings_resource_type"), "cspm_findings", ["resource_type"])
    op.create_index(op.f("ix_cspm_findings_severity"), "cspm_findings", ["severity"])


def downgrade() -> None:
    op.drop_table("cspm_findings")
    op.drop_table("cspm_scans")
    op.drop_table("cloud_accounts")
    sa.Enum(name="cspmfindingstatusenum").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="cspmscanstatusenum").drop(op.get_bind(), checkfirst=True)
