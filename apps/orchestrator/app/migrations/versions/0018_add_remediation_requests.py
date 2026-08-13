"""add remediation_requests table

Revision ID: 0018
Revises: 0017
Create Date: 2026-07-18

"""
import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Hàng đợi chờ duyệt cho remediate-apply — xem
    # app/models.py:RemediationRequest, app/remediation_requests.py.
    op.create_table(
        "remediation_requests",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("hostname", sa.String(length=255), sa.ForeignKey("hosts.hostname"), nullable=False),
        sa.Column("control_id", sa.String(length=128), sa.ForeignKey("controls.id"), nullable=False),
        sa.Column("dry_run_job_id", sa.Integer(), sa.ForeignKey("jobs.id"), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("decided_by", sa.String(length=255), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("apply_job_id", sa.Integer(), sa.ForeignKey("jobs.id"), nullable=True),
    )
    op.create_index(
        "ix_remediation_requests_status", "remediation_requests", ["status"]
    )
    op.create_index(
        "ix_remediation_requests_requested_by", "remediation_requests", ["requested_by"]
    )


def downgrade() -> None:
    op.drop_index("ix_remediation_requests_requested_by", table_name="remediation_requests")
    op.drop_index("ix_remediation_requests_status", table_name="remediation_requests")
    op.drop_table("remediation_requests")
