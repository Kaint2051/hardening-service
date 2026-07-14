"""add jobs.control_id, jobs.remediation_variant_id

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-02

"""
import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("jobs", sa.Column("control_id", sa.String(128), sa.ForeignKey("controls.id"), nullable=True))
    op.add_column(
        "jobs",
        sa.Column("remediation_variant_id", sa.Integer(), sa.ForeignKey("remediation_variants.id"), nullable=True),
    )
    op.create_index("ix_jobs_control_id", "jobs", ["control_id"])


def downgrade() -> None:
    op.drop_index("ix_jobs_control_id", table_name="jobs")
    op.drop_column("jobs", "remediation_variant_id")
    op.drop_column("jobs", "control_id")
