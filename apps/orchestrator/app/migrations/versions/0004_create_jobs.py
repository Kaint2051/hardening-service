"""create jobs

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-01

"""
import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "jobs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("hostname", sa.String(255), sa.ForeignKey("hosts.hostname"), nullable=False),
        sa.Column("job_type", sa.String(32), nullable=False),
        sa.Column("scap_profile", sa.String(255), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        # JSON (không phải JSONB) — phải compile được trên cả SQLite (test)
        # lẫn Postgres (thật), không cần index/query theo nội dung.
        sa.Column("result_summary", sa.JSON(), nullable=True),
        sa.Column("triggered_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_jobs_hostname", "jobs", ["hostname"])
    op.create_index("ix_jobs_status", "jobs", ["status"])


def downgrade() -> None:
    op.drop_table("jobs")
