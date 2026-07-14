"""create control_versions (lịch sử thay đổi Control)

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-02

"""
import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "control_versions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("control_id", sa.String(128), sa.ForeignKey("controls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("from_maturity", sa.String(16), nullable=True),
        sa.Column("to_maturity", sa.String(16), nullable=True),
        # JSON (không phải JSONB) — cùng lý do với jobs.result_summary: cần
        # compile được trên cả SQLite (test) lẫn Postgres (thật), không cần
        # index/query theo nội dung.
        sa.Column("detail", sa.JSON(), nullable=True),
    )
    op.create_index("ix_control_versions_control_id", "control_versions", ["control_id"])


def downgrade() -> None:
    op.drop_table("control_versions")
