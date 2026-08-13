"""add hosts.metrics + metrics_updated_at

Revision ID: 0025
Revises: 0024
Create Date: 2026-08-11

"""
import sqlalchemy as sa
from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Số liệu tài nguyên (CPU/RAM/Disk % + interface mạng chính/% băng
    # thông) — Agent TỰ đo tại chỗ, báo lên mỗi ~3 phút (apps/agent/metrics.go,
    # app/agents.py:agent_metrics). CHỈ có với host đã cài Agent — KHÁC
    # system_info (migration 0024, tới từ SSH nên dùng được cho mọi host).
    # JSON (không phải JSONB) — cùng lý do system_info: JSONB Postgres-only
    # làm test SQLite crash.
    op.add_column(
        "hosts",
        sa.Column("metrics", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "hosts",
        sa.Column("metrics_updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("hosts", "metrics_updated_at")
    op.drop_column("hosts", "metrics")
