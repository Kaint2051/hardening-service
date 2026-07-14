"""add hosts.active_response_enabled

Revision ID: 0011
Revises: 0010
Create Date: 2026-07-07

"""
import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # sa.false() (construct SQL), KHÔNG phải chuỗi Python "false" — cùng bug
    # thật đã phát hiện qua test cho canary_rollouts.cancel_requested /
    # hosts.agent_renewal_blocked (xem migration 0009/0010, app/models.py):
    # chuỗi trần compile thành literal CHUỖI 'false' trong DDL, SQLite
    # lưu/trả nguyên chuỗi đó (không tự cast sang boolean như Postgres) khiến
    # cột luôn truthy ngay từ dòng đầu tiên khi test qua SQLite.
    op.add_column(
        "hosts",
        sa.Column("active_response_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("hosts", "active_response_enabled")
