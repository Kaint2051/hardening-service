"""add hosts.agent_renewal_blocked

Revision ID: 0010
Revises: 0009
Create Date: 2026-07-03

"""
import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # sa.false() (construct SQL), KHÔNG phải chuỗi Python "false" — cùng bug
    # thật đã phát hiện qua test cho canary_rollouts.cancel_requested (xem
    # migration 0009 / app/models.py:Host.agent_renewal_blocked): chuỗi trần
    # compile thành literal CHUỖI 'false' trong DDL, SQLite lưu/trả nguyên
    # chuỗi đó (không tự cast sang boolean như Postgres) khiến cột luôn
    # truthy ngay từ dòng đầu tiên khi test qua SQLite.
    op.add_column(
        "hosts",
        sa.Column("agent_renewal_blocked", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("hosts", "agent_renewal_blocked")
