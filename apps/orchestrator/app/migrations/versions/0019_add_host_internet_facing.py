"""add host internet_facing

Revision ID: 0019
Revises: 0018
Create Date: 2026-07-31

"""
import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Dùng cho GET /hosts/risk-overview (app/risk.py:compute_attention_level)
    # — máy lộ ra Internet cần ngưỡng khắt khe hơn máy chỉ nội bộ, độc lập
    # với Tier (mức độ quan trọng dịch vụ, không phải mức lộ ra ngoài).
    op.add_column(
        "hosts",
        sa.Column("internet_facing", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("hosts", "internet_facing")
