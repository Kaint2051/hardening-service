"""add hosts.decommissioned_at/decommissioned_by

Revision ID: 0012
Revises: 0011
Create Date: 2026-07-15

"""
import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # NULL = đang quản lý (mặc định) — không dùng cột Boolean vì cần biết CẢ
    # lúc nào lẫn AI đã decommission (cùng mẫu ca_migration_updated_by), phục
    # vụ audit trail thay vì chỉ 1 cờ true/false.
    op.add_column("hosts", sa.Column("decommissioned_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("hosts", sa.Column("decommissioned_by", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("hosts", "decommissioned_by")
    op.drop_column("hosts", "decommissioned_at")
