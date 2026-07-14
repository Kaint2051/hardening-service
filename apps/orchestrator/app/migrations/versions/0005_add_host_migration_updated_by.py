"""add hosts.ca_migration_updated_by (four-eyes cho Tier 0/1)

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-02

"""
import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "hosts",
        sa.Column("ca_migration_updated_by", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("hosts", "ca_migration_updated_by")
