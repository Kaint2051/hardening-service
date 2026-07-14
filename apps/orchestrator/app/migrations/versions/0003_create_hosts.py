"""create hosts (host registry)

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-01

"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hosts",
        sa.Column("hostname", sa.String(255), primary_key=True),
        sa.Column("ip_address", sa.String(64), nullable=False),
        sa.Column("os_family", sa.String(64), nullable=False),
        sa.Column("os_version", sa.String(32), nullable=True),
        sa.Column("tier", sa.Integer(), nullable=False, server_default="2"),
        sa.Column("ca_migration_status", sa.String(32), nullable=False, server_default="not_started"),
        sa.Column("added_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_hosts_ca_migration_status", "hosts", ["ca_migration_status"])
    op.create_index("ix_hosts_tier", "hosts", ["tier"])


def downgrade() -> None:
    op.drop_table("hosts")
