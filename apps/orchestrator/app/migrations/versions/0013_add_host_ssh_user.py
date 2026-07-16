"""add hosts.ssh_user

Revision ID: 0013
Revises: 0012
Create Date: 2026-07-15

"""
import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("hosts", sa.Column("ssh_user", sa.String(64), nullable=False, server_default="root"))


def downgrade() -> None:
    op.drop_column("hosts", "ssh_user")
