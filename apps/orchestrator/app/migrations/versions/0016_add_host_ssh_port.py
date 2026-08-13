"""add hosts.ssh_port

Revision ID: 0016
Revises: 0015
Create Date: 2026-07-17

"""
import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Cổng SSH thật của host, mặc định 22 — xem app/models.py:Host.ssh_port.
    op.add_column(
        "hosts",
        sa.Column("ssh_port", sa.Integer(), nullable=False, server_default="22"),
    )


def downgrade() -> None:
    op.drop_column("hosts", "ssh_port")
