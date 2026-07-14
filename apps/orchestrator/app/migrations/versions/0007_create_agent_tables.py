"""create agent_enrollment_tokens, agent_fim_events, hosts.agent_* columns

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-02

"""
import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("hosts", sa.Column("agent_enrolled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("hosts", sa.Column("agent_last_seen", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "agent_enrollment_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("hostname", sa.String(255), sa.ForeignKey("hosts.hostname", ondelete="CASCADE"), nullable=False),
        sa.Column("jti", sa.String(255), nullable=False, unique=True),
        sa.Column("issued_by", sa.String(255), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_enrollment_tokens_hostname", "agent_enrollment_tokens", ["hostname"])

    op.create_table(
        "agent_fim_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("hostname", sa.String(255), sa.ForeignKey("hosts.hostname", ondelete="CASCADE"), nullable=False),
        sa.Column("path", sa.String(512), nullable=False),
        sa.Column("event_type", sa.String(16), nullable=False),
        sa.Column("old_hash", sa.String(64), nullable=True),
        sa.Column("new_hash", sa.String(64), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_agent_fim_events_hostname", "agent_fim_events", ["hostname"])


def downgrade() -> None:
    op.drop_table("agent_fim_events")
    op.drop_table("agent_enrollment_tokens")
    op.drop_column("hosts", "agent_last_seen")
    op.drop_column("hosts", "agent_enrolled_at")
