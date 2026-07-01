"""create audit_log (append-only, hash-chain)

Revision ID: 0001
Revises:
Create Date: 2026-07-01

"""
import os

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# Role Postgres dùng riêng để ghi audit log (mục 4 architecture-proposal.md:
# "audit log append-only" — enforce ở tầng DB, không chỉ ở application code).
AUDIT_ROLE = os.environ.get("POSTGRES_AUDIT_USER", "orchestrator_audit")


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("resource", sa.String(255), nullable=True),
        sa.Column(
            "payload",
            postgresql.JSONB(),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False, unique=True),
    )
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])

    # --- Chốt quyền INSERT-only cho role audit (không có UPDATE/DELETE) ---
    # Đây là control kỹ thuật thực thi bằng Postgres GRANT, không phải chỉ kỷ
    # luật ở code — nếu Orchestrator bị RCE, kẻ tấn công dùng kết nối audit
    # role vẫn không thể sửa/xoá bản ghi cũ để xoá dấu vết.
    op.execute(f"REVOKE ALL ON audit_log FROM PUBLIC")
    op.execute(f"GRANT INSERT, SELECT ON audit_log TO {AUDIT_ROLE}")
    op.execute(
        f"GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO {AUDIT_ROLE}"
    )
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM {AUDIT_ROLE}")


def downgrade() -> None:
    op.drop_index("ix_audit_log_created_at", table_name="audit_log")
    op.drop_table("audit_log")
