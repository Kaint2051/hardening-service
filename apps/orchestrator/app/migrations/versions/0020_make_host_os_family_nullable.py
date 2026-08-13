"""make host os_family nullable

Revision ID: 0020
Revises: 0019
Create Date: 2026-08-04

"""
import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # os_family/os_version không còn bắt buộc điền lúc đăng ký host (xem
    # app/schemas.py:HostCreate) — Agent (nếu có cài) tự báo cáo qua mỗi
    # heartbeat (app/agents.py:agent_heartbeat), host thuần agentless vẫn
    # điền tay qua PATCH /hosts/{hostname} như trước. os_version đã nullable
    # từ đầu, chỉ os_family cần đổi.
    op.alter_column("hosts", "os_family", existing_type=sa.String(64), nullable=True)


def downgrade() -> None:
    op.alter_column("hosts", "os_family", existing_type=sa.String(64), nullable=False)
