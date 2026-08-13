"""add connection_method to remediation_requests

Revision ID: 0021
Revises: 0020
Create Date: 2026-08-07

"""
import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Chọn tay SSH/Agent lúc gửi duyệt remediate-apply — NULL giữ nguyên
    # hành vi tự động chọn theo cấu hình host, xem
    # app/models.py:RemediationRequest.connection_method.
    op.add_column(
        "remediation_requests",
        sa.Column("connection_method", sa.String(length=16), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("remediation_requests", "connection_method")
