"""add hosts.system_info + system_info_updated_at

Revision ID: 0024
Revises: 0023
Create Date: 2026-08-11

"""
import sqlalchemy as sa
from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Thông tin OS/kernel/phần cứng máy đích, tự thu thập trong CÙNG phiên SSH
    # của job "ssh-check" (apps/execution-env/ssh-check.sh) — xem docstring
    # cột trong app/models.py để biết vì sao đây là dữ liệu THAM KHẢO, không
    # phải nguồn sự thật để ra quyết định bảo mật.
    #
    # JSON (không phải JSONB) — cùng lý do Job.result_summary/
    # Host.ansible_var_overrides: JSONB là Postgres-only, làm test SQLite
    # crash ("can't render element of type JSONB"). Không cần index/query
    # theo nội dung, chỉ đọc/ghi nguyên khối.
    op.add_column(
        "hosts",
        sa.Column("system_info", sa.JSON(), nullable=False, server_default="{}"),
    )
    # Tách riêng thay vì nhét timestamp vào trong JSON: cần biết dữ liệu này
    # CŨ tới mức nào (máy có thể đã nâng cấp kernel sau lần test SSH gần nhất)
    # mà không phải parse JSON, và để UI cảnh báo khi quá cũ.
    op.add_column(
        "hosts",
        sa.Column("system_info_updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("hosts", "system_info_updated_at")
    op.drop_column("hosts", "system_info")
