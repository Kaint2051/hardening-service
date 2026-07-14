"""add controls.risk_group, canary_rollouts table, jobs.canary_rollout_id

Revision ID: 0009
Revises: 0008
Create Date: 2026-07-03

"""
import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "controls",
        sa.Column("risk_group", sa.String(1), nullable=False, server_default="B"),
    )

    op.create_table(
        "canary_rollouts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("control_id", sa.String(128), sa.ForeignKey("controls.id"), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="running"),
        sa.Column("triggered_by", sa.String(255), nullable=False),
        sa.Column("eligible_host_count", sa.Integer(), nullable=False),
        sa.Column("aborted_hostname", sa.String(255), nullable=True),
        sa.Column("abort_reason", sa.String(32), nullable=True),
        # sa.false() (construct SQL), KHÔNG phải chuỗi Python "false" — bug
        # thật phát hiện qua test thật (xem app/models.py:CanaryRollout.
        # cancel_requested): server_default="false" (chuỗi trần) compile
        # thành literal CHUỖI 'false' trong DDL, SQLite lưu/trả về y hệt chuỗi
        # đó (không tự cast sang boolean như Postgres), khiến cancel_requested
        # luôn truthy ngay từ dòng đầu tiên khi test qua SQLite.
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.add_column(
        "jobs",
        sa.Column("canary_rollout_id", sa.Integer(), sa.ForeignKey("canary_rollouts.id"), nullable=True),
    )

    # Partial unique index — chỉ 1 rollout "running" tại 1 thời điểm cho mỗi
    # control (enforce ở tầng DB, xem app/models.py:CanaryRollout). op.create_index
    # không hỗ trợ portable WHERE clause trong codebase này -> raw SQL, cùng
    # tiền lệ migrations/versions/0001_create_audit_log.py.
    op.execute(
        "CREATE UNIQUE INDEX ux_canary_rollouts_running "
        "ON canary_rollouts (control_id) WHERE status = 'running'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX ux_canary_rollouts_running")
    op.drop_column("jobs", "canary_rollout_id")
    op.drop_table("canary_rollouts")
    op.drop_column("controls", "risk_group")
