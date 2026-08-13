"""add app_roles, role_permissions, user_role_assignments (RBAC tuỳ biến)

Revision ID: 0026
Revises: 0025
Create Date: 2026-08-13

"""
import sqlalchemy as sa
from alembic import op

from app.permissions import BUILTIN_ROLE_PERMISSIONS

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "app_roles",
        sa.Column("name", sa.String(64), primary_key=True),
        sa.Column("is_builtin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("description", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(255), nullable=True),
    )

    op.create_table(
        "role_permissions",
        sa.Column("role_name", sa.String(64), sa.ForeignKey("app_roles.name", ondelete="CASCADE"), primary_key=True),
        sa.Column("permission", sa.String(128), primary_key=True),
    )

    # user_id = Keycloak "sub" (UUID ổn định) — KHÔNG dùng username (đổi
    # được ở Keycloak). Bảng này để TRỐNG sau migration — nạp qua script
    # backfill riêng (apps/orchestrator/scripts/backfill_user_role_assignments.py),
    # vì cần gọi Keycloak Admin API (mạng), không phù hợp nhúng vào Alembic.
    op.create_table(
        "user_role_assignments",
        sa.Column("user_id", sa.String(64), primary_key=True),
        sa.Column(
            "role_name", sa.String(64), sa.ForeignKey("app_roles.name", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("assigned_by", sa.String(255), nullable=True),
    )

    # Seed 6 role builtin + toàn bộ role_permissions từ BUILTIN_ROLE_PERMISSIONS
    # (app/permissions.py) — nguồn seed DUY NHẤT, dùng lại nguyên vẹn bởi
    # app/rbac.py:seed_builtin_roles cho fixture test, để migration (Postgres
    # thật) và test (SQLite in-memory) không lệch nhau.
    app_roles_table = sa.table(
        "app_roles",
        sa.column("name", sa.String),
        sa.column("is_builtin", sa.Boolean),
    )
    role_permissions_table = sa.table(
        "role_permissions",
        sa.column("role_name", sa.String),
        sa.column("permission", sa.String),
    )

    op.bulk_insert(
        app_roles_table,
        [{"name": role_name, "is_builtin": True} for role_name in BUILTIN_ROLE_PERMISSIONS],
    )
    op.bulk_insert(
        role_permissions_table,
        [
            {"role_name": role_name, "permission": permission}
            for role_name, permissions in BUILTIN_ROLE_PERMISSIONS.items()
            for permission in sorted(permissions)
        ],
    )


def downgrade() -> None:
    op.drop_table("user_role_assignments")
    op.drop_table("role_permissions")
    op.drop_table("app_roles")
