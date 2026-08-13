"""add controls.overridable_variables + hosts.ansible_var_overrides

Revision ID: 0015
Revises: 0014
Create Date: 2026-07-17

"""
import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # {tên biến: giá trị mặc định} — xem app/control_templates.py, app/models.py.
    op.add_column(
        "controls",
        sa.Column("overridable_variables", sa.JSON(), nullable=False, server_default="{}"),
    )
    # {tên biến: giá trị override riêng cho host này} — xem app/hosts.py PATCH
    # /hosts/{hostname}/variable-overrides, app/models.py.
    op.add_column(
        "hosts",
        sa.Column("ansible_var_overrides", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("hosts", "ansible_var_overrides")
    op.drop_column("controls", "overridable_variables")
