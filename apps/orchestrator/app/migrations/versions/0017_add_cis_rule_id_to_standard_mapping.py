"""add standard_mappings.cis_rule_id

Revision ID: 0017
Revises: 0016
Create Date: 2026-07-18

"""
import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Cầu nối rule_id lúc quét <-> Control dùng để sửa — xem
    # app/models.py:StandardMapping.cis_rule_id, app/controls.py GET /controls/lookup.
    op.add_column(
        "standard_mappings",
        sa.Column("cis_rule_id", sa.String(length=255), nullable=True),
    )
    op.create_index(
        "ix_standard_mappings_cis_rule_id", "standard_mappings", ["cis_rule_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_standard_mappings_cis_rule_id", table_name="standard_mappings")
    op.drop_column("standard_mappings", "cis_rule_id")
