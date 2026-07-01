"""create control registry (controls, standard_mappings, remediation_variants)

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-01

"""
import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "controls",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("maturity", sa.String(16), nullable=False, server_default="draft"),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    op.create_table(
        "standard_mappings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("control_id", sa.String(128), sa.ForeignKey("controls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("standard", sa.String(32), nullable=False),
        sa.Column("standard_version", sa.String(128), nullable=False),
        sa.Column("section_id", sa.String(64), nullable=False),
        sa.Column("reference_url", sa.String(512), nullable=True),
        sa.UniqueConstraint(
            "control_id", "standard", "standard_version", "section_id",
            name="uq_standard_mapping",
        ),
    )
    op.create_index("ix_standard_mappings_control_id", "standard_mappings", ["control_id"])

    op.create_table(
        "remediation_variants",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("control_id", sa.String(128), sa.ForeignKey("controls.id", ondelete="CASCADE"), nullable=False),
        sa.Column("os_family", sa.String(64), nullable=False),
        sa.Column("os_version", sa.String(32), nullable=True),
        sa.Column("check_method", sa.String(32), nullable=False),
        sa.Column("remediation_ref", sa.String(255), nullable=False),
        sa.Column("rollback_available", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint(
            "control_id", "os_family", "os_version",
            name="uq_remediation_variant",
        ),
    )
    op.create_index("ix_remediation_variants_control_id", "remediation_variants", ["control_id"])


def downgrade() -> None:
    op.drop_table("remediation_variants")
    op.drop_table("standard_mappings")
    op.drop_table("controls")
