"""replace host internet_facing boolean with 3-level exposure

Revision ID: 0022
Revises: 0021
Create Date: 2026-08-10

"""
import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # "internet_facing" boolean không đủ diễn tả rủi ro thật — máy đứng sau
    # reverse proxy/WAF khác hẳn máy expose thẳng IP/cổng ra Internet (xem
    # app/schemas.py:EXPOSURE_LEVELS, app/risk.py:compute_attention_level).
    # Backfill giữ nguyên NGỮ NGHĨA CŨ theo hướng an toàn hơn (không hạ rủi
    # ro của dữ liệu đã có): True -> "direct" (giả định xấu nhất vì chưa biết
    # có proxy hay không), False -> "local".
    op.add_column(
        "hosts",
        sa.Column("exposure", sa.String(length=16), nullable=False, server_default="local"),
    )
    op.execute(
        "UPDATE hosts SET exposure = CASE WHEN internet_facing THEN 'direct' ELSE 'local' END"
    )
    op.drop_column("hosts", "internet_facing")


def downgrade() -> None:
    op.add_column(
        "hosts",
        sa.Column("internet_facing", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute("UPDATE hosts SET internet_facing = (exposure <> 'local')")
    op.drop_column("hosts", "exposure")
