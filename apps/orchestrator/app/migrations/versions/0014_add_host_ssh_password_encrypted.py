"""add hosts.ssh_password_encrypted

Revision ID: 0014
Revises: 0013
Create Date: 2026-07-15

"""
import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # NULL = chưa cấu hình password cho host này. Giá trị (khi có) là chuỗi
    # Fernet token (đã mã hoá), KHÔNG BAO GIỜ là plaintext — xem
    # app/hosts.py:_encrypt_ssh_password.
    op.add_column("hosts", sa.Column("ssh_password_encrypted", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("hosts", "ssh_password_encrypted")
