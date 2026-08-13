"""add hosts.static_ssh_private_key_encrypted

Revision ID: 0023
Revises: 0022
Create Date: 2026-08-10

"""
import sqlalchemy as sa
from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Fernet token (đã mã hoá), KHÔNG BAO GIỜ là plaintext — xem
    # app/hosts.py:_encrypt_host_secret. Cột riêng, KHÔNG dùng chung
    # ssh_password_encrypted — field đó có endpoint GET .../ssh-credential
    # trả plaintext theo yêu cầu (đúng cho password tham khảo), nhưng KHÔNG
    # nên có cho 1 secret sống mãi/không revoke như static SSH key.
    op.add_column(
        "hosts",
        sa.Column("static_ssh_private_key_encrypted", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("hosts", "static_ssh_private_key_encrypted")
