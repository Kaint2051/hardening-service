from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.db import Base

GENESIS_HASH = "0" * 64


class AuditLog(Base):
    """Append-only, hash-chain audit log (nguyên tắc 4 trong architecture-proposal.md).

    Mỗi bản ghi băm theo (prev_hash + created_at + actor + action + resource +
    payload) — chỉnh sửa hồi tố bất kỳ bản ghi nào sẽ làm sai lệch hash của mọi
    bản ghi phía sau, giúp phát hiện can thiệp dữ liệu.

    Quyền ghi bảng này chỉ cấp cho role Postgres riêng (orchestrator_audit) với
    INSERT + SELECT — không có UPDATE/DELETE (áp bằng GRANT trong migration
    0001, không chỉ dựa vào code tầng application).
    """

    __tablename__ = "audit_log"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    actor = Column(String(255), nullable=False)
    action = Column(String(255), nullable=False)
    resource = Column(String(255), nullable=True)
    payload = Column(JSONB, nullable=False, server_default="{}")
    prev_hash = Column(String(64), nullable=False)
    record_hash = Column(String(64), nullable=False)


class Control(Base):
    """1 control hardening, độc lập với bất kỳ chuẩn cụ thể nào (mục 3/6:
    "Control Registry mapping đa chuẩn"). Một Control có thể map tới nhiều
    StandardMapping (CIS, STIG, TCVN...) và nhiều RemediationVariant (theo
    distro/version) khác nhau.

    `maturity` theo roadmap Giai đoạn 1 ("Control Registry với maturity
    labelling"): draft -> reviewed -> production. Chuyển từ draft lên phải
    qua role "approver"/"admin" khác người tạo (four-eyes — xem app/controls.py).
    """

    __tablename__ = "controls"

    id = Column(String(128), primary_key=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False, server_default="")
    category = Column(String(64), nullable=False)
    maturity = Column(String(16), nullable=False, server_default="draft")
    created_by = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    standard_mappings = relationship(
        "StandardMapping", back_populates="control", cascade="all, delete-orphan"
    )
    remediation_variants = relationship(
        "RemediationVariant", back_populates="control", cascade="all, delete-orphan"
    )


class StandardMapping(Base):
    """Ánh xạ 1 Control sang 1 mục cụ thể trong 1 chuẩn (CIS/STIG/TCVN/CUSTOM)."""

    __tablename__ = "standard_mappings"
    __table_args__ = (
        UniqueConstraint(
            "control_id", "standard", "standard_version", "section_id",
            name="uq_standard_mapping",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    control_id = Column(String(128), ForeignKey("controls.id", ondelete="CASCADE"), nullable=False)
    standard = Column(String(32), nullable=False)
    standard_version = Column(String(128), nullable=False)
    section_id = Column(String(64), nullable=False)
    reference_url = Column(String(512), nullable=True)

    control = relationship("Control", back_populates="standard_mappings")


class RemediationVariant(Base):
    """Bản remediation cụ thể theo distro/version cho 1 Control.

    `remediation_ref` là con trỏ (vd. tên file/hash nội dung) trỏ tới nội dung
    ĐÃ KÝ trong scripts/content-signing/signed/ — KHÔNG lưu script thực thi
    trực tiếp ở đây (mục 4.2/4.3: Agent Active Response chỉ nhận
    control_id + remediation_ref đã ký, không nhận lệnh tự do).
    """

    __tablename__ = "remediation_variants"
    __table_args__ = (
        UniqueConstraint(
            "control_id", "os_family", "os_version",
            name="uq_remediation_variant",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    control_id = Column(String(128), ForeignKey("controls.id", ondelete="CASCADE"), nullable=False)
    os_family = Column(String(64), nullable=False)
    os_version = Column(String(32), nullable=True)
    check_method = Column(String(32), nullable=False)
    remediation_ref = Column(String(255), nullable=False)
    rollback_available = Column(Boolean, nullable=False, server_default="false")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    control = relationship("Control", back_populates="remediation_variants")
