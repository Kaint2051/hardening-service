import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text

from app.db import AuditSessionLocal
from app.models import GENESIS_HASH, AuditLog

# Khoá advisory theo tên cố định để tuần tự hoá việc đọc prev_hash + insert.
# Dùng advisory lock (thay vì "SELECT ... FOR UPDATE" trên hàng cuối) vì khi
# bảng rỗng không có hàng nào để khoá — 2 request đầu tiên vẫn có thể race
# nếu chỉ dựa vào FOR UPDATE.
_ADVISORY_LOCK_KEY = "audit_log_chain"


def _compute_hash(
    prev_hash: str,
    created_at_iso: str,
    actor: str,
    action: str,
    resource: Optional[str],
    payload: dict,
) -> str:
    material = "|".join(
        [
            prev_hash,
            created_at_iso,
            actor,
            action,
            resource or "",
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def write_audit_event(
    actor: str, action: str, resource: Optional[str], payload: dict
) -> AuditLog:
    """Ghi 1 sự kiện audit, nối vào hash-chain hiện có.

    Dùng session/engine riêng (audit_database_url) kết nối bằng role Postgres
    chỉ có quyền INSERT + SELECT trên audit_log — nếu code có bug cố tình
    UPDATE/DELETE, Postgres sẽ tự chặn ở tầng quyền, không phụ thuộc vào việc
    hàm này viết đúng hay không.
    """
    session = AuditSessionLocal()
    try:
        session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": _ADVISORY_LOCK_KEY},
        )

        last = session.query(AuditLog).order_by(AuditLog.id.desc()).first()
        prev_hash = last.record_hash if last else GENESIS_HASH

        created_at = datetime.now(timezone.utc)
        record_hash = _compute_hash(
            prev_hash, created_at.isoformat(), actor, action, resource, payload
        )

        entry = AuditLog(
            created_at=created_at,
            actor=actor,
            action=action,
            resource=resource,
            payload=payload,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )
        session.add(entry)
        session.commit()
        session.refresh(entry)
        return entry
    finally:
        session.close()


def verify_chain() -> bool:
    """Duyệt toàn bộ audit_log theo id tăng dần, verify hash-chain còn nguyên vẹn.

    Dùng để phát hiện can thiệp hồi tố (ai đó chỉnh trực tiếp trong DB, bỏ qua
    tầng application) — nên chạy định kỳ như một job giám sát độc lập.
    """
    session = AuditSessionLocal()
    try:
        prev_hash = GENESIS_HASH
        for row in session.query(AuditLog).order_by(AuditLog.id.asc()).yield_per(500):
            if row.prev_hash != prev_hash:
                return False
            expected = _compute_hash(
                row.prev_hash,
                row.created_at.isoformat(),
                row.actor,
                row.action,
                row.resource,
                row.payload,
            )
            if expected != row.record_hash:
                return False
            prev_hash = row.record_hash
        return True
    finally:
        session.close()
