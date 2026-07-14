"""Host Registry API (Giai đoạn 1, mục 7 architecture-proposal.md).

Vai trò:
  - operator/admin: đăng ký máy mới, cập nhật ca_migration_status (phản ánh
    tiến độ chạy ansible/playbooks/zero-to-ca-migration.yml +
    revoke-old-credential.yml — xem ansible/README.md).
  - Mọi role đã đăng nhập: đọc (list/get) — dùng để biết máy nào đang
    "migrate dở dang" (ca_migration_status="trust_deployed" nhưng chưa
    "migrated") mà không phải tự query DB thủ công như trước.

CHƯA làm ở lần này: sửa/xoá host, job/scan thật (cần chốt trước cơ chế
Orchestrator tự spawn Ephemeral Execution Environment — xem trao đổi riêng).
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.audit import write_audit_event
from app.auth import CurrentUser, require_roles
from app.db import SessionLocal
from app.models import Host
from app.schemas import (
    CA_MIGRATION_STATUSES,
    HostActiveResponseUpdate,
    HostAgentRenewalUpdate,
    HostCreate,
    HostMigrationStatusUpdate,
    HostOut,
)

router = APIRouter(prefix="/hosts", tags=["host-registry"])

_ALL_ROLES = ("viewer", "auditor", "rule-editor", "approver", "operator", "admin")
_OPERATOR_ROLES = ("operator", "admin")

# Tier 0/1 = "production/Tier cao" theo mục 1.3 architecture-proposal.md.
# Tier 2 (mặc định) chưa cần four-eyes ở bước này.
_HIGH_TIER_MAX = 1


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("", response_model=HostOut, status_code=status.HTTP_201_CREATED)
def register_host(
    body: HostCreate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> Host:
    if db.get(Host, body.hostname) is not None:
        raise HTTPException(status_code=409, detail="host đã được đăng ký")
    host = Host(
        hostname=body.hostname,
        ip_address=body.ip_address,
        os_family=body.os_family,
        os_version=body.os_version,
        tier=body.tier,
        ca_migration_status="not_started",
        added_by=user.username,
    )
    db.add(host)
    db.commit()
    db.refresh(host)

    write_audit_event(
        actor=user.username,
        action="host_registered",
        resource=host.hostname,
        payload={"ip_address": host.ip_address, "tier": host.tier, "os_family": host.os_family},
    )
    return host


@router.get("", response_model=list[HostOut])
def list_hosts(
    ca_migration_status: str | None = None,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_roles(*_ALL_ROLES)),
) -> list[Host]:
    query = db.query(Host)
    if ca_migration_status is not None:
        query = query.filter(Host.ca_migration_status == ca_migration_status)
    return query.order_by(Host.hostname.asc()).all()


@router.get("/{hostname}", response_model=HostOut)
def get_host(
    hostname: str,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_roles(*_ALL_ROLES)),
) -> Host:
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    return host


@router.patch("/{hostname}/ca-migration-status", response_model=HostOut)
def update_ca_migration_status(
    hostname: str,
    body: HostMigrationStatusUpdate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> Host:
    if body.ca_migration_status not in CA_MIGRATION_STATUSES:
        raise HTTPException(
            status_code=422, detail=f"ca_migration_status phải là 1 trong {CA_MIGRATION_STATUSES}"
        )
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    if body.ca_migration_status == "migrated":
        # Bắt buộc phải qua "trust_deployed" trước — thiếu ràng buộc này thì
        # 1 operator có thể tự đăng ký host rồi nhảy thẳng
        # not_started -> migrated 1 mình, khiến check four-eyes bên dưới bị
        # bỏ qua hoàn toàn (ca_migration_updated_by khi đó vẫn là None, guard
        # "is not None" tự tắt cả điều kiện) — phát hiện qua test thật gọi
        # API trực tiếp, không phải chỉ đọc code.
        if host.ca_migration_status != "trust_deployed":
            raise HTTPException(
                status_code=422,
                detail="chỉ được xác nhận 'migrated' từ trạng thái 'trust_deployed'",
            )
        # Four-eyes: xác nhận "migrated" (khẳng định credential cũ đã bị thu
        # hồi) cho host Tier 0/1 không được do đúng người vừa đặt
        # "trust_deployed" tự xác nhận nốt — cần người thứ 2 (xem mô tả cột
        # trong app/models.py). Nhờ ràng buộc ngay trên, tới đây
        # ca_migration_updated_by chắc chắn không còn None.
        if host.tier <= _HIGH_TIER_MAX and host.ca_migration_updated_by == user.username:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="host Tier cao: không được tự xác nhận 'migrated' cho thay đổi trust_deployed của chính mình (four-eyes)",
            )

    previous_status = host.ca_migration_status
    host.ca_migration_status = body.ca_migration_status
    host.ca_migration_updated_by = user.username
    db.commit()
    db.refresh(host)

    write_audit_event(
        actor=user.username,
        action="host_ca_migration_status_updated",
        resource=hostname,
        payload={"from": previous_status, "to": body.ca_migration_status, "tier": host.tier},
    )
    return host


@router.patch("/{hostname}/agent-renewal", response_model=HostOut)
def update_agent_renewal(
    hostname: str,
    body: HostAgentRenewalUpdate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> Host:
    # Khoá/mở renew cert mTLS định kỳ của Agent trên 1 host cụ thể (vd host
    # nghi ngờ bị chiếm, chờ điều tra) — enforce thật ở
    # POST /internal/agent/renew-cert (xem app/agents.py), endpoint này chỉ
    # đặt cờ + ghi audit.
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    host.agent_renewal_blocked = body.blocked
    db.commit()
    db.refresh(host)

    write_audit_event(
        actor=user.username,
        action="agent_renewal_blocked_updated",
        resource=hostname,
        payload={"blocked": body.blocked},
    )
    return host


@router.patch("/{hostname}/active-response", response_model=HostOut)
def update_active_response(
    hostname: str,
    body: HostActiveResponseUpdate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> Host:
    # Bật/tắt Active Response RIÊNG cho 1 host (mục 4.3/4.4 — Agent thực thi
    # remediation thật) — vẫn cần kill-switch TOÀN CỤC
    # settings.active_response_enabled bật thì host mới thật sự dùng đường
    # Agent, enforce thật ở app/jobs.py:_dispatch_remediate_job. Endpoint này
    # chỉ đặt cờ + ghi audit, cùng cấu trúc update_agent_renewal ở trên.
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    host.active_response_enabled = body.enabled
    db.commit()
    db.refresh(host)

    write_audit_event(
        actor=user.username,
        action="active_response_enabled_updated",
        resource=hostname,
        payload={"enabled": body.enabled},
    )
    return host
